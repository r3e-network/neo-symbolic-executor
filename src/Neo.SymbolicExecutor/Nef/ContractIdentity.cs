using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Nef;

/// <summary>
/// Neo N3 contract identity helpers. The deployed contract hash is the Hash160 of the
/// deployment identity script emitted by Neo.SmartContract.Helper.GetContractHash.
/// </summary>
public static class ContractIdentity
{
    public const int UInt160Length = 20;

    public static string ComputeContractHashHex(
        NefFile nef,
        ContractManifest manifest,
        ReadOnlySpan<byte> deploySenderLittleEndian)
    {
        byte[] hash = ComputeContractHash(nef, manifest, deploySenderLittleEndian);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static byte[] ComputeContractHash(
        NefFile nef,
        ContractManifest manifest,
        ReadOnlySpan<byte> deploySenderLittleEndian)
    {
        ArgumentNullException.ThrowIfNull(nef);
        ArgumentNullException.ThrowIfNull(manifest);
        if (deploySenderLittleEndian.Length != UInt160Length)
            throw new ArgumentException("deploy sender hash must be exactly 20 bytes", nameof(deploySenderLittleEndian));

        byte[] identityScript = BuildContractHashScript(
            deploySenderLittleEndian,
            nef.Checksum,
            manifest.Name ?? "");
        byte[] hash = Hash160(identityScript);
        Array.Reverse(hash);
        return hash;
    }

    public static byte[] ParseUInt160LittleEndianHex(string value)
    {
        string normalized = NormalizeUInt160LittleEndianHex(value);
        try
        {
            return Convert.FromHexString(normalized);
        }
        catch (FormatException ex)
        {
            throw new ArgumentException("deploy sender hash must be 20 bytes of hexadecimal UInt160 data", nameof(value), ex);
        }
    }

    public static string NormalizeUInt160LittleEndianHex(string value)
    {
        if (value is null)
            throw new ArgumentNullException(nameof(value));
        string normalized = value.Trim();
        if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            normalized = normalized[2..];
        if (normalized.Length != UInt160Length * 2)
            throw new ArgumentException("deploy sender hash must be a 20-byte UInt160 hex string", nameof(value));
        return normalized.ToLowerInvariant();
    }

    private static byte[] BuildContractHashScript(
        ReadOnlySpan<byte> deploySenderLittleEndian,
        uint nefChecksum,
        string manifestName)
    {
        var script = new List<byte>(64 + Encoding.UTF8.GetByteCount(manifestName));
        script.Add((byte)NeoVm.OpCode.ABORT);

        // Round-2 fix: Neo's Helper.GetContractHash emits the deploy sender via EmitPush(sender),
        // which pushes sender.ToArray() — the UInt160 little-endian wire bytes — AS-IS. The previous
        // Array.Reverse(...) pushed big-endian bytes, producing a different (wrong) contract hash for
        // any non-palindromic sender. Push the little-endian bytes unchanged. (Verified against real
        // Neo 3.9.0: sender 0011..2233, checksum 0x12345678, name "MyContract" =>
        // 0x02e14ed6f01f22151aa90334f7651fd3b262b322.)
        EmitPushBytes(script, deploySenderLittleEndian);
        EmitPushInteger(script, new BigInteger(nefChecksum));
        EmitPushBytes(script, Encoding.UTF8.GetBytes(manifestName));
        return script.ToArray();
    }

    private static void EmitPushBytes(List<byte> script, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length < 0x100)
        {
            script.Add((byte)NeoVm.OpCode.PUSHDATA1);
            script.Add((byte)bytes.Length);
        }
        else if (bytes.Length < 0x10000)
        {
            script.Add((byte)NeoVm.OpCode.PUSHDATA2);
            script.Add((byte)bytes.Length);
            script.Add((byte)(bytes.Length >> 8));
        }
        else
        {
            script.Add((byte)NeoVm.OpCode.PUSHDATA4);
            script.Add((byte)bytes.Length);
            script.Add((byte)(bytes.Length >> 8));
            script.Add((byte)(bytes.Length >> 16));
            script.Add((byte)(bytes.Length >> 24));
        }

        foreach (byte b in bytes)
            script.Add(b);
    }

    private static void EmitPushInteger(List<byte> script, BigInteger value)
    {
        if (value == BigInteger.MinusOne)
        {
            script.Add((byte)NeoVm.OpCode.PUSHM1);
            return;
        }
        // Review fix (#50): Neo's ScriptBuilder.EmitPush(BigInteger) short-forms the inclusive
        // range [-1, 16] (PUSHM1, PUSH0..PUSH16). The previous `< 16` bound excluded 16, emitting a
        // PUSHINT byte sequence instead of PUSH16 (0x20) and producing a different contract-identity
        // script (hence hash) than Neo for any checksum byte equal to 16.
        if (value >= BigInteger.Zero && value <= 16)
        {
            script.Add((byte)((byte)NeoVm.OpCode.PUSH0 + (byte)value));
            return;
        }

        byte[] bytes = value.ToByteArray(isUnsigned: false, isBigEndian: false);
        if (bytes.Length > 32)
            throw new ArgumentOutOfRangeException(nameof(value), "NeoVM integers are limited to 32 bytes");

        int width = 1;
        while (width < bytes.Length)
            width <<= 1;
        if (width > 32)
            throw new ArgumentOutOfRangeException(nameof(value), "NeoVM integers are limited to 32 bytes");

        int opcodeOffset = width switch
        {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            16 => 4,
            32 => 5,
            _ => throw new InvalidOperationException($"unsupported NeoVM integer width {width}"),
        };
        script.Add((byte)((byte)NeoVm.OpCode.PUSHINT8 + opcodeOffset));
        byte pad = value.Sign < 0 ? (byte)0xFF : (byte)0x00;
        for (int i = 0; i < width; i++)
            script.Add(i < bytes.Length ? bytes[i] : pad);
    }

    private static byte[] Hash160(byte[] bytes)
    {
        byte[] sha256 = SHA256.HashData(bytes);
        var digest = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
        digest.BlockUpdate(sha256, 0, sha256.Length);
        byte[] result = new byte[digest.GetDigestSize()];
        digest.DoFinal(result, 0);
        return result;
    }
}
