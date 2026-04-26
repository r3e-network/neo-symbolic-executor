using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Builds a structurally-valid NEF, then bit-flips one byte. Stresses the parser's per-field
/// validation paths instead of failing at "magic mismatch" on every iteration.
/// </summary>
public sealed class NefMutationTarget : IFuzzTarget
{
    public string Name => "nef-mutation";
    public Type[] ExpectedExceptions => new[]
    {
        typeof(FormatException),
        typeof(EndOfStreamException),
        typeof(ArgumentOutOfRangeException),
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        byte[] valid = BuildValidNef(rng);
        // Flip one byte (or set zero) to corrupt.
        if (valid.Length > 0)
        {
            int idx = rng.Next(valid.Length);
            valid[idx] = rng.Next(2) == 0 ? (byte)0 : (byte)(valid[idx] ^ rng.Next(1, 256));
        }
        reproInput = valid;
        reason = null;
        try
        {
            _ = NefFile.Parse(valid, verifyChecksum: rng.Next(2) == 0);
            return true;
        }
        catch (FormatException) { return true; }
        catch (EndOfStreamException) { return true; }
        catch (ArgumentOutOfRangeException) { return true; }
    }

    private static byte[] BuildValidNef(Random rng)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true))
        {
            bw.Write(NefFile.MagicValue);
            byte[] compiler = new byte[64];
            rng.NextBytes(compiler);
            // Null-out a portion for realism.
            for (int i = compiler.Length - 1; i >= 0 && rng.NextDouble() < 0.5; i--) compiler[i] = 0;
            bw.Write(compiler);

            byte[] source = new byte[rng.Next(0, 128)];
            rng.NextBytes(source);
            WriteVarInt(bw, (ulong)source.Length);
            bw.Write(source);
            bw.Write((byte)0); // reserve

            int tokenCount = rng.Next(0, 4);
            WriteVarInt(bw, (ulong)tokenCount);
            for (int i = 0; i < tokenCount; i++)
            {
                byte[] hash = new byte[20];
                rng.NextBytes(hash);
                bw.Write(hash);
                byte[] name = new byte[rng.Next(1, 16)];
                rng.NextBytes(name);
                for (int k = 0; k < name.Length; k++) name[k] = (byte)(0x41 + (name[k] % 26));
                WriteVarInt(bw, (ulong)name.Length);
                bw.Write(name);
                bw.Write((ushort)rng.Next(0, 8));     // params count
                bw.Write((byte)(rng.Next(2) == 0 ? 1 : 0)); // hasReturn
                bw.Write((byte)rng.Next(0, 16));     // callFlags
            }

            bw.Write((ushort)0); // reserve

            byte[] script = new byte[rng.Next(1, 256)];
            rng.NextBytes(script);
            WriteVarInt(bw, (ulong)script.Length);
            bw.Write(script);
        }
        byte[] prefix = ms.ToArray();
        Span<byte> hashFirst = stackalloc byte[32];
        SHA256.HashData(prefix, hashFirst);
        Span<byte> hashSecond = stackalloc byte[32];
        SHA256.HashData(hashFirst, hashSecond);
        uint checksum = BinaryPrimitives.ReadUInt32LittleEndian(hashSecond);
        byte[] full = new byte[prefix.Length + 4];
        Array.Copy(prefix, full, prefix.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(full.AsSpan(prefix.Length), checksum);
        return full;
    }

    private static void WriteVarInt(BinaryWriter bw, ulong v)
    {
        if (v < 0xFD) bw.Write((byte)v);
        else if (v <= 0xFFFF) { bw.Write((byte)0xFD); bw.Write((ushort)v); }
        else if (v <= 0xFFFFFFFF) { bw.Write((byte)0xFE); bw.Write((uint)v); }
        else { bw.Write((byte)0xFF); bw.Write(v); }
    }
}
