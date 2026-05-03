using System;
using System.IO;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Tests;

public class NefParserTests
{
    [Fact]
    public void Parse_Roundtrip_FromHandcraftedNef()
    {
        // Build a minimal valid NEF in memory: empty source, no tokens, a 2-byte script.
        var script = new byte[] { 0x40, 0x40 }; // RET RET
        byte[] bytes = BuildNef("dotnet-3.0", "", System.Array.Empty<MethodToken>(), script);

        var nef = NefFile.Parse(bytes, verifyChecksum: true);

        nef.Compiler.Should().Be("dotnet-3.0");
        nef.Source.Should().Be("");
        nef.Tokens.Should().BeEmpty();
        nef.Script.Should().BeEquivalentTo(script);
    }

    [Fact]
    public void Parse_BadMagic_Throws()
    {
        var bytes = new byte[100];
        // First 4 bytes left as zeros -> wrong magic.
        var act = () => NefFile.Parse(bytes, verifyChecksum: false);
        act.Should().Throw<FormatException>().WithMessage("*magic*");
    }

    [Fact]
    public void Parse_BadChecksum_Throws()
    {
        var script = new byte[] { 0x40 };
        byte[] bytes = BuildNef("dotnet", "", System.Array.Empty<MethodToken>(), script);
        // Tamper with the script byte; checksum should now mismatch.
        bytes[bytes.Length - 5] = (byte)(bytes[bytes.Length - 5] ^ 0xFF);
        var act = () => NefFile.Parse(bytes, verifyChecksum: true);
        act.Should().Throw<FormatException>().WithMessage("*checksum*");
    }

    [Fact]
    public void Parse_EmptyScript_Throws()
    {
        // Per Neo.SmartContract.NefFile, a NEF with zero-length script is invalid — there's
        // nothing for the VM to execute. The parser must reject it before the engine ever sees it.
        byte[] bytes = BuildNef("dotnet", "", System.Array.Empty<MethodToken>(), System.Array.Empty<byte>());
        var act = () => NefFile.Parse(bytes, verifyChecksum: true);
        act.Should().Throw<FormatException>().WithMessage("*script*non-empty*");
    }

    [Fact]
    public void Parse_NonZeroReserveByte_Throws()
    {
        // Reserved bytes in the wire format must be zero — non-zero almost always signals a
        // corrupt or future-version NEF the parser doesn't understand.
        var script = new byte[] { 0x40 };
        byte[] bytes = BuildNef("dotnet", "", System.Array.Empty<MethodToken>(), script);
        // Patch the single-byte reserve right after the source varbytes (positions: 4 magic +
        // 64 compiler + 1 source-len(0) = 69, then the next byte is reserve1). We set it to 1.
        bytes[69] = 1;
        // Recompute checksum so we test the reserve check, not the checksum.
        uint cs = NefFile.ComputeChecksum(bytes.AsSpan(0, bytes.Length - 4));
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(
            bytes.AsSpan(bytes.Length - 4), cs);
        var act = () => NefFile.Parse(bytes, verifyChecksum: true);
        act.Should().Throw<FormatException>().WithMessage("*reserved byte 1*");
    }

    [Fact]
    public void Parse_TruncatedNef_Throws()
    {
        // A NEF file shorter than its declared structure must fail with FormatException, not
        // bubble an EndOfStreamException out of BinaryReader (audit C# #29 lineage).
        var script = new byte[] { 0x40 };
        byte[] bytes = BuildNef("dotnet", "", System.Array.Empty<MethodToken>(), script);
        // Drop the trailing checksum + half the script's varbytes prefix to simulate truncation.
        var truncated = bytes.AsSpan(0, bytes.Length - 6).ToArray();
        var act = () => NefFile.Parse(truncated, verifyChecksum: false);
        act.Should().Throw<System.Exception>(
            "any failure mode is acceptable as long as the parser doesn't accept a truncated file");
    }

    [Fact]
    public void Parse_RoundtripWithMethodTokens_PreservesAllFields()
    {
        // Tokens path was previously untested. Build a NEF with two CALLT tokens, parse it, and
        // assert every field round-trips. This covers MethodToken.Read which is its own decoder.
        var hashA = new byte[20]; for (int i = 0; i < 20; i++) hashA[i] = (byte)i;
        var hashB = new byte[20]; for (int i = 0; i < 20; i++) hashB[i] = (byte)(i * 3);
        var tokens = new[]
        {
            new MethodToken(hashA, "transfer", ParametersCount: 4, HasReturnValue: true, CallFlags: 0x0F),
            new MethodToken(hashB, "balanceOf", ParametersCount: 1, HasReturnValue: true, CallFlags: 0x01),
        };
        byte[] bytes = BuildNef("dotnet-3.0", "github.com/example", tokens,
            new byte[] { 0x40, 0x40 });

        var nef = NefFile.Parse(bytes, verifyChecksum: true);

        nef.Compiler.Should().Be("dotnet-3.0");
        nef.Source.Should().Be("github.com/example");
        nef.Tokens.Should().HaveCount(2);
        nef.Tokens[0].Hash.Should().BeEquivalentTo(hashA);
        nef.Tokens[0].Method.Should().Be("transfer");
        nef.Tokens[0].ParametersCount.Should().Be(4);
        nef.Tokens[0].HasReturnValue.Should().BeTrue();
        nef.Tokens[0].CallFlags.Should().Be(0x0F);
        nef.Tokens[1].Method.Should().Be("balanceOf");
        nef.Tokens[1].CallFlags.Should().Be(0x01);
    }

    [Fact]
    public void Parse_VerifyChecksumFalse_AcceptsTamperedNef()
    {
        // The verifyChecksum=false code path is used by the fuzzer's structured-mutation target
        // and by exploration tools that operate on intentionally-malformed inputs. Ensure it
        // doesn't accidentally re-enforce checksum validation.
        var script = new byte[] { 0x40 };
        byte[] bytes = BuildNef("dotnet", "", System.Array.Empty<MethodToken>(), script);
        bytes[bytes.Length - 5] = (byte)(bytes[bytes.Length - 5] ^ 0xFF);
        var nef = NefFile.Parse(bytes, verifyChecksum: false);
        nef.Compiler.Should().Be("dotnet");
    }

    private static byte[] BuildNef(string compiler, string source, MethodToken[] tokens, byte[] script)
    {
        using var ms = new MemoryStream();
        using (var bw = new BinaryWriter(ms, System.Text.Encoding.ASCII, leaveOpen: true))
        {
            bw.Write(NefFile.MagicValue);
            var compilerBytes = new byte[64];
            var compilerStr = System.Text.Encoding.ASCII.GetBytes(compiler);
            System.Array.Copy(compilerStr, compilerBytes, System.Math.Min(compilerStr.Length, 64));
            bw.Write(compilerBytes);
            WriteVarBytes(bw, System.Text.Encoding.ASCII.GetBytes(source));
            bw.Write((byte)0); // reserve
            WriteVarInt(bw, (ulong)tokens.Length);
            foreach (var t in tokens) WriteToken(bw, t);
            bw.Write((ushort)0); // reserve
            WriteVarBytes(bw, script);
        }
        // Now compute checksum over the prefix.
        byte[] prefix = ms.ToArray();
        uint checksum = NefFile.ComputeChecksum(prefix);
        byte[] full = new byte[prefix.Length + 4];
        System.Array.Copy(prefix, full, prefix.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(full.AsSpan(prefix.Length), checksum);
        return full;
    }

    private static void WriteVarBytes(BinaryWriter bw, byte[] bytes)
    {
        WriteVarInt(bw, (ulong)bytes.Length);
        bw.Write(bytes);
    }

    private static void WriteVarInt(BinaryWriter bw, ulong value)
    {
        if (value < 0xFD) { bw.Write((byte)value); }
        else if (value <= 0xFFFF) { bw.Write((byte)0xFD); bw.Write((ushort)value); }
        else if (value <= 0xFFFFFFFF) { bw.Write((byte)0xFE); bw.Write((uint)value); }
        else { bw.Write((byte)0xFF); bw.Write(value); }
    }

    private static void WriteToken(BinaryWriter bw, MethodToken t)
    {
        bw.Write(t.Hash);
        var nameBytes = System.Text.Encoding.UTF8.GetBytes(t.Method);
        WriteVarInt(bw, (ulong)nameBytes.Length);
        bw.Write(nameBytes);
        bw.Write(t.ParametersCount);
        bw.Write((byte)(t.HasReturnValue ? 1 : 0));
        bw.Write(t.CallFlags);
    }
}
