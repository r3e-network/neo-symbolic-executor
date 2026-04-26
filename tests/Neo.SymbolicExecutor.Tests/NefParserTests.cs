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
