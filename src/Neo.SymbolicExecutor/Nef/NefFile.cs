using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Neo.SymbolicExecutor.Nef;

/// <summary>
/// NEO Executable Format 3 container, mirroring Neo.SmartContract.NefFile structure exactly.
/// We parse independently of the Neo SmartContract NuGet so this library can ship with a
/// minimal dependency surface.
///
/// Layout:
///   uint32 magic = 0x3346454E ("NEF3")
///   byte[64] compiler (null-padded ASCII)
///   varbytes source
///   byte reserved (must be 0)
///   varbytes-prefixed array of MethodToken
///   uint16 reserved (must be 0)
///   varbytes script
///   uint32 checksum (first 4 bytes of double-SHA256 over the prefix bytes)
/// </summary>
public sealed class NefFile
{
    public const uint MagicValue = 0x3346454E;

    // Review note (#52/#76): the binary STRUCTURE/layout mirrors Neo.SmartContract.NefFile exactly,
    // but these size limits are intentionally RELAXED analysis budgets, not Neo's deploy-time limits
    // (Neo caps script at 131070 bytes). A relaxed cap only ever accepts a SUPERSET of Neo-deployable
    // inputs, so it never narrows the analyzed surface and has no soundness impact; oversized inputs
    // are bounded here so the analyzer cannot be DoS'd. The compiler/source fixed strings are decoded
    // as ASCII with lenient NUL-trimming (vs Neo's strict UTF-8 / strict NUL-padding); MethodToken
    // method names are already validated as strict UTF-8 (see MethodToken.Read).
    public const int MaxScriptSize = 512 * 1024;

    public required string Compiler { get; init; }
    public required string Source { get; init; }
    public required MethodToken[] Tokens { get; init; }
    public required byte[] Script { get; init; }
    public uint Checksum { get; init; }

    public static NefFile Parse(byte[] data, bool verifyChecksum = true)
    {
        if (data is null) throw new ArgumentNullException(nameof(data));
        try
        {
            using var ms = new MemoryStream(data);
            using var br = new BinaryReader(ms, Encoding.ASCII, leaveOpen: true);

            uint magic = br.ReadUInt32();
            if (magic != MagicValue)
                throw new FormatException($"NEF magic mismatch: got 0x{magic:X8}, expected 0x{MagicValue:X8}");

            byte[] compilerBytes = br.ReadBytes(64);
            if (compilerBytes.Length != 64)
                throw new FormatException("NEF compiler section truncated");
            string compiler = TrimNul(Encoding.ASCII.GetString(compilerBytes));

            string source = TrimNul(Encoding.ASCII.GetString(ReadVarBytes(br, maxLength: 256)));

            byte reserve1 = br.ReadByte();
            if (reserve1 != 0) throw new FormatException("NEF reserved byte 1 must be zero");

            ushort tokenCount = (ushort)ReadVarInt(br, maxValue: 128);
            var tokens = new MethodToken[tokenCount];
            for (int i = 0; i < tokenCount; i++)
                tokens[i] = MethodToken.Read(br);

            ushort reserve2 = br.ReadUInt16();
            if (reserve2 != 0) throw new FormatException("NEF reserved bytes 2 must be zero");

            byte[] script = ReadVarBytes(br, maxLength: MaxScriptSize);
            if (script.Length == 0) throw new FormatException("NEF script must be non-empty");

            long checksumOffset = ms.Position;
            uint checksum = br.ReadUInt32();
            if (ms.Position != ms.Length)
            {
                throw new FormatException(
                    $"NEF has {ms.Length - ms.Position} trailing byte(s) after checksum");
            }

            if (verifyChecksum)
            {
                uint expected = ComputeChecksum(data.AsSpan(0, (int)checksumOffset));
                if (expected != checksum)
                    throw new FormatException($"NEF checksum mismatch: got 0x{checksum:X8}, expected 0x{expected:X8}");
            }

            return new NefFile
            {
                Compiler = compiler,
                Source = source,
                Tokens = tokens,
                Script = script,
                Checksum = checksum,
            };
        }
        catch (EndOfStreamException ex)
        {
            throw new FormatException("NEF file truncated before all required fields were present", ex);
        }
        catch (IOException ex)
        {
            throw new FormatException($"NEF file could not be parsed: {ex.Message}", ex);
        }
    }

    public static uint ComputeChecksum(ReadOnlySpan<byte> bytes)
    {
        Span<byte> first = stackalloc byte[32];
        SHA256.HashData(bytes, first);
        Span<byte> second = stackalloc byte[32];
        SHA256.HashData(first, second);
        return BinaryPrimitives.ReadUInt32LittleEndian(second);
    }

    private static byte[] ReadVarBytes(BinaryReader br, int maxLength)
    {
        long length = ReadVarInt(br, maxValue: maxLength);
        if (length < 0 || length > maxLength)
            throw new FormatException($"VarBytes length {length} out of range");
        var bytes = br.ReadBytes((int)length);
        if (bytes.Length != length)
            throw new FormatException($"VarBytes truncated: wanted {length}, got {bytes.Length}");
        return bytes;
    }

    private static long ReadVarInt(BinaryReader br, long maxValue)
    {
        byte fb = br.ReadByte();
        long value = fb switch
        {
            0xFD => br.ReadUInt16(),
            0xFE => br.ReadUInt32(),
            0xFF => (long)br.ReadUInt64(),
            _ => fb,
        };
        if (value < 0 || value > maxValue)
            throw new FormatException($"VarInt {value} exceeds max {maxValue}");
        return value;
    }

    private static string TrimNul(string s)
    {
        int i = s.IndexOf('\0');
        return i < 0 ? s : s[..i];
    }
}

/// <summary>
/// CALLT method token. Mirrors Neo.SmartContract.MethodToken serialization:
///   byte[20] hash + varstring method + ushort parametersCount + bool hasReturnValue + byte callFlags.
/// </summary>
public sealed record MethodToken(
    byte[] Hash,
    string Method,
    ushort ParametersCount,
    bool HasReturnValue,
    byte CallFlags)
{
    private const byte ValidCallFlagsMask = 0x0F;
    private static readonly UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static MethodToken Read(BinaryReader br)
    {
        var hash = br.ReadBytes(20);
        if (hash.Length != 20) throw new FormatException("MethodToken hash truncated");
        long len = br.ReadByte();
        len = len switch
        {
            0xFD => br.ReadUInt16(),
            0xFE => br.ReadUInt32(),
            0xFF => (long)br.ReadUInt64(),
            _ => len,
        };
        if (len < 0 || len > 32) throw new FormatException("MethodToken method name too long");
        // Audit C# #29 fix: BinaryReader.ReadBytes returns short-read buffers on EOF without
        // throwing. Validate length explicitly so we don't produce a truncated method name.
        var nameBytes = br.ReadBytes((int)len);
        if (nameBytes.Length != len)
            throw new FormatException($"MethodToken name truncated: wanted {len}, got {nameBytes.Length}");
        string name;
        try
        {
            name = StrictUtf8.GetString(nameBytes);
        }
        catch (DecoderFallbackException ex)
        {
            throw new FormatException("MethodToken method name is not valid strict UTF-8", ex);
        }
        ushort parametersCount = br.ReadUInt16();
        byte hasReturnValueByte = br.ReadByte();
        if (hasReturnValueByte is not 0 and not 1)
            throw new FormatException("MethodToken hasReturnValue must be encoded as 0 or 1");
        bool hasRet = hasReturnValueByte == 1;
        byte callFlags = br.ReadByte();
        if ((callFlags & ~ValidCallFlagsMask) != 0)
            throw new FormatException($"MethodToken callFlags contain unsupported bits: 0x{callFlags:X2}");
        return new MethodToken(hash, name, parametersCount, hasRet, callFlags);
    }
}
