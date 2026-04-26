using System;
using System.IO;
using Neo.SymbolicExecutor.Fuzzer.Generators;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

public sealed class NefParserTarget : IFuzzTarget
{
    public string Name => "nef";
    public Type[] ExpectedExceptions => new[]
    {
        typeof(FormatException),
        typeof(EndOfStreamException),
        typeof(ArgumentOutOfRangeException),
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = ByteGen.RandomBytes(rng, 0, 2048);
        reproInput = bytes;
        reason = null;
        try { _ = NefFile.Parse(bytes, verifyChecksum: rng.Next(2) == 0); return true; }
        catch (FormatException) { return true; }
        catch (EndOfStreamException) { return true; }
        catch (ArgumentOutOfRangeException) { return true; }
    }
}
