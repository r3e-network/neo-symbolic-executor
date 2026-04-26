using System;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>Property: ScriptDecoder.Decode never throws an unexpected exception type.</summary>
public sealed class ScriptDecoderTarget : IFuzzTarget
{
    public string Name => "decoder";
    public Type[] ExpectedExceptions => new[] { typeof(VmFaultException) };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = rng.Next(2) == 0
            ? ByteGen.RandomBytes(rng, 0, 512)
            : OpCodeGen.RandomScript(rng, 1, 64);
        reproInput = bytes;
        reason = null;
        try { _ = ScriptDecoder.Decode(bytes); return true; }
        catch (VmFaultException) { return true; }
    }
}
