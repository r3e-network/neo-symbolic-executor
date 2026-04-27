using System;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Run the full detector set on real engine-produced states (not synthetic ones). Catches
/// bugs that only manifest when telemetry is shaped exactly the way the engine emits it.
/// Properties: no exceptions; deterministic across two consecutive runs.
/// </summary>
public sealed class CombinedDetectorsOnEngineTarget : IFuzzTarget
{
    public string Name => "engine-detectors";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    private static readonly System.Collections.Generic.IReadOnlyList<IDetector> Detectors =
        DefaultDetectorSet.All();

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 8, 64);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; }

        var result = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 2_000, MaxPaths = 16, MaxStackSize = 64,
            MaxItemSize = 16 * 1024, MaxCollectionSize = 128, MaxHeapObjects = 256,
            MaxQueuedStates = 64, PerRunDeadline = System.TimeSpan.FromSeconds(2),
        }).Run();

        var engine = new DetectorEngine(Detectors);
        var ctx = new AnalysisContext { States = result.FinalStates };
        var first = engine.Run(ctx);
        var second = engine.Run(ctx);

        if (first.Length != second.Length) { reason = "non-deterministic finding count"; return false; }
        for (int i = 0; i < first.Length; i++)
        {
            if (first[i].DedupeKey != second[i].DedupeKey
                || first[i].Severity != second[i].Severity
                || Math.Abs(first[i].Confidence - second[i].Confidence) > 1e-9)
            {
                reason = $"non-deterministic finding[{i}]: {first[i].DedupeKey} vs {second[i].DedupeKey}";
                return false;
            }
        }
        return true;
    }
}
