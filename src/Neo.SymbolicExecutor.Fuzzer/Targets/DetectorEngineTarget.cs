using System;
using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Property: running the full detector set against random states never throws and is
/// deterministic — running twice with the same input yields identical findings.
/// </summary>
public sealed class DetectorEngineTarget : IFuzzTarget
{
    public string Name => "detectors";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var states = new List<ExecutionState>();
        int count = rng.Next(1, 6);
        for (int i = 0; i < count; i++) states.Add(StateGen.RandomState(new Random(rng.Next())));

        reproInput = System.Text.Encoding.UTF8.GetBytes($"seed={seed},states={count}");
        reason = null;

        var engine = new DetectorEngine(DefaultDetectorSet.All());
        var ctx = new AnalysisContext { States = states };
        var first = engine.Run(ctx);
        var second = engine.Run(ctx);

        if (first.Length != second.Length)
        {
            reason = $"non-deterministic finding count: {first.Length} vs {second.Length}";
            return false;
        }
        for (int i = 0; i < first.Length; i++)
        {
            if (first[i].DedupeKey != second[i].DedupeKey
                || first[i].Severity != second[i].Severity
                || Math.Abs(first[i].Confidence - second[i].Confidence) > 1e-9
                || !first[i].Tags.SetEquals(second[i].Tags))
            {
                reason = $"non-deterministic finding[{i}]: {first[i].DedupeKey}";
                return false;
            }
        }
        return true;
    }
}
