using System;
using System.Linq;
using System.Text;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Oracle: <see cref="SymbolicEngine.Run"/> is deterministic. Running the engine twice on
/// the same script with the same options must produce structurally-equal results: same
/// number of final states, same per-state status, same PC, same final stack size, same
/// telemetry counters. A divergence here is always a bug — either non-deterministic ordering
/// in the worklist drainage, hash randomization seeping into a cross-state ordering, or
/// a non-deterministic data structure (e.g. a HashSet whose enumeration order leaked into
/// state-equality logic).
///
/// Why the existing fuzzer never caught a determinism bug: the engine target only checks
/// "no Running status after Run()". Two non-deterministic but otherwise-valid runs both
/// pass that property. This oracle compares the runs against each other.
/// </summary>
public sealed class DeterminismOracleTarget : IFuzzTarget
{
    public string Name => "engine-determinism";
    public Type[] ExpectedExceptions => Type.EmptyTypes;
    public bool SupportsDirectReplay => true;

    // Audit fix (iter-2 wakeup-36): PerRunDeadline at 30 s.
    //
    // Iteration history:
    //   wakeup-35: removed PerRunDeadline entirely — it caused JIT-warmup-dependent
    //   non-determinism (first run hits 2 s deadline, second doesn't). But that left the
    //   oracle without a memory safety net; a pathological iteration can allocate 8 GB
    //   in a single Run() before MaxSteps fires.
    //
    //   wakeup-36 (now): PerRunDeadline = 30 s. JIT warmup variance is ~tens of ms; with
    //   a 30 s budget that's < 0.2% of the limit, so both runs always agree on whether
    //   the deadline fires. Memory bombs are still bounded.
    private static readonly ExecutionOptions Options = new()
    {
        MaxSteps = 2_000, MaxPaths = 32, MaxStackSize = 128,
        MaxInvocationStackDepth = 64, MaxItemSize = 32 * 1024,
        MaxCollectionSize = 256, MaxHeapObjects = 512,
        MaxQueuedStates = 128,
        PerRunDeadline = System.TimeSpan.FromSeconds(30),
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 4, 64);
        reproInput = bytes;
        return RunWithInput(bytes, out reason);
    }

    public bool RunWithInput(byte[] input, out string? reason)
    {
        reason = null;
        NeoProgram program;
        try { program = ScriptDecoder.Decode(input); }
        catch (VmFaultException) { return true; }

        var first = new SymbolicEngine(program, Options).Run();
        var second = new SymbolicEngine(program, Options).Run();

        if (first.FinalStates.Length != second.FinalStates.Length)
        {
            reason = $"non-deterministic state count: {first.FinalStates.Length} vs {second.FinalStates.Length}";
            return false;
        }
        if (first.StepsExecuted != second.StepsExecuted)
        {
            reason = $"non-deterministic steps: {first.StepsExecuted} vs {second.StepsExecuted}";
            return false;
        }
        if (first.StatesExplored != second.StatesExplored)
        {
            reason = $"non-deterministic states-explored: {first.StatesExplored} vs {second.StatesExplored}";
            return false;
        }
        if (first.BudgetExceeded != second.BudgetExceeded)
        {
            reason = $"non-deterministic budget: {first.BudgetExceeded} vs {second.BudgetExceeded}";
            return false;
        }

        // Element-wise: each final state must match its counterpart on observable fields.
        for (int i = 0; i < first.FinalStates.Length; i++)
        {
            var a = first.FinalStates[i];
            var b = second.FinalStates[i];
            if (a.Status != b.Status) { reason = $"state[{i}] status: {a.Status} vs {b.Status}"; return false; }
            if (a.Pc != b.Pc) { reason = $"state[{i}] pc: 0x{a.Pc:X4} vs 0x{b.Pc:X4}"; return false; }
            if (a.EvaluationStack.Count != b.EvaluationStack.Count)
            { reason = $"state[{i}] stack size: {a.EvaluationStack.Count} vs {b.EvaluationStack.Count}"; return false; }
            if (a.Path.Count != b.Path.Count)
            { reason = $"state[{i}] path length: {a.Path.Count} vs {b.Path.Count}"; return false; }
            if (a.Telemetry.StorageOps.Count != b.Telemetry.StorageOps.Count)
            { reason = $"state[{i}] storage ops: {a.Telemetry.StorageOps.Count} vs {b.Telemetry.StorageOps.Count}"; return false; }
            if (a.Telemetry.ExternalCalls.Count != b.Telemetry.ExternalCalls.Count)
            { reason = $"state[{i}] external calls: {a.Telemetry.ExternalCalls.Count} vs {b.Telemetry.ExternalCalls.Count}"; return false; }
            if (a.Telemetry.WitnessChecks.Count != b.Telemetry.WitnessChecks.Count)
            { reason = $"state[{i}] witness checks: {a.Telemetry.WitnessChecks.Count} vs {b.Telemetry.WitnessChecks.Count}"; return false; }
            if (a.Telemetry.WitnessChecksEnforced.Count != b.Telemetry.WitnessChecksEnforced.Count)
            { reason = $"state[{i}] witness enforced: {a.Telemetry.WitnessChecksEnforced.Count} vs {b.Telemetry.WitnessChecksEnforced.Count}"; return false; }
            if (a.Telemetry.GasCost != b.Telemetry.GasCost)
            { reason = $"state[{i}] gas: {a.Telemetry.GasCost} vs {b.Telemetry.GasCost}"; return false; }
            // Path ordering must also be identical — a divergence here points to non-deterministic
            // worklist scheduling, which would in turn make any path-sensitive detector unstable.
            for (int p = 0; p < a.Path.Count; p++)
            {
                if (a.Path[p] != b.Path[p])
                {
                    reason = $"state[{i}] path[{p}]: 0x{a.Path[p]:X4} vs 0x{b.Path[p]:X4}";
                    return false;
                }
            }
        }
        return true;
    }
}
