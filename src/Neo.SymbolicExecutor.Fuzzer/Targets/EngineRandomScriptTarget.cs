using System;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Property: random structurally-valid scripts run to a terminal status under tight budgets,
/// and never produce a still-Running state at the end. CatchableVmException must not leak out
/// of <see cref="SymbolicEngine.Run"/>.
/// </summary>
public sealed class EngineRandomScriptTarget : IFuzzTarget
{
    public string Name => "engine";
    public Type[] ExpectedExceptions => Type.EmptyTypes; // engine.Run should swallow everything

    private readonly ExecutionOptions _engineOptions = new()
    {
        MaxSteps = 2_000,
        MaxPaths = 32,
        MaxStackSize = 128,
        MaxInvocationStackDepth = 64,
        MaxItemSize = 64 * 1024,
        MaxCollectionSize = 256,
        MaxQueuedStates = 256,
    };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 2, 64);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; } // decode failure is fine

        var engine = new SymbolicEngine(program, _engineOptions);
        var result = engine.Run();

        // Property 1: every final state has a terminal status.
        if (result.FinalStates.Any(s => s.Status == TerminalStatus.Running))
        {
            reason = "engine produced a state with status=Running after Run() returned";
            return false;
        }
        // Property: bounded total work. The engine has MaxSteps per state and a worklist cap;
        // in the worst case it processes every queued state once. Allow generous headroom.
        long maxAllowed = (long)_engineOptions.MaxSteps * Math.Max(1, _engineOptions.MaxQueuedStates) + 10_000;
        if (result.StepsExecuted > maxAllowed)
        {
            reason = $"step count {result.StepsExecuted} > allowed {maxAllowed} " +
                     $"(MaxSteps={_engineOptions.MaxSteps}, MaxQueuedStates={_engineOptions.MaxQueuedStates})";
            return false;
        }
        return true;
    }
}
