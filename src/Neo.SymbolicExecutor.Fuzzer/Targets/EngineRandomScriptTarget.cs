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

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 2, 64);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; } // decode failure is fine

        var engine = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 2_000,
            MaxPaths = 32,
            MaxStackSize = 128,
            MaxInvocationStackDepth = 64,
            MaxItemSize = 64 * 1024,
            MaxCollectionSize = 256,
        });

        var result = engine.Run();

        // Property 1: every final state has a terminal status.
        if (result.FinalStates.Any(s => s.Status == TerminalStatus.Running))
        {
            reason = "engine produced a state with status=Running after Run() returned";
            return false;
        }
        // Property 2: bounded resource use vs the budget.
        if (result.StepsExecuted > 2_000 * Math.Max(1, result.StatesExplored) + 1_000)
        {
            reason = $"step count {result.StepsExecuted} exceeds budget envelope";
            return false;
        }
        return true;
    }
}
