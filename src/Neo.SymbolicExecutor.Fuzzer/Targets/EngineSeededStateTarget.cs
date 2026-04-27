using System;
using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Engine target with symbolic seeds on the stack: forces the SMT-less branching and
/// enforcement-tracking paths to fire. Properties: termination + bounded resources.
/// </summary>
public sealed class EngineSeededStateTarget : IFuzzTarget
{
    public string Name => "engine-seeded";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 4, 32);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; }

        // Audit fix (iter-2 wakeup-2): construct the Heap with the same budgets we'll pass to
        // the engine. The default-constructed Heap allows up to 1 MiB × 4096 objects per state,
        // which under symbolic forking produces multi-GB peaks. The seeded target uses smaller
        // engine budgets but the heap was silently larger.
        var state = new ExecutionState
        {
            Heap = new Heap(maxObjects: 256, maxItemSize: 16 * 1024, maxCollectionSize: 128),
        };
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = 0;

        // Seed the stack with a few symbolic + concrete values to drive symbolic forks.
        int seedCount = rng.Next(0, 6);
        for (int i = 0; i < seedCount; i++)
        {
            switch (rng.Next(4))
            {
                case 0: state.Push(SymbolicValue.Int(rng.Next())); break;
                case 1: state.Push(SymbolicValue.Bool(rng.Next(2) == 0)); break;
                case 2: state.Push(SymbolicValue.Symbol(Sort.Int, $"x{i}")); break;
                case 3: state.Push(SymbolicValue.Symbol(Sort.Bool, $"witness_ok_{i}")); break;
            }
        }

        var result = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 2_000,
            MaxPaths = 32,
            MaxStackSize = 128,
            MaxInvocationStackDepth = 32,
            MaxItemSize = 16 * 1024,
            MaxCollectionSize = 128,
            MaxHeapObjects = 256,
            MaxQueuedStates = 128,
            PerRunDeadline = System.TimeSpan.FromSeconds(2),
        }).Run(state);

        if (result.FinalStates.Any(s => s.Status == TerminalStatus.Running))
        {
            reason = "engine-seeded: state with status=Running";
            return false;
        }
        return true;
    }
}
