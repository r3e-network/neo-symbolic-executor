using System;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Property: after engine.Run, mutating one final state never leaks into another. Tests the
/// audit C1/C6 invariant under realistic engine-produced state shapes.
/// </summary>
public sealed class EngineNoCloneLeakTarget : IFuzzTarget
{
    public string Name => "clone-leak";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 2, 32);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; }

        var result = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 1_000,
            MaxPaths = 16,
            MaxStackSize = 64,
            MaxItemSize = 16 * 1024,
            MaxCollectionSize = 128,
            MaxHeapObjects = 256,
            MaxQueuedStates = 64,
            PerRunDeadline = System.TimeSpan.FromSeconds(2),
        }).Run();
        if (result.FinalStates.Length < 2) return true;

        // Pick two states; mutate the first; sample some invariant on the second.
        var s1 = result.FinalStates[0];
        var s2 = result.FinalStates[1];
        int s2WitnessBefore = s2.Telemetry.WitnessChecks.Count;
        int s2ExternalCallsBefore = s2.Telemetry.ExternalCalls.Count;
        int s2StorageOpsBefore = s2.Telemetry.StorageOps.Count;

        s1.Telemetry.WitnessChecks.Add(unchecked((int)0xDEAD));
        s1.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0xBEEF });
        if (s1.Telemetry.StorageOps.Count > 0)
        {
            // we can't mutate the StorageOp record itself, but we can add to storage ops list
            s1.Telemetry.StorageOps.Add(s1.Telemetry.StorageOps[0]);
        }

        if (s2.Telemetry.WitnessChecks.Count != s2WitnessBefore)
        {
            reason = "WitnessChecks mutation leaked across cloned states";
            return false;
        }
        if (s2.Telemetry.ExternalCalls.Count != s2ExternalCallsBefore)
        {
            reason = "ExternalCalls mutation leaked across cloned states";
            return false;
        }
        if (s2.Telemetry.StorageOps.Count != s2StorageOpsBefore)
        {
            reason = "StorageOps mutation leaked across cloned states";
            return false;
        }
        return true;
    }
}
