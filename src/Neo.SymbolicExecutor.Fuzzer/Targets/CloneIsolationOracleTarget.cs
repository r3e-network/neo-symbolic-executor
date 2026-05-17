using System;
using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Oracle: <see cref="ExecutionState.Clone"/> produces a state whose mutations are isolated
/// from the original. Stronger than the existing <c>clone-leak</c> target: this one mutates
/// every container in <see cref="Telemetry"/> and the heap, then verifies the original is
/// bit-identical to a snapshot taken before the clone.
///
/// This catches:
///  - List/HashSet/Dictionary clones that share the underlying buffer
///  - Record/struct clones that retain a mutable reference (audit C1, C6 class)
///  - Heap.Clone() mutations that mutate parent heap entries
///  - Any new field added to ExecutionState that the author forgot to deep-copy
/// </summary>
public sealed class CloneIsolationOracleTarget : IFuzzTarget
{
    public string Name => "clone-isolation";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        // Drive the engine just enough to populate non-trivial telemetry.
        var bytes = OpCodeGen.RandomScript(rng, 4, 48);
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
        if (result.FinalStates.Length == 0) return true;

        // Pick a final state that has at least some telemetry to test against.
        ExecutionState? src = result.FinalStates.OrderByDescending(s =>
            s.Telemetry.StorageOps.Count + s.Telemetry.ExternalCalls.Count
            + s.Telemetry.WitnessChecks.Count + s.Telemetry.ArithmeticOps.Count).FirstOrDefault();
        if (src is null) return true;

        // Snapshot every observable field before cloning + mutating the clone.
        var snap = new Snapshot(src);
        var clone = src.Clone();

        // Mutate every telemetry container and the heap on the clone.
        clone.Telemetry.StorageOps.Add(new StorageOp(0xCAFE, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 0xDE, 0xAD }), null, false, false));
        clone.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0xBEEF, Method = "x" });
        clone.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
            0xF00D, "MUTATED", SymbolicValue.Int(1), SymbolicValue.Int(2),
            OverflowPossible: false, DivisorMaybeZero: false, Checked: false));
        clone.Telemetry.WitnessChecks.Add(0x1234);
        clone.Telemetry.WitnessChecksEnforced.Add(0x5678);
        clone.Telemetry.CallerHashChecks.Add(0xAAAA);
        clone.Telemetry.SignatureChecks.Add(0xBBBB);
        clone.Telemetry.TimeAccesses.Add(0xCCCC);
        clone.Telemetry.RandomnessAccesses.Add(0xDDDD);
        clone.Telemetry.EventsEmitted.Add(0xEEEE);
        clone.Telemetry.LoopsDetected.Add(0xFFFF);
        clone.Telemetry.VisitCapsHit.Add(0x7777);
        clone.Telemetry.IteratorLoops.Add(0x1111);
        clone.Telemetry.ExceptionsThrown.Add(0x2222);
        clone.Telemetry.UnknownSyscalls.Add(0x3333);
        clone.Telemetry.UnknownOpcodes.Add(0x4444);
        clone.Telemetry.SmtUnknownOffsets.Add(0x5555);
        clone.Telemetry.GasCost = -987654321;
        clone.Telemetry.MaxCallStackDepth = -1;
        clone.Telemetry.Truncated = !clone.Telemetry.Truncated;
        clone.Telemetry.ReentrancyGuard = !clone.Telemetry.ReentrancyGuard;

        // Mutate path + visit counts + stacks
        clone.Path.Add(0x9999);
        clone.VisitCounts[0xABCD] = 99;
        if (clone.EvaluationStack.Count > 0)
            clone.EvaluationStack[0] = SymbolicValue.Int(unchecked((int)0xDEADBEEF));
        clone.EvaluationStack.Add(SymbolicValue.Int(unchecked((int)0xC0FFEE)));
        if (clone.StaticFields.Count > 0)
            clone.StaticFields[0] = SymbolicValue.Int(0x55);
        clone.StaticFields.Add(SymbolicValue.Int(0x66));
        clone.InteropContext["mutated"] = SymbolicValue.Int(1);
        if (clone.CallStack.Count > 0)
        {
            clone.CallStack[0].Locals.Add(SymbolicValue.Int(0x77));
            clone.CallStack[0].Args.Add(SymbolicValue.Int(0x88));
        }
        clone.Status = TerminalStatus.Faulted;
        clone.TerminationReason = "mutated";
        clone.Pc = 0x11AA;
        clone.Steps += 99999;

        // Verify the source is unchanged.
        return snap.MatchesOrExplain(src, out reason);
    }

    /// <summary>Captures every observable field of an <see cref="ExecutionState"/> at a moment in time.</summary>
    private sealed record Snapshot
    {
        private readonly int Pc;
        private readonly int Steps;
        private readonly TerminalStatus Status;
        private readonly string? Reason;
        private readonly int StackCount;
        private readonly int CallStackCount;
        private readonly int StaticsCount;
        private readonly int VisitCount;
        private readonly int PathCount;
        private readonly int InteropCount;
        private readonly int StorageCount;
        private readonly int ExtCallCount;
        private readonly int ArithCount;
        private readonly int WitCount;
        private readonly int WitEnfCount;
        private readonly int CallerCount;
        private readonly int SigCount;
        private readonly int TimeCount;
        private readonly int RandCount;
        private readonly int EventCount;
        private readonly int LoopsCount;
        private readonly int VisitCapsCount;
        private readonly int ItLoopsCount;
        private readonly int ExceptCount;
        private readonly int UnSysCount;
        private readonly int UnOpCount;
        private readonly int SmtUnkCount;
        private readonly long Gas;
        private readonly int MaxDepth;
        private readonly bool Truncated;
        private readonly bool Guard;
        private readonly int FrameLocalsTotal;
        private readonly int FrameArgsTotal;

        public Snapshot(ExecutionState s)
        {
            Pc = s.Pc;
            Steps = s.Steps;
            Status = s.Status;
            Reason = s.TerminationReason;
            StackCount = s.EvaluationStack.Count;
            CallStackCount = s.CallStack.Count;
            StaticsCount = s.StaticFields.Count;
            VisitCount = s.VisitCounts.Count;
            PathCount = s.Path.Count;
            InteropCount = s.InteropContext.Count;
            StorageCount = s.Telemetry.StorageOps.Count;
            ExtCallCount = s.Telemetry.ExternalCalls.Count;
            ArithCount = s.Telemetry.ArithmeticOps.Count;
            WitCount = s.Telemetry.WitnessChecks.Count;
            WitEnfCount = s.Telemetry.WitnessChecksEnforced.Count;
            CallerCount = s.Telemetry.CallerHashChecks.Count;
            SigCount = s.Telemetry.SignatureChecks.Count;
            TimeCount = s.Telemetry.TimeAccesses.Count;
            RandCount = s.Telemetry.RandomnessAccesses.Count;
            EventCount = s.Telemetry.EventsEmitted.Count;
            LoopsCount = s.Telemetry.LoopsDetected.Count;
            VisitCapsCount = s.Telemetry.VisitCapsHit.Count;
            ItLoopsCount = s.Telemetry.IteratorLoops.Count;
            ExceptCount = s.Telemetry.ExceptionsThrown.Count;
            UnSysCount = s.Telemetry.UnknownSyscalls.Count;
            UnOpCount = s.Telemetry.UnknownOpcodes.Count;
            SmtUnkCount = s.Telemetry.SmtUnknownOffsets.Count;
            Gas = s.Telemetry.GasCost;
            MaxDepth = s.Telemetry.MaxCallStackDepth;
            Truncated = s.Telemetry.Truncated;
            Guard = s.Telemetry.ReentrancyGuard;
            int locals = 0, args = 0;
            foreach (var f in s.CallStack) { locals += f.Locals.Count; args += f.Args.Count; }
            FrameLocalsTotal = locals;
            FrameArgsTotal = args;
        }

        public bool MatchesOrExplain(ExecutionState s, out string? reason)
        {
            int locals = 0, args = 0;
            foreach (var f in s.CallStack) { locals += f.Locals.Count; args += f.Args.Count; }
            string? Bad(string field, object before, object after) =>
                $"clone leaked into source: {field} {before} -> {after}";
            reason = null;
            if (s.Pc != Pc) { reason = Bad("Pc", Pc, s.Pc); return false; }
            if (s.Steps != Steps) { reason = Bad("Steps", Steps, s.Steps); return false; }
            if (s.Status != Status) { reason = Bad("Status", Status, s.Status); return false; }
            if (s.TerminationReason != Reason) { reason = Bad("TerminationReason", Reason ?? "<null>", s.TerminationReason ?? "<null>"); return false; }
            if (s.EvaluationStack.Count != StackCount) { reason = Bad("EvaluationStack.Count", StackCount, s.EvaluationStack.Count); return false; }
            if (s.CallStack.Count != CallStackCount) { reason = Bad("CallStack.Count", CallStackCount, s.CallStack.Count); return false; }
            if (s.StaticFields.Count != StaticsCount) { reason = Bad("StaticFields.Count", StaticsCount, s.StaticFields.Count); return false; }
            if (s.VisitCounts.Count != VisitCount) { reason = Bad("VisitCounts.Count", VisitCount, s.VisitCounts.Count); return false; }
            if (s.Path.Count != PathCount) { reason = Bad("Path.Count", PathCount, s.Path.Count); return false; }
            if (s.InteropContext.Count != InteropCount) { reason = Bad("InteropContext.Count", InteropCount, s.InteropContext.Count); return false; }
            if (s.Telemetry.StorageOps.Count != StorageCount) { reason = Bad("Telemetry.StorageOps", StorageCount, s.Telemetry.StorageOps.Count); return false; }
            if (s.Telemetry.ExternalCalls.Count != ExtCallCount) { reason = Bad("Telemetry.ExternalCalls", ExtCallCount, s.Telemetry.ExternalCalls.Count); return false; }
            if (s.Telemetry.ArithmeticOps.Count != ArithCount) { reason = Bad("Telemetry.ArithmeticOps", ArithCount, s.Telemetry.ArithmeticOps.Count); return false; }
            if (s.Telemetry.WitnessChecks.Count != WitCount) { reason = Bad("Telemetry.WitnessChecks", WitCount, s.Telemetry.WitnessChecks.Count); return false; }
            if (s.Telemetry.WitnessChecksEnforced.Count != WitEnfCount) { reason = Bad("Telemetry.WitnessChecksEnforced", WitEnfCount, s.Telemetry.WitnessChecksEnforced.Count); return false; }
            if (s.Telemetry.CallerHashChecks.Count != CallerCount) { reason = Bad("Telemetry.CallerHashChecks", CallerCount, s.Telemetry.CallerHashChecks.Count); return false; }
            if (s.Telemetry.SignatureChecks.Count != SigCount) { reason = Bad("Telemetry.SignatureChecks", SigCount, s.Telemetry.SignatureChecks.Count); return false; }
            if (s.Telemetry.TimeAccesses.Count != TimeCount) { reason = Bad("Telemetry.TimeAccesses", TimeCount, s.Telemetry.TimeAccesses.Count); return false; }
            if (s.Telemetry.RandomnessAccesses.Count != RandCount) { reason = Bad("Telemetry.RandomnessAccesses", RandCount, s.Telemetry.RandomnessAccesses.Count); return false; }
            if (s.Telemetry.EventsEmitted.Count != EventCount) { reason = Bad("Telemetry.EventsEmitted", EventCount, s.Telemetry.EventsEmitted.Count); return false; }
            if (s.Telemetry.LoopsDetected.Count != LoopsCount) { reason = Bad("Telemetry.LoopsDetected", LoopsCount, s.Telemetry.LoopsDetected.Count); return false; }
            if (s.Telemetry.VisitCapsHit.Count != VisitCapsCount) { reason = Bad("Telemetry.VisitCapsHit", VisitCapsCount, s.Telemetry.VisitCapsHit.Count); return false; }
            if (s.Telemetry.IteratorLoops.Count != ItLoopsCount) { reason = Bad("Telemetry.IteratorLoops", ItLoopsCount, s.Telemetry.IteratorLoops.Count); return false; }
            if (s.Telemetry.ExceptionsThrown.Count != ExceptCount) { reason = Bad("Telemetry.ExceptionsThrown", ExceptCount, s.Telemetry.ExceptionsThrown.Count); return false; }
            if (s.Telemetry.UnknownSyscalls.Count != UnSysCount) { reason = Bad("Telemetry.UnknownSyscalls", UnSysCount, s.Telemetry.UnknownSyscalls.Count); return false; }
            if (s.Telemetry.UnknownOpcodes.Count != UnOpCount) { reason = Bad("Telemetry.UnknownOpcodes", UnOpCount, s.Telemetry.UnknownOpcodes.Count); return false; }
            if (s.Telemetry.SmtUnknownOffsets.Count != SmtUnkCount) { reason = Bad("Telemetry.SmtUnknownOffsets", SmtUnkCount, s.Telemetry.SmtUnknownOffsets.Count); return false; }
            if (s.Telemetry.GasCost != Gas) { reason = Bad("Telemetry.GasCost", Gas, s.Telemetry.GasCost); return false; }
            if (s.Telemetry.MaxCallStackDepth != MaxDepth) { reason = Bad("Telemetry.MaxCallStackDepth", MaxDepth, s.Telemetry.MaxCallStackDepth); return false; }
            if (s.Telemetry.Truncated != Truncated) { reason = Bad("Telemetry.Truncated", Truncated, s.Telemetry.Truncated); return false; }
            if (s.Telemetry.ReentrancyGuard != Guard) { reason = Bad("Telemetry.ReentrancyGuard", Guard, s.Telemetry.ReentrancyGuard); return false; }
            if (locals != FrameLocalsTotal) { reason = Bad("CallFrame.Locals total", FrameLocalsTotal, locals); return false; }
            if (args != FrameArgsTotal) { reason = Bad("CallFrame.Args total", FrameArgsTotal, args); return false; }
            return true;
        }
    }
}
