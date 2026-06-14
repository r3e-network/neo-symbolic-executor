using System.Collections.Generic;
using System.Linq;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> HandleCall(ExecutionState state, Instruction inst, int target)
    {
        if (state.CallStack.Count >= _options.MaxInvocationStackDepth)
            throw new VmFaultException("invocation stack overflow");
        var frame = new CallFrame(returnPc: inst.EndOffset);
        state.CallStack.Add(frame);
        if (state.CallStack.Count > state.Telemetry.MaxCallStackDepth)
            state.Telemetry.MaxCallStackDepth = state.CallStack.Count;
        state.Pc = target;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleCallA(ExecutionState state, Instruction inst)
    {
        var ptr = state.Pop();
        if (ptr.Sort != Sort.Pointer)
            throw new VmFaultException($"CALLA requires Pointer StackItem, got {ptr.Sort}");

        var concreteTarget = ptr.AsConcretePointer();
        if (concreteTarget is null)
        {
            state.Terminate(TerminalStatus.Stopped, "CALLA requires concrete Pointer target (no SMT model)");
            return Single(state);
        }
        if (concreteTarget.Value < 0 || concreteTarget.Value >= _program.Bytes.Length)
            throw new VmFaultException($"CALLA target {concreteTarget.Value} outside script bytes");
        if (state.CallStack.Count >= _options.MaxInvocationStackDepth)
            throw new VmFaultException("invocation stack overflow (CALLA)");
        var frame = new CallFrame(returnPc: inst.EndOffset);
        state.CallStack.Add(frame);
        if (state.CallStack.Count > state.Telemetry.MaxCallStackDepth)
            state.Telemetry.MaxCallStackDepth = state.CallStack.Count;
        state.Pc = (int)concreteTarget.Value;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleReturn(ExecutionState state, Instruction inst)
    {
        if (state.CallStack.Count == 0)
        {
            state.Terminate(TerminalStatus.Halted, "RET with empty call stack");
            return Single(state);
        }
        var top = state.CallStack[^1];
        state.CallStack.RemoveAt(state.CallStack.Count - 1);
        if (state.CallStack.Count == 0)
        {
            // Returning from outermost frame -> halt.
            state.Terminate(TerminalStatus.Halted, "outermost RET");
            return Single(state);
        }
        state.Pc = top.ReturnPc;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleAssert(ExecutionState state, Instruction inst, bool withMessage)
    {
        SymbolicValue? msg = null;
        if (withMessage) msg = state.Pop();
        var cond = state.Pop();
        MarkExternalCallReturnChecked(state, cond);

        var truthy = cond.Truthy();
        if (truthy == true)
        {
            MarkConditionalEnforcement(state, cond, taken: true, inst.Offset);
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        if (truthy == false)
        {
            string reason = msg is null ? "ASSERT failed" : "ASSERT failed: " + DescribeMessage(msg);
            state.Terminate(TerminalStatus.Faulted, reason);
            return Single(state);
        }

        var condTruthy = Expr.ToBool(cond.Expression);
        var (passSat, failSat) = ConsultSmt(state, condTruthy);
        if (passSat == Smt.SmtOutcome.Unsat && failSat == Smt.SmtOutcome.Unsat)
        {
            state.Terminate(TerminalStatus.Stopped, "both ASSERT outcomes unsatisfiable");
            return Single(state);
        }
        if (passSat == Smt.SmtOutcome.Unsat)
        {
            state.PathConditions = state.PathConditions.Add(Expr.Not(condTruthy));
            string reason = msg is null ? "ASSERT failed (symbolic)" : "ASSERT failed: " + DescribeMessage(msg);
            state.Terminate(TerminalStatus.Faulted, reason);
            return Single(state);
        }
        if (failSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            state.PathConditions = state.PathConditions.Add(condTruthy);
            MarkConditionalEnforcement(state, cond, taken: true, inst.Offset);
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        if (passSat == Smt.SmtOutcome.Unknown || failSat == Smt.SmtOutcome.Unknown)
            state.Telemetry.SmtUnknownOffsets.Add(inst.Offset);

        // Symbolic assertion: fork into the success path (continue) and failure path (faulted).
        var pass = state.Clone();
        pass.PathConditions = pass.PathConditions.Add(condTruthy);
        MarkConditionalEnforcement(pass, cond, taken: true, inst.Offset);
        pass.Pc = inst.EndOffset;

        var fail = state;
        fail.PathConditions = fail.PathConditions.Add(Expr.Not(condTruthy));
        string failReason = msg is null ? "ASSERT failed (symbolic)" : "ASSERT failed: " + DescribeMessage(msg);
        fail.Terminate(TerminalStatus.Faulted, failReason);

        return new[] { pass, fail };
    }

    private IEnumerable<ExecutionState> HandleXDrop(ExecutionState state, Instruction inst)
    {
        var n = state.Pop();
        var idx = TryConcretizeIndex(state, n, lo: 0, hi: state.EvaluationStack.Count);
        if (idx is null) { state.Terminate(TerminalStatus.Stopped, "XDROP requires concrete count (no SMT model)"); return Single(state); }
        if (idx.Value < 0 || idx.Value > int.MaxValue)
            throw new VmFaultException($"XDROP index {idx.Value} out of Int32 range");
        int i = (int)idx.Value;
        if (i < 0 || i >= state.EvaluationStack.Count)
            throw new VmFaultException($"XDROP index {i} out of range");
        state.EvaluationStack.RemoveAt(state.EvaluationStack.Count - 1 - i);
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandlePick(ExecutionState state, Instruction inst)
    {
        var n = state.Pop();
        var idx = TryConcretizeIndex(state, n, lo: 0, hi: state.EvaluationStack.Count - 1);
        if (idx is null) { state.Terminate(TerminalStatus.Stopped, "PICK requires concrete count (no SMT model)"); return Single(state); }
        if (idx.Value < 0 || idx.Value > int.MaxValue)
            throw new VmFaultException($"PICK index {idx.Value} out of Int32 range");
        state.Push(state.Peek((int)idx.Value));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleRoll(ExecutionState state, Instruction inst)
    {
        var n = state.Pop();
        var idx = TryConcretizeIndex(state, n, lo: 0, hi: state.EvaluationStack.Count - 1);
        if (idx is null) { state.Terminate(TerminalStatus.Stopped, "ROLL requires concrete count (no SMT model)"); return Single(state); }
        if (idx.Value < 0 || idx.Value > int.MaxValue)
            throw new VmFaultException($"ROLL index {idx.Value} out of Int32 range");
        int i = (int)idx.Value;
        if (i < 0 || i >= state.EvaluationStack.Count)
            throw new VmFaultException($"ROLL index {i} out of range");
        var picked = state.EvaluationStack[^(i + 1)];
        state.EvaluationStack.RemoveAt(state.EvaluationStack.Count - 1 - i);
        state.EvaluationStack.Add(picked);
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> HandleReverseN(ExecutionState state, Instruction inst)
    {
        var n = state.Pop();
        var idx = TryConcretizeIndex(state, n, lo: 0, hi: state.EvaluationStack.Count);
        if (idx is null) { state.Terminate(TerminalStatus.Stopped, "REVERSEN requires concrete count (no SMT model)"); return Single(state); }
        if (idx.Value < 0 || idx.Value > int.MaxValue)
            throw new VmFaultException($"REVERSEN count {idx.Value} out of Int32 range");
        int count = (int)idx.Value;
        if (count > 1) ReverseTopN(state, count);
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    /// <summary>
    /// When a comparison/assert consumes an external-call return value, mark the originating
    /// ExternalCall as return_checked. Audit unchecked_return finding: this propagation is the
    /// signal that distinguishes a true unchecked-return from a properly handled one.
    /// </summary>
    private static void MarkExternalCallReturnChecked(ExecutionState state, SymbolicValue v)
    {
        foreach (var name in v.Expression.FreeSymbols().Concat(v.Taints))
        {
            if (!name.StartsWith("ext_ret_", System.StringComparison.Ordinal)) continue;
            if (!int.TryParse(name.AsSpan("ext_ret_".Length), out int off)) continue;
            foreach (var call in state.Telemetry.ExternalCalls)
                if (call.Offset == off) call.ReturnChecked = true;
        }
    }
}
