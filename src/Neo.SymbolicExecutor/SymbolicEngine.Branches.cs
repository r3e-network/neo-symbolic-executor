using System;
using System.Collections.Generic;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> ConditionalBranch(ExecutionState state, Instruction inst, bool jumpOnTrue)
    {
        var cond = state.Pop();
        // Audit C# #3 fix: a JMPIF/JMPIFNOT consuming an external-call return value is a valid
        // way to "check the return". Tag the originating call as ReturnChecked so
        // UncheckedReturnDetector doesn't false-positive.
        MarkExternalCallReturnChecked(state, cond);
        var truthy = cond.Truthy();
        if (truthy.HasValue)
        {
            // Concrete branch — no fork.
            bool take = truthy.Value == jumpOnTrue;
            int target = take ? inst.Target : inst.EndOffset;
            if (take && inst.Target >= 0 && inst.Target < state.Pc) state.Telemetry.LoopsDetected.Add(inst.Target);
            MarkConditionalEnforcement(state, cond, taken: take ? jumpOnTrue : !jumpOnTrue);
            state.Pc = target;
            return Single(state);
        }

        // Symbolic — consult the SMT backend (if any) to prune unreachable branches.
        var takeExpr = jumpOnTrue ? cond.Expression : Expr.Not(cond.Expression);
        var notTakeExpr = jumpOnTrue ? Expr.Not(cond.Expression) : cond.Expression;
        var (takeSat, notTakeSat) = ConsultSmt(state, takeExpr);
        if (takeSat == Smt.SmtOutcome.Unsat && notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Terminate(TerminalStatus.Stopped, "both branches unsatisfiable");
            return Single(state);
        }
        if (takeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: !jumpOnTrue);
            state.PathConditions = state.PathConditions.Add(notTakeExpr);
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        if (notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: jumpOnTrue);
            state.PathConditions = state.PathConditions.Add(takeExpr);
            // Audit fix (iter-2 wakeup-17 pipeline-consistency): only record valid back-edges.
            // A JMP whose sbyte delta makes target negative will fault on the next step, but
            // the Add(-N) before that pollutes telemetry with negative offsets that downstream
            // detectors can surface as Findings with negative offset.
            if (inst.Target >= 0 && inst.Target < state.Pc) state.Telemetry.LoopsDetected.Add(inst.Target);
            state.Pc = inst.Target;
            return Single(state);
        }
        if (takeSat == Smt.SmtOutcome.Unknown || notTakeSat == Smt.SmtOutcome.Unknown)
            state.Telemetry.SmtUnknownOffsets.Add(inst.Offset);

        // Symbolic — fork into both branches.
        var taken = state.Clone();
        var notTaken = state;

        // Audit C8/C9 fix: enforcement marker applies only to the branch that proceeds *because*
        // the witness/positive condition held. The else branch must NOT inherit enforcement.
        MarkConditionalEnforcement(taken, cond, taken: jumpOnTrue);
        MarkConditionalEnforcement(notTaken, cond, taken: !jumpOnTrue);

        taken.PathConditions = taken.PathConditions.Add(jumpOnTrue ? cond.Expression : Expr.Not(cond.Expression));
        notTaken.PathConditions = notTaken.PathConditions.Add(jumpOnTrue ? Expr.Not(cond.Expression) : cond.Expression);

        if (inst.Target >= 0 && inst.Target < taken.Pc) taken.Telemetry.LoopsDetected.Add(inst.Target);
        taken.Pc = inst.Target;
        notTaken.Pc = inst.EndOffset;

        return new[] { taken, notTaken };
    }

    /// <summary>
    /// Audit C8/C9: only mark a witness check as enforced on the branch that proceeds because
    /// the witness condition was true. The "auth failed" branch must remain unenforced.
    /// </summary>
    private static void MarkConditionalEnforcement(ExecutionState state, SymbolicValue cond, bool taken)
    {
        if (!taken) return;
        // Walk the cond expression; any Symbol whose name starts with "witness_ok_<offset>" was
        // produced by CheckWitness at that offset.
        foreach (var name in cond.Expression.FreeSymbols())
        {
            if (name.StartsWith("witness_ok_", StringComparison.Ordinal)
                && int.TryParse(name.AsSpan("witness_ok_".Length), out int off))
            {
                state.Telemetry.WitnessChecksEnforced.Add(off);
            }
            else if (name.StartsWith("caller_hash_", StringComparison.Ordinal)
                     && int.TryParse(name.AsSpan("caller_hash_".Length), out int co))
            {
                state.Telemetry.CallerHashChecks.Add(co);
            }
        }
    }

    private IEnumerable<ExecutionState> ComparisonBranch(ExecutionState state, Instruction inst)
    {
        var b = state.Pop();
        var a = state.Pop();
        // Audit C# #3 fix: comparison branches consume both operands as a check; tag any
        // external-call return values that flow in.
        MarkExternalCallReturnChecked(state, a);
        MarkExternalCallReturnChecked(state, b);
        // Audit fix (iter-2 wakeup-10 differential): NeoVM's JMP* numeric branches use
        // `Pop().GetInteger()` for both operands — they coerce Bool→0/1, Bytes→signed-LE int
        // BEFORE comparing. This is DIFFERENT from EQUAL/NOTEQUAL which use type-aware
        // StackItem.Equals (Boolean.Equals(Integer)=false). Our prior code routed JMPEQ/JMPNE
        // through Expr.Eq/Ne (the type-aware path), which made `JMPEQ true 1` not jump even
        // though NeoVM jumps. Use Expr.ConcreteInt to fold concretely; Lt/Le/Gt/Ge already
        // canonicalize via ConcreteInt so they work for JMPGT/JMPGE/JMPLT/JMPLE unchanged.
        Expression rel;
        if (inst.OpCode is NeoVm.OpCode.JMPEQ or NeoVm.OpCode.JMPEQ_L
                        or NeoVm.OpCode.JMPNE or NeoVm.OpCode.JMPNE_L)
        {
            // Numeric equality: both sides via GetInteger.
            if (Expr.ConcreteInt(a.Expression) is { } na && Expr.ConcreteInt(b.Expression) is { } nb)
                rel = inst.OpCode is NeoVm.OpCode.JMPEQ or NeoVm.OpCode.JMPEQ_L
                    ? Expr.Bool(na == nb)
                    : Expr.Bool(na != nb);
            else
                rel = new BinaryExpr(Sort.Bool,
                    inst.OpCode is NeoVm.OpCode.JMPEQ or NeoVm.OpCode.JMPEQ_L ? "num==" : "num!=",
                    a.Expression, b.Expression);
        }
        else
        {
            rel = inst.OpCode switch
            {
                NeoVm.OpCode.JMPGT or NeoVm.OpCode.JMPGT_L => Expr.Gt(a.Expression, b.Expression),
                NeoVm.OpCode.JMPGE or NeoVm.OpCode.JMPGE_L => Expr.Ge(a.Expression, b.Expression),
                NeoVm.OpCode.JMPLT or NeoVm.OpCode.JMPLT_L => Expr.Lt(a.Expression, b.Expression),
                NeoVm.OpCode.JMPLE or NeoVm.OpCode.JMPLE_L => Expr.Le(a.Expression, b.Expression),
                _ => throw new VmFaultException("not a comparison branch"),
            };
        }
        var relValue = SymbolicValue.Of(rel, a.Taints.Union(b.Taints));
        return ConditionalBranchOnExpr(state, inst, relValue);
    }

    private IEnumerable<ExecutionState> ConditionalBranchOnExpr(ExecutionState state, Instruction inst, SymbolicValue cond)
    {
        var truthy = cond.Truthy();
        if (truthy.HasValue)
        {
            bool take = truthy.Value;
            int target = take ? inst.Target : inst.EndOffset;
            if (take && inst.Target >= 0 && inst.Target < state.Pc) state.Telemetry.LoopsDetected.Add(inst.Target);
            MarkConditionalEnforcement(state, cond, taken: take);
            state.Pc = target;
            return Single(state);
        }

        var (takeSat, notTakeSat) = ConsultSmt(state, cond.Expression);
        if (takeSat == Smt.SmtOutcome.Unsat && notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Terminate(TerminalStatus.Stopped, "both branches unsatisfiable");
            return Single(state);
        }
        if (takeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: false);
            state.PathConditions = state.PathConditions.Add(Expr.Not(cond.Expression));
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        if (notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: true);
            state.PathConditions = state.PathConditions.Add(cond.Expression);
            // Audit fix (iter-2 wakeup-17 pipeline-consistency): only record valid back-edges.
            // A JMP whose sbyte delta makes target negative will fault on the next step, but
            // the Add(-N) before that pollutes telemetry with negative offsets that downstream
            // detectors can surface as Findings with negative offset.
            if (inst.Target >= 0 && inst.Target < state.Pc) state.Telemetry.LoopsDetected.Add(inst.Target);
            state.Pc = inst.Target;
            return Single(state);
        }
        if (takeSat == Smt.SmtOutcome.Unknown || notTakeSat == Smt.SmtOutcome.Unknown)
            state.Telemetry.SmtUnknownOffsets.Add(inst.Offset);

        var taken = state.Clone();
        var notTaken = state;
        MarkConditionalEnforcement(taken, cond, taken: true);
        MarkConditionalEnforcement(notTaken, cond, taken: false);
        taken.PathConditions = taken.PathConditions.Add(cond.Expression);
        notTaken.PathConditions = notTaken.PathConditions.Add(Expr.Not(cond.Expression));
        if (inst.Target >= 0 && inst.Target < taken.Pc) taken.Telemetry.LoopsDetected.Add(inst.Target);
        taken.Pc = inst.Target;
        notTaken.Pc = inst.EndOffset;
        return new[] { taken, notTaken };
    }

    /// <summary>
    /// Ask the SMT backend whether each branch is satisfiable under accumulated path conditions.
    /// Returns (Unknown, Unknown) when no backend is configured. Soundness: UNKNOWN never causes
    /// the engine to drop a fork — only UNSAT does.
    /// </summary>
    private (Smt.SmtOutcome Take, Smt.SmtOutcome NotTake) ConsultSmt(ExecutionState state, Expression branchCond)
    {
        var backend = _options.SmtBackend;
        if (backend is null || !backend.IsAvailable)
            return (Smt.SmtOutcome.Unknown, Smt.SmtOutcome.Unknown);
        var take = backend.IsSatisfiable(state.PathConditions, branchCond);
        var notTake = backend.IsSatisfiable(state.PathConditions, Expr.Not(branchCond));
        return (take, notTake);
    }
}
