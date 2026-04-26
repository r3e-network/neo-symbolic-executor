using System;
using System.Collections.Generic;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> ConditionalBranch(ExecutionState state, Instruction inst, bool jumpOnTrue)
    {
        var cond = state.Pop();
        var truthy = cond.Truthy();
        if (truthy.HasValue)
        {
            // Concrete branch — no fork.
            bool take = truthy.Value == jumpOnTrue;
            int target = take ? inst.Target : inst.EndOffset;
            if (take && inst.Target < state.Pc) state.Telemetry.LoopsDetected.Add(inst.Target);
            MarkConditionalEnforcement(state, cond, taken: take ? jumpOnTrue : !jumpOnTrue);
            state.Pc = target;
            return Single(state);
        }

        // Symbolic — fork into both branches.
        var taken = state.Clone();
        var notTaken = state;

        // Audit C8/C9 fix: enforcement marker applies only to the branch that proceeds *because*
        // the witness/positive condition held. The else branch must NOT inherit enforcement.
        MarkConditionalEnforcement(taken, cond, taken: jumpOnTrue);
        MarkConditionalEnforcement(notTaken, cond, taken: !jumpOnTrue);

        taken.PathConditions = taken.PathConditions.Add(jumpOnTrue ? cond.Expression : Expr.Not(cond.Expression));
        notTaken.PathConditions = notTaken.PathConditions.Add(jumpOnTrue ? Expr.Not(cond.Expression) : cond.Expression);

        if (inst.Target < taken.Pc) taken.Telemetry.LoopsDetected.Add(inst.Target);
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
        Expression rel = inst.OpCode switch
        {
            NeoVm.OpCode.JMPEQ or NeoVm.OpCode.JMPEQ_L => Expr.Eq(a.Expression, b.Expression),
            NeoVm.OpCode.JMPNE or NeoVm.OpCode.JMPNE_L => Expr.Ne(a.Expression, b.Expression),
            NeoVm.OpCode.JMPGT or NeoVm.OpCode.JMPGT_L => Expr.Gt(a.Expression, b.Expression),
            NeoVm.OpCode.JMPGE or NeoVm.OpCode.JMPGE_L => Expr.Ge(a.Expression, b.Expression),
            NeoVm.OpCode.JMPLT or NeoVm.OpCode.JMPLT_L => Expr.Lt(a.Expression, b.Expression),
            NeoVm.OpCode.JMPLE or NeoVm.OpCode.JMPLE_L => Expr.Le(a.Expression, b.Expression),
            _ => throw new VmFaultException("not a comparison branch"),
        };
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
            if (take && inst.Target < state.Pc) state.Telemetry.LoopsDetected.Add(inst.Target);
            MarkConditionalEnforcement(state, cond, taken: take);
            state.Pc = target;
            return Single(state);
        }

        var taken = state.Clone();
        var notTaken = state;
        MarkConditionalEnforcement(taken, cond, taken: true);
        MarkConditionalEnforcement(notTaken, cond, taken: false);
        taken.PathConditions = taken.PathConditions.Add(cond.Expression);
        notTaken.PathConditions = notTaken.PathConditions.Add(Expr.Not(cond.Expression));
        if (inst.Target < taken.Pc) taken.Telemetry.LoopsDetected.Add(inst.Target);
        taken.Pc = inst.Target;
        notTaken.Pc = inst.EndOffset;
        return new[] { taken, notTaken };
    }
}
