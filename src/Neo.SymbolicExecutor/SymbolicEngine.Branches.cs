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
            MarkConditionalEnforcement(state, cond, taken: take ? jumpOnTrue : !jumpOnTrue, inst.Offset);
            state.Pc = target;
            return Single(state);
        }

        // Symbolic — consult the SMT backend (if any) to prune unreachable branches.
        var condTruthy = Expr.ToBool(cond.Expression);
        var takeExpr = jumpOnTrue ? condTruthy : Expr.Not(condTruthy);
        var notTakeExpr = jumpOnTrue ? Expr.Not(condTruthy) : condTruthy;
        var (takeSat, notTakeSat) = ConsultSmt(state, takeExpr);
        if (takeSat == Smt.SmtOutcome.Unsat && notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Terminate(TerminalStatus.Stopped, "both branches unsatisfiable");
            return Single(state);
        }
        if (takeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: !jumpOnTrue, inst.Offset);
            state.PathConditions = state.PathConditions.Add(notTakeExpr);
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        if (notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: jumpOnTrue, inst.Offset);
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
        MarkConditionalEnforcement(taken, cond, taken: jumpOnTrue, inst.Offset);
        MarkConditionalEnforcement(notTaken, cond, taken: !jumpOnTrue, inst.Offset);

        taken.PathConditions = taken.PathConditions.Add(takeExpr);
        notTaken.PathConditions = notTaken.PathConditions.Add(notTakeExpr);

        if (inst.Target >= 0 && inst.Target < taken.Pc) taken.Telemetry.LoopsDetected.Add(inst.Target);
        taken.Pc = inst.Target;
        notTaken.Pc = inst.EndOffset;

        return new[] { taken, notTaken };
    }

    /// <summary>
    /// Audit C8/C9: only mark a witness check as enforced on the branch that proceeds because
    /// the witness condition was true. The "auth failed" branch must remain unenforced.
    /// </summary>
    private static void MarkConditionalEnforcement(
        ExecutionState state,
        SymbolicValue cond,
        bool taken,
        int enforcementOffset)
    {
        var guard = taken ? cond.Expression : Expr.Not(cond.Expression);
        // Only mark auth as enforced when the continuing guard requires the positive auth result.
        // A guard such as `not(witness_ok_10)` or `sig_ok_20 == 0` is explicitly the opposite.
        foreach (var name in PositiveAuthSymbols(guard))
        {
            if (TryAuthSymbolOffset(name, "witness_ok_", out int off))
            {
                state.Telemetry.WitnessCheckResultsEnforced.Add(name);
                state.Telemetry.WitnessChecksEnforced.Add(off);
            }
            else if (TryAuthSymbolOffset(name, "sig_ok_", out int so))
            {
                state.Telemetry.SignatureCheckResultsEnforced.Add(name);
                state.Telemetry.SignatureChecksEnforced.Add(so);
            }
            else if (TryAuthSymbolOffset(name, "multisig_ok_", out int mo))
            {
                state.Telemetry.SignatureCheckResultsEnforced.Add(name);
                state.Telemetry.SignatureChecksEnforced.Add(mo);
            }
        }

        foreach (var principal in PositiveCallerHashPrincipals(guard))
        {
            state.Telemetry.CallerHashChecks.Add(enforcementOffset);
            state.Telemetry.CallerHashCheckOps.Add(new CallerHashCheckOp(
                enforcementOffset,
                SymbolicValue.Of(principal)));
        }
    }

    private static IEnumerable<string> PositiveAuthSymbols(Expression guard)
    {
        switch (guard)
        {
            case Symbol symbol when IsAuthSymbol(symbol.Name):
                yield return symbol.Name;
                yield break;
            case UnaryExpr { Op: "tobool", Operand: Symbol symbol } when IsAuthSymbol(symbol.Name):
                yield return symbol.Name;
                yield break;
            case BinaryExpr { Op: "and" } and:
                foreach (var name in PositiveAuthSymbols(and.Left))
                    yield return name;
                foreach (var name in PositiveAuthSymbols(and.Right))
                    yield return name;
                yield break;
            case BinaryExpr { Op: "==" or "num==" } equality:
                if (AuthEquals(equality.Left, equality.Right, expected: true) is { } equalName)
                    yield return equalName;
                yield break;
            case BinaryExpr { Op: "!=" or "num!=" } inequality:
                if (AuthEquals(inequality.Left, inequality.Right, expected: false) is { } notEqualName)
                    yield return notEqualName;
                yield break;
            case UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "==" or "num==" } equality
            }:
                if (AuthEquals(equality.Left, equality.Right, expected: false) is { } negatedEqualName)
                    yield return negatedEqualName;
                yield break;
            case UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "!=" or "num!=" } inequality
            }:
                if (AuthEquals(inequality.Left, inequality.Right, expected: true) is { } negatedNotEqualName)
                    yield return negatedNotEqualName;
                yield break;
        }
    }

    private static string? AuthEquals(Expression left, Expression right, bool expected)
    {
        if (left is Symbol leftSymbol && IsAuthSymbol(leftSymbol.Name) && IsBoolLike(right, expected))
            return leftSymbol.Name;
        if (right is Symbol rightSymbol && IsAuthSymbol(rightSymbol.Name) && IsBoolLike(left, expected))
            return rightSymbol.Name;
        return null;
    }

    private static IEnumerable<Expression> PositiveCallerHashPrincipals(Expression guard)
    {
        switch (guard)
        {
            case BinaryExpr { Op: "and" } binary:
                foreach (var leftPrincipal in PositiveCallerHashPrincipals(binary.Left))
                    yield return leftPrincipal;
                foreach (var rightPrincipal in PositiveCallerHashPrincipals(binary.Right))
                    yield return rightPrincipal;
                yield break;
            case BinaryExpr { Op: "==" or "num==" } equality:
                if (CallerHashBindingPrincipal(equality.Left, equality.Right) is { } equalityPrincipal)
                    yield return equalityPrincipal;
                yield break;
            case UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "!=" or "num!=" } inequality
            }:
                if (CallerHashBindingPrincipal(inequality.Left, inequality.Right) is { } negatedPrincipal)
                    yield return negatedPrincipal;
                yield break;
        }
    }

    private static Expression? CallerHashBindingPrincipal(Expression left, Expression right)
    {
        if (left is Symbol leftSymbol
            && IsCallingScriptHashSymbol(leftSymbol.Name)
            && IsHash160LikeRuntimePrincipal(right))
            return right;
        if (right is Symbol rightSymbol
            && IsCallingScriptHashSymbol(rightSymbol.Name)
            && IsHash160LikeRuntimePrincipal(left))
            return left;
        return null;
    }

    private static bool IsCallingScriptHashSymbol(string name) =>
        string.Equals(name, "calling_script_hash", StringComparison.Ordinal)
        || name.StartsWith("caller_hash_", StringComparison.Ordinal);

    private static bool IsHash160LikeRuntimePrincipal(Expression expression) =>
        expression is BytesConst { Value.Length: 20 }
        || expression is Symbol { Sort: Sort.Bytes };

    private static bool IsBoolLike(Expression expression, bool expected) =>
        expression switch
        {
            BoolConst b => b.Value == expected,
            IntConst i => expected ? i.Value == 1 : i.Value.IsZero,
            BytesConst bytes => expected
                ? Expr.BytesToInteger(bytes.Value) == 1
                : Expr.BytesToInteger(bytes.Value).IsZero,
            _ => false,
        };

    private static bool IsAuthSymbol(string name) =>
        name.StartsWith("witness_ok_", StringComparison.Ordinal)
        || name.StartsWith("sig_ok_", StringComparison.Ordinal)
        || name.StartsWith("multisig_ok_", StringComparison.Ordinal);

    private static bool TryAuthSymbolOffset(string name, string prefix, out int offset)
    {
        offset = default;
        if (!name.StartsWith(prefix, StringComparison.Ordinal))
            return false;

        ReadOnlySpan<char> suffix = name.AsSpan(prefix.Length);
        int occurrenceSeparator = suffix.IndexOf('_');
        ReadOnlySpan<char> offsetSpan = occurrenceSeparator >= 0
            ? suffix[..occurrenceSeparator]
            : suffix;
        return int.TryParse(offsetSpan, out offset);
    }

    private IEnumerable<ExecutionState> ComparisonBranch(ExecutionState state, Instruction inst)
    {
        var b = state.Pop();
        var a = state.Pop();
        // Audit C# #3 fix: comparison branches consume both operands as a check; tag any
        // external-call return values that flow in.
        MarkExternalCallReturnChecked(state, a);
        MarkExternalCallReturnChecked(state, b);
        EnforceNeoVmIntegerInput(state, inst, inst.OpCode.ToString(), a, "left operand");
        EnforceNeoVmIntegerInput(state, inst, inst.OpCode.ToString(), b, "right operand");
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
            MarkConditionalEnforcement(state, cond, taken: take, inst.Offset);
            state.Pc = target;
            return Single(state);
        }

        var condTruthy = Expr.ToBool(cond.Expression);
        var (takeSat, notTakeSat) = ConsultSmt(state, condTruthy);
        if (takeSat == Smt.SmtOutcome.Unsat && notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Terminate(TerminalStatus.Stopped, "both branches unsatisfiable");
            return Single(state);
        }
        if (takeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: false, inst.Offset);
            state.PathConditions = state.PathConditions.Add(Expr.Not(condTruthy));
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        if (notTakeSat == Smt.SmtOutcome.Unsat)
        {
            state.Telemetry.SmtPrunedBranches++;
            MarkConditionalEnforcement(state, cond, taken: true, inst.Offset);
            state.PathConditions = state.PathConditions.Add(condTruthy);
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
        MarkConditionalEnforcement(taken, cond, taken: true, inst.Offset);
        MarkConditionalEnforcement(notTaken, cond, taken: false, inst.Offset);
        taken.PathConditions = taken.PathConditions.Add(condTruthy);
        notTaken.PathConditions = notTaken.PathConditions.Add(Expr.Not(condTruthy));
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
        var condition = Expr.ToBool(branchCond);
        var take = backend.IsSatisfiable(state.PathConditions, condition);
        var notTake = backend.IsSatisfiable(state.PathConditions, Expr.Not(condition));
        return (take, notTake);
    }
}
