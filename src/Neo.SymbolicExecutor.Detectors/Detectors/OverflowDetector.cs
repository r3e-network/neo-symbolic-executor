using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects unchecked arithmetic where overflow / divide-by-zero is possible.
///
/// Audit precision lessons:
/// - The Python detector defaulted confidence to 0.8, but flagged any arithmetic with a symbolic
///   operand as "overflow possible" — a major false-positive vector for normal contract code.
///   We default to 0.6 here and rely on the engine emitting `OverflowPossible=true` only when
///   neither operand is bounded.
/// - INC, DEC, SHL, POW must be tracked (audit found Python missed these in `arithmetic_ops`).
///   Our engine adds them via UnaryArith/BinaryArith.
/// - DIV/MOD by symbolic divisor adds a divide-by-zero finding even when overflow is unlikely.
/// - The engine does NOT presently tag arithmetic results consumed by a downstream ASSERT/JMPIF
///   as <see cref="ArithmeticOp.Checked"/> (the flag is reserved for a future flow pass and is
///   currently only set when an operand is provably bounded). Because of that, the bare
///   <see cref="ArithmeticOp.OverflowPossible"/> flag fires on guarded/bounded code too. Review
///   fix (#15): when an SMT backend is available we additionally require the overflow predicate
///   (result &gt; NeoVmIntegerMax OR result &lt; NeoVmIntegerMin) to be satisfiable under the op's
///   own path conditions before reporting, which suppresses paths where a guard already bounds
///   the result. UNKNOWN still reports, preserving the over-approximation invariant.
/// </summary>
public sealed class OverflowDetector : BaseDetector
{
    public override string Name => "overflow";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.6;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            foreach (var op in state.Telemetry.ArithmeticOps)
            {
                if (op.Checked) continue;

                if (op.OverflowPossible && OverflowFeasible(context, op))
                {
                    yield return MakeFinding(
                        title: $"Unchecked {op.Operation} may overflow",
                        description: $"{op.Operation} at 0x{op.Offset:X4} consumes operand(s) with " +
                                     "unbounded symbolic range. Without an explicit ASSERT on the result, " +
                                     "an overflow can mint or consume excess value.",
                        offset: op.Offset,
                        severity: op.Operation is "DIV" or "MOD" ? Severity.Medium : Severity.High,
                        state: state,
                        tags: new[] { "arithmetic-overflow", op.Operation.ToLowerInvariant() });
                }

                if (op.DivisorMaybeZero)
                {
                    yield return MakeFinding(
                        title: $"{op.Operation} divisor may be zero",
                        description: $"{op.Operation} at 0x{op.Offset:X4} may execute with a zero divisor, " +
                                     "causing a non-catchable VM fault.",
                        offset: op.Offset,
                        severity: Severity.Medium,
                        state: state,
                        tags: new[] { "divide-by-zero" });
                }
            }
        }
    }

    /// <summary>
    /// Review fix (#15): gate the overflow report on an SMT feasibility query. We conjoin the op's
    /// path conditions with the actual overflow predicate (result outside the NeoVM 256-bit signed
    /// integer range) and only report when the conjunction is SAT or UNKNOWN. When no SMT backend
    /// is available, or the op carries no concrete result expression to constrain, we fall back to
    /// the previous over-approximating behavior (report).
    /// </summary>
    private static bool OverflowFeasible(AnalysisContext context, ArithmeticOp op)
    {
        var smt = context.SmtBackend;
        if (smt is null || !smt.IsAvailable) return true;
        if (op.Result is not { } result || result.Sort != Sort.Int) return true;

        var conditions = op.PathConditions.IsDefault
            ? new List<Expression>()
            : op.PathConditions.ToList();

        Expression overflowPredicate = Expr.BoolOr(
            Expr.Gt(result.Expression, Expr.Int(Expr.NeoVmIntegerMax)),
            Expr.Lt(result.Expression, Expr.Int(Expr.NeoVmIntegerMin)));

        // Sound by the ISmtBackend contract: UNSAT means the result is provably bounded under the
        // guards on this path, so suppress. SAT/UNKNOWN both preserve over-approximation.
        return smt.IsSatisfiable(conditions, overflowPredicate) != Smt.SmtOutcome.Unsat;
    }
}
