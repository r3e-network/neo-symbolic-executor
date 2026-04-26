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
/// - When the result is consumed by an ASSERT/JMPIF or stored back via STLOC and immediately
///   asserted, mark `Checked=true` and skip — implemented via expression flow tagging.
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

                if (op.OverflowPossible)
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
}
