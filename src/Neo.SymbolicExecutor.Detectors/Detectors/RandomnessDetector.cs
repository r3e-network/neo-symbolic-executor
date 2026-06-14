using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Insecure-randomness patterns:
/// - Block timestamp consumed by a modulo / bitwise-mask / shift expression on a branch path →
///   HIGH weak-randomness. That arithmetic shape is the signature of "derive entropy from time"
///   (e.g. <c>timestamp % n</c> to pick a winner); a validator who nudges the block time controls
///   the outcome. Review fix (#17): only this arithmetic-consuming shape earns HIGH.
/// - A bare timestamp in a branch condition WITHOUT such arithmetic is the benign deadline /
///   time-lock pattern (<c>timestamp &gt; deadline</c>), so it is downgraded to Low/Info rather
///   than reported as HIGH weak-randomness.
/// - Per-state use of <see cref="Telemetry.RandomnessAccesses"/> from System.Runtime.GetRandom →
///   INFO (audit randomness.py finding: GetRandom is Neo N3's secure VRF source; flagging it as
///   MEDIUM was wrong direction).
/// </summary>
public sealed class RandomnessDetector : BaseDetector
{
    public override string Name => "randomness";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.8;

    // Review fix (#17): the binary ops whose presence around a timestamp operand indicates the
    // value is being folded into entropy rather than compared against a deadline. Covers both the
    // engine's symbol forms (%, &, <<, >>) and the spelled-out aliases (mod/and/shl/shr) so the
    // heuristic is robust to alternate expression encodings.
    private static readonly string[] EntropyOps = { "%", "mod", "&", "and", "<<", "shl", ">>", "shr" };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            // Pattern: timestamp value flows into a randomness-style use (mod, mask, shift). Detect
            // by any path condition containing the "timestamp" symbol as a direct operand of one of
            // the entropy-shaped binary ops; a bare timestamp branch (deadline/time-lock) does not
            // match.
            bool sawTimestampInBranch = false;
            bool sawTimestampDerivedRandomness = false;
            int firstOff = 0;
            foreach (var cond in state.PathConditions)
            {
                if (cond.FreeSymbols().Any(n => n == "timestamp"))
                    sawTimestampInBranch = true;
                if (TimestampFeedsEntropyOp(cond))
                {
                    sawTimestampDerivedRandomness = true;
                    break;
                }
            }
            if (!sawTimestampDerivedRandomness && sawTimestampInBranch)
            {
                // Bare timestamp in a branch (deadline / time-lock), not entropy synthesis. Surface
                // as Info advisory rather than a HIGH weak-randomness assertion.
                firstOff = state.Telemetry.TimeAccesses.Count > 0 ? state.Telemetry.TimeAccesses[0] : 0;
                yield return MakeFinding(
                    title: "Block timestamp used in a branch condition",
                    description: $"Block timestamp influences a branch at 0x{firstOff:X4} but is not folded into a "
                               + "modulo/mask/shift expression. This is the typical deadline or time-lock pattern, "
                               + "not entropy synthesis. Surfaced for review; validators can still nudge block time "
                               + "by a few seconds.",
                    offset: firstOff,
                    severity: Severity.Info,
                    state: state,
                    tags: new[] { "timestamp-branch" });
                continue;
            }
            if (!sawTimestampDerivedRandomness && state.Telemetry.TimeAccesses.Count > 0
                && state.Telemetry.RandomnessAccesses.Count == 0)
            {
                // Soft signal: time was read but not GetRandom — suspicious only if entropy is
                // synthesized from time. We surface as Low.
                firstOff = state.Telemetry.TimeAccesses[0];
                yield return MakeFinding(
                    title: "Timestamp consulted without GetRandom",
                    description: "GetTime is read but Runtime.GetRandom is not used. If timestamp is used as "
                               + "entropy, miners/proposers can influence outcomes.",
                    offset: firstOff,
                    severity: Severity.Low,
                    state: state,
                    tags: new[] { "timestamp-entropy" });
                continue;
            }

            if (sawTimestampDerivedRandomness)
            {
                firstOff = state.Telemetry.TimeAccesses.Count > 0 ? state.Telemetry.TimeAccesses[0] : 0;
                yield return MakeFinding(
                    title: "Timestamp-derived randomness in branch condition",
                    description: $"Block timestamp is folded into a modulo/mask/shift expression that influences a "
                               + $"path condition at 0x{firstOff:X4}. Validators can manipulate timestamps; do not "
                               + "derive entropy from time.",
                    offset: firstOff,
                    severity: Severity.High,
                    state: state,
                    tags: new[] { "weak-randomness" });
            }
            else if (state.Telemetry.RandomnessAccesses.Count > 0)
            {
                int off = state.Telemetry.RandomnessAccesses[0];
                yield return MakeFinding(
                    title: "Runtime.GetRandom used",
                    description: $"Contract reads Runtime.GetRandom at 0x{off:X4}. This is Neo N3's secure VRF "
                               + "source and is appropriate for randomness; surfaced for review only.",
                    offset: off,
                    severity: Severity.Info,
                    state: state,
                    tags: new[] { "vrf" });
            }
        }
    }

    /// <summary>
    /// Review fix (#17): true iff <paramref name="expr"/> contains a binary entropy-shaped op
    /// (modulo / bitwise-AND / shift) whose subtree references the <c>timestamp</c> symbol — the
    /// signature of deriving randomness from block time. A bare <c>timestamp &gt; deadline</c>
    /// comparison does not match because its op is not in <see cref="EntropyOps"/>.
    /// </summary>
    private static bool TimestampFeedsEntropyOp(Expression expr)
    {
        switch (expr)
        {
            case BinaryExpr b:
                if (System.Array.IndexOf(EntropyOps, b.Op) >= 0
                    && (ExpressionReferencesTimestamp(b.Left) || ExpressionReferencesTimestamp(b.Right)))
                    return true;
                return TimestampFeedsEntropyOp(b.Left) || TimestampFeedsEntropyOp(b.Right);
            case UnaryExpr u:
                return TimestampFeedsEntropyOp(u.Operand);
            case TernaryExpr t:
                return TimestampFeedsEntropyOp(t.A) || TimestampFeedsEntropyOp(t.B) || TimestampFeedsEntropyOp(t.C);
            default:
                return false;
        }
    }

    private static bool ExpressionReferencesTimestamp(Expression expr) =>
        expr.FreeSymbols().Any(n => n == "timestamp");
}
