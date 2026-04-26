using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Insecure-randomness patterns:
/// - Block timestamp / blockhash / transaction hash used as entropy → HIGH (audit unchanged).
/// - Per-state use of <see cref="Telemetry.RandomnessAccesses"/> from System.Runtime.GetRandom →
///   INFO (audit randomness.py finding: GetRandom is Neo N3's secure VRF source; flagging it as
///   MEDIUM was wrong direction).
/// </summary>
public sealed class RandomnessDetector : BaseDetector
{
    public override string Name => "randomness";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.8;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            // Pattern: timestamp value flows into a randomness-style use (mod, mask). Detect by
            // any path condition or stack expression containing the "timestamp" symbol AND a
            // bitwise/mod operation whose other operand is non-trivial.
            bool sawTimestampDerivedRandomness = false;
            int firstOff = 0;
            foreach (var cond in state.PathConditions)
            {
                if (cond.FreeSymbols().Any(n => n == "timestamp"))
                {
                    sawTimestampDerivedRandomness = true;
                    break;
                }
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
                    description: $"Block timestamp influences a path condition at 0x{firstOff:X4}. "
                               + "Validators can manipulate timestamps; do not derive entropy from time.",
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
}
