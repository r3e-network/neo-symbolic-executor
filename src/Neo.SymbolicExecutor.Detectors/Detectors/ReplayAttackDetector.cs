using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// New detector per audit coverage gap #3: replay attacks via missing nonce/sequence handling.
///
/// Heuristic: if a contract performs sensitive operations gated by a signature/witness check but
/// reads NO storage value with a nonce-shaped key (matching common naming patterns: "nonce",
/// "seq", "counter", "used_"), surface a finding.
///
/// This is admittedly a name-based heuristic — false positives expected on contracts that use
/// non-standard naming. SMT-backed taint analysis can refine this in a future iteration.
/// </summary>
public sealed class ReplayAttackDetector : BaseDetector
{
    public override string Name => "replay_attack";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.6;

    private static readonly string[] NonceHints =
        { "nonce", "seq", "sequence", "counter", "used_", "executed_", "nonces" };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            // Auth via signature?
            if (state.Telemetry.SignatureChecks.Count == 0
                && state.Telemetry.CallerHashChecks.Count == 0) continue;

            bool hasSensitive = state.Telemetry.StorageOps.Any(o =>
                o.Kind == StorageOpKind.Put || o.Kind == StorageOpKind.Delete);
            if (!hasSensitive) continue;

            bool nonceLooking = state.Telemetry.StorageOps.Any(o =>
                o.Key.AsConcreteBytes() is byte[] kb
                && NonceHints.Any(h => System.Text.Encoding.UTF8.GetString(kb).Contains(h, System.StringComparison.OrdinalIgnoreCase)));
            if (nonceLooking) continue;

            int firstSensitive = state.Telemetry.StorageOps
                .Where(o => o.Kind == StorageOpKind.Put || o.Kind == StorageOpKind.Delete)
                .Min(o => o.Offset);

            yield return MakeFinding(
                title: "Signature-gated state change without an apparent nonce",
                description: $"Sensitive operation at 0x{firstSensitive:X4} is gated by signature/witness, but no "
                           + "nonce-shaped storage key (nonce/seq/counter/used_) is read on this path. Off-chain "
                           + "signed messages may be replayable.",
                offset: firstSensitive,
                severity: Severity.Medium,
                state: state,
                tags: new[] { "replay" });
        }
    }
}
