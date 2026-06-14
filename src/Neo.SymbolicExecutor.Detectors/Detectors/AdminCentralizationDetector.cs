using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Surfaces single-witness centralization. Per audit detector audit #2 the prior MEDIUM severity
/// was over-aggressive (multisig contracts with internal verifyAdmin helpers fire spuriously);
/// downgrade to LOW unless we also see a sensitive operation guarded by exactly that one witness.
/// </summary>
public sealed class AdminCentralizationDetector : BaseDetector
{
    public override string Name => "admin_centralization";
    public override Severity DefaultSeverity => Severity.Low;
    public override double DefaultConfidence => 0.6;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            if (state.Telemetry.WitnessChecksEnforced.Count != 1) continue;
            // Require at least one sensitive operation in this state.
            bool hasSensitive = false;
            foreach (var op in state.Telemetry.StorageOps)
                if (ProtocolRiskHelpers.IsStateWrite(op))
                { hasSensitive = true; break; }
            if (!hasSensitive)
                foreach (var c in state.Telemetry.ExternalCalls)
                {
                    if (c.ModeledSelfCall) continue;
                    hasSensitive = true; break;
                }
            if (!hasSensitive) continue;

            // Audit fix: WitnessChecksEnforced is a HashSet — `foreach { break; }` reads an
            // unspecified element. Same telemetry can produce different finding offsets
            // (and therefore different DedupeKeys) across runs. Pick the deterministic minimum.
            int off = int.MaxValue;
            foreach (var v in state.Telemetry.WitnessChecksEnforced) if (v < off) off = v;
            if (off == int.MaxValue) off = 0;
            yield return MakeFinding(
                title: "Privileged operation gated by a single witness",
                description: $"State performs privileged operations gated by one CheckWitness at 0x{off:X4}. "
                           + "Consider multisig or threshold authorization to reduce single-key risk.",
                offset: off,
                severity: Severity.Low,
                state: state,
                tags: new[] { "centralization" });
        }
    }
}
