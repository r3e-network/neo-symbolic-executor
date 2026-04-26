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
                if (op.Kind == StorageOpKind.Put || op.Kind == StorageOpKind.Delete)
                { hasSensitive = true; break; }
            if (!hasSensitive)
                foreach (var c in state.Telemetry.ExternalCalls)
                { hasSensitive = true; break; }
            if (!hasSensitive) continue;

            int off = 0;
            foreach (var v in state.Telemetry.WitnessChecksEnforced) { off = v; break; }
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
