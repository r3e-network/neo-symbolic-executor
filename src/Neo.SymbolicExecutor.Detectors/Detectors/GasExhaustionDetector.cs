using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Paths that accumulate disproportionate gas cost. Threshold is conservative; this is a
/// triage signal more than a vulnerability per se.
/// </summary>
public sealed class GasExhaustionDetector : BaseDetector
{
    public override string Name => "gas_exhaustion";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.6;

    public const long Threshold = 5_000_000;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            if (state.Telemetry.GasCost < Threshold) continue;
            yield return MakeFinding(
                title: "Path accumulates high gas cost",
                description: $"Estimated gas cost on this path is {state.Telemetry.GasCost} (threshold {Threshold}). "
                           + "Verify the path is bounded by user-controlled inputs.",
                offset: 0,
                severity: Severity.Medium,
                state: state,
                tags: new[] { "gas" });
        }
    }
}
