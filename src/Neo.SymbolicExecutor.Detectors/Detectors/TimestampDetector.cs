using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Surfaces use of <c>System.Runtime.GetTime</c>. INFO severity unless paired with the
/// randomness pattern (handled by <see cref="RandomnessDetector"/>).
/// </summary>
public sealed class TimestampDetector : BaseDetector
{
    public override string Name => "timestamp";
    public override Severity DefaultSeverity => Severity.Info;
    public override double DefaultConfidence => 0.9;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            if (state.Telemetry.TimeAccesses.Count == 0) continue;
            int off = state.Telemetry.TimeAccesses[0];
            yield return MakeFinding(
                title: "Runtime.GetTime read",
                description: $"Contract reads block timestamp at 0x{off:X4}. Block timestamps can drift up to "
                           + "~15 seconds and are loosely controlled by validators; do not use as a strict timer.",
                offset: off,
                severity: Severity.Info,
                state: state,
                tags: new[] { "timestamp" });
        }
    }
}
