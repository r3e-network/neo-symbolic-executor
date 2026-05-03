using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Marker for a detector. Stateless; gets called per analysis with a list of final states.
/// </summary>
public interface IDetector
{
    string Name { get; }
    Severity DefaultSeverity { get; }
    double DefaultConfidence { get; }

    IEnumerable<Finding> Analyze(AnalysisContext context);
}

public sealed class AnalysisContext
{
    public required IReadOnlyList<ExecutionState> States { get; init; }
    public Nef.ContractManifest? Manifest { get; init; }
    public Nef.NefFile? Nef { get; init; }
    public SourceHints? SourceHints { get; init; }
    public NativeContractRegistry Natives { get; init; } = NativeContractRegistry.Default;
    public Smt.ISmtBackend? SmtBackend { get; init; }
    public bool DropUnsatFindings { get; init; }
}

public abstract class BaseDetector : IDetector
{
    public abstract string Name { get; }
    public virtual Severity DefaultSeverity => Severity.Medium;
    public virtual double DefaultConfidence => 0.8;

    public abstract IEnumerable<Finding> Analyze(AnalysisContext context);

    /// <summary>
    /// Construct a finding with calibrated confidence and a deterministic rationale.
    ///
    /// Calibration formula (matches the Python `BaseDetector.calibrated_confidence`):
    ///   conf = base * (1 - clamp(uncertainty / 8.0, 0, 0.4))
    /// Truncated states (analysis budget hit) get an additional 0.5x penalty per audit C7.
    /// </summary>
    protected Finding MakeFinding(
        string title,
        string description,
        int offset,
        Severity severity,
        ExecutionState? state,
        IEnumerable<string>? tags = null,
        double? confidenceOverride = null)
    {
        double baseConf = confidenceOverride ?? DefaultConfidence;
        int uncertainty = state is null ? 0 : PathUncertaintyScore(state);
        double penalty = System.Math.Min(uncertainty / 8.0, 0.4);
        double conf = baseConf * (1.0 - penalty);

        // Reasons surface in JSON/Markdown reports, so format with InvariantCulture for
        // byte-identical CI output across machine locales (Turkish would emit "0,80").
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        string reason;
        if (state is null)
        {
            reason = $"static rule (base {baseConf.ToString("0.00", inv)})";
        }
        else if (state.Telemetry.Truncated)
        {
            conf *= 0.5;
            reason = $"path uncertainty={uncertainty}, base {baseConf.ToString("0.00", inv)}, halved due to truncated exploration";
        }
        else
        {
            reason = $"path uncertainty={uncertainty}, base {baseConf.ToString("0.00", inv)} -> {conf.ToString("0.00", inv)}";
        }

        return new Finding(
            Detector: Name,
            Severity: severity,
            Title: title,
            Description: description,
            Offset: offset,
            Confidence: System.Math.Round(System.Math.Clamp(conf, 0, 1), 3),
            ConfidenceReason: reason,
            Tags: (tags ?? System.Linq.Enumerable.Empty<string>()).ToImmutableHashSet(),
            PathConditions: state?.PathConditions.ToImmutableArray() ?? default);
    }

    /// <summary>
    /// Score the uncertainty of a path: number of symbolic constraints + complexity of constraint
    /// expressions. Higher score -> more symbolic, less certain. Bounded at 32.
    /// </summary>
    public static int PathUncertaintyScore(ExecutionState state)
    {
        int score = 0;
        foreach (var c in state.PathConditions)
        {
            score += c.Complexity;
            if (score > 32) return 32;
        }
        return score;
    }
}
