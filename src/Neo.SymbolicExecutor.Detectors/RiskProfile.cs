using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Aggregated risk view across an entire analysis. Mirrors the Python `risk_profile` payload:
/// per-detector worst severity, deterministic weighted score, confidence-weighted score,
/// and per-detector mean confidence. Surfaced in JSON + Markdown reports.
/// </summary>
public sealed record RiskProfile(
    Severity OverallMaxSeverity,
    int TotalFindings,
    IReadOnlyDictionary<Severity, int> SeverityCounts,
    IReadOnlyDictionary<string, Severity> DetectorMaxSeverity,
    IReadOnlyDictionary<string, double> DetectorAverageConfidence,
    int WeightedScore,
    int ConfidenceWeightedScore)
{
    public static RiskProfile FromFindings(IEnumerable<Finding> findings)
    {
        var list = findings.ToList();
        if (list.Count == 0)
        {
            return new RiskProfile(
                Severity.Info, 0,
                ImmutableDictionary<Severity, int>.Empty,
                ImmutableDictionary<string, Severity>.Empty,
                ImmutableDictionary<string, double>.Empty,
                0, 0);
        }

        var sevCounts = list.GroupBy(f => f.Severity)
            .ToDictionary(g => g.Key, g => g.Count());

        var detectorMax = list.GroupBy(f => f.Detector)
            .ToDictionary(g => g.Key, g => g.Max(f => f.Severity));

        var detectorConf = list.GroupBy(f => f.Detector)
            .ToDictionary(g => g.Key, g => System.Math.Round(g.Average(f => f.Confidence), 3));

        int weighted = list.Sum(f => f.Severity.Weight());
        int confWeighted = (int)System.Math.Round(list.Sum(f => f.Severity.Weight() * f.Confidence));

        return new RiskProfile(
            list.Max(f => f.Severity),
            list.Count,
            sevCounts,
            detectorMax,
            detectorConf,
            weighted,
            confWeighted);
    }
}
