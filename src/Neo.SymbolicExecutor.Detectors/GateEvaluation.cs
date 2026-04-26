using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// CI risk-gating policy (audit Phases 20-23). Specifies thresholds; <see cref="Evaluate"/>
/// produces a <see cref="GateEvaluation"/> describing pass/fail and the violated rules.
/// </summary>
public sealed class GatePolicy
{
    public Severity? FailOnMaxSeverity { get; init; }
    public int? FailOnTotalFindings { get; init; }
    public int? FailOnWeightedScore { get; init; }
    public int? FailOnConfidenceWeightedScore { get; init; }
    public IReadOnlyDictionary<Severity, int>? FailOnSeverityCount { get; init; }
    public IReadOnlyDictionary<string, Severity>? FailOnDetectorSeverity { get; init; }
    public IReadOnlyDictionary<Severity, double>? MinConfidence { get; init; }

    public GateEvaluation Evaluate(IReadOnlyList<Finding> findings, RiskProfile profile)
    {
        var violations = new List<string>();

        // Audit fix: a clean run (zero findings) returns OverallMaxSeverity = Info as a sentinel,
        // which would falsely trip a `FailOnMaxSeverity = Info` gate. Skip the max-severity check
        // when there are no findings — a no-finding run cannot exceed any severity threshold.
        if (FailOnMaxSeverity is Severity sev && profile.TotalFindings > 0
            && profile.OverallMaxSeverity >= sev)
            violations.Add($"max severity {profile.OverallMaxSeverity} >= threshold {sev}");

        if (FailOnTotalFindings is int totalCap && profile.TotalFindings >= totalCap)
            violations.Add($"total findings {profile.TotalFindings} >= threshold {totalCap}");

        if (FailOnWeightedScore is int wsCap && profile.WeightedScore >= wsCap)
            violations.Add($"weighted score {profile.WeightedScore} >= threshold {wsCap}");

        if (FailOnConfidenceWeightedScore is int cwsCap && profile.ConfidenceWeightedScore >= cwsCap)
            violations.Add($"confidence-weighted score {profile.ConfidenceWeightedScore} >= threshold {cwsCap}");

        if (FailOnSeverityCount is { } sevCap)
        {
            foreach (var (s, cap) in sevCap)
            {
                int actual = profile.SeverityCounts.TryGetValue(s, out int n) ? n : 0;
                if (actual >= cap)
                    violations.Add($"{s.ToLowerString()} findings {actual} >= threshold {cap}");
            }
        }

        if (FailOnDetectorSeverity is { } detCap)
        {
            foreach (var (d, capSev) in detCap)
            {
                if (profile.DetectorMaxSeverity.TryGetValue(d, out var actual) && actual >= capSev)
                    violations.Add($"detector {d} max severity {actual} >= threshold {capSev}");
            }
        }

        if (MinConfidence is { } floor)
        {
            foreach (var f in findings)
            {
                if (floor.TryGetValue(f.Severity, out double minConf) && f.Confidence < minConf)
                    violations.Add($"{f.Detector} finding at 0x{f.Offset:X4} confidence {f.Confidence:0.00} < floor {minConf:0.00}");
            }
        }

        return new GateEvaluation(
            Passed: violations.Count == 0,
            Violations: violations.ToImmutableArray(),
            Policies: SerializePolicies());
    }

    private ImmutableDictionary<string, string> SerializePolicies()
    {
        var b = ImmutableDictionary.CreateBuilder<string, string>();
        if (FailOnMaxSeverity is { } a) b["fail-on-max-severity"] = a.ToLowerString();
        if (FailOnTotalFindings is { } b1) b["fail-on-total-findings"] = b1.ToString();
        if (FailOnWeightedScore is { } w) b["fail-on-weighted-score"] = w.ToString();
        if (FailOnConfidenceWeightedScore is { } cw) b["fail-on-confidence-weighted-score"] = cw.ToString();
        if (FailOnSeverityCount is { Count: > 0 } sc)
            b["fail-on-severity-count"] = string.Join(",", sc.Select(kv => $"{kv.Key.ToLowerString()}={kv.Value}"));
        if (FailOnDetectorSeverity is { Count: > 0 } ds)
            b["fail-on-detector-severity"] = string.Join(",", ds.Select(kv => $"{kv.Key}={kv.Value.ToLowerString()}"));
        if (MinConfidence is { Count: > 0 } mc)
            b["min-confidence"] = string.Join(",", mc.Select(kv => $"{kv.Key.ToLowerString()}={kv.Value:0.00}"));
        return b.ToImmutable();
    }
}

public sealed record GateEvaluation(
    bool Passed,
    ImmutableArray<string> Violations,
    ImmutableDictionary<string, string> Policies);
