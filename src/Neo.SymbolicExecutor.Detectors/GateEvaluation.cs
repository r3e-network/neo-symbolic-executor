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
    public bool FailOnBudgetExceeded { get; init; }
    public bool FailOnIncompleteCoverage { get; init; }

    public GateEvaluation Evaluate(
        IReadOnlyList<Finding> findings,
        RiskProfile profile,
        bool budgetExceeded = false,
        bool coverageIncomplete = false,
        string? coverageReason = null)
    {
        var violations = new List<string>();

        if (FailOnBudgetExceeded && budgetExceeded)
            violations.Add("analysis budget exceeded — results may be incomplete");

        if (FailOnIncompleteCoverage && coverageIncomplete)
        {
            string suffix = string.IsNullOrWhiteSpace(coverageReason) ? "" : $" — {coverageReason}";
            violations.Add("analysis coverage incomplete" + suffix);
        }

        // Audit fix: a clean run (zero findings) returns OverallMaxSeverity = Info as a sentinel,
        // which would falsely trip a `FailOnMaxSeverity = Info` gate. Skip the max-severity check
        // when there are no findings — a no-finding run cannot exceed any severity threshold.
        if (FailOnMaxSeverity is Severity sev && profile.TotalFindings > 0
            && profile.OverallMaxSeverity >= sev)
            violations.Add($"max severity {profile.OverallMaxSeverity.ToLowerString()} >= threshold {sev.ToLowerString()}");

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
                    violations.Add($"detector {d} max severity {actual.ToLowerString()} >= threshold {capSev.ToLowerString()}");
            }
        }

        if (MinConfidence is { } floor)
        {
            // Gate violation strings render into JSON/Markdown reports — keep them locale-stable.
            var inv = System.Globalization.CultureInfo.InvariantCulture;
            foreach (var f in findings)
            {
                if (floor.TryGetValue(f.Severity, out double minConf) && f.Confidence < minConf)
                    violations.Add($"{f.Detector} finding at 0x{f.Offset:X4} confidence {f.Confidence.ToString("0.00", inv)} < floor {minConf.ToString("0.00", inv)}");
            }
        }

        return new GateEvaluation(
            Passed: violations.Count == 0,
            Violations: violations.ToImmutableArray(),
            Policies: SerializePolicies());
    }

    private ImmutableDictionary<string, string> SerializePolicies()
    {
        // Policy strings render into JSON/Markdown — InvariantCulture keeps int/double output
        // identical regardless of host locale.
        var inv = System.Globalization.CultureInfo.InvariantCulture;
        var b = ImmutableDictionary.CreateBuilder<string, string>();
        if (FailOnMaxSeverity is { } a) b["fail-on-max-severity"] = a.ToLowerString();
        if (FailOnTotalFindings is { } b1) b["fail-on-total-findings"] = b1.ToString(inv);
        if (FailOnWeightedScore is { } w) b["fail-on-weighted-score"] = w.ToString(inv);
        if (FailOnConfidenceWeightedScore is { } cw) b["fail-on-confidence-weighted-score"] = cw.ToString(inv);
        if (FailOnSeverityCount is { Count: > 0 } sc)
            b["fail-on-severity-count"] = string.Join(
                ",",
                sc.OrderBy(kv => (int)kv.Key)
                  .Select(kv => $"{kv.Key.ToLowerString()}={kv.Value.ToString(inv)}"));
        if (FailOnDetectorSeverity is { Count: > 0 } ds)
            b["fail-on-detector-severity"] = string.Join(
                ",",
                ds.OrderBy(kv => kv.Key, System.StringComparer.Ordinal)
                  .Select(kv => $"{kv.Key}={kv.Value.ToLowerString()}"));
        if (MinConfidence is { Count: > 0 } mc)
            b["min-confidence"] = string.Join(
                ",",
                mc.OrderBy(kv => (int)kv.Key)
                  .Select(kv => $"{kv.Key.ToLowerString()}={kv.Value.ToString("0.00", inv)}"));
        if (FailOnBudgetExceeded) b["fail-on-budget-exceeded"] = "true";
        if (FailOnIncompleteCoverage) b["fail-on-incomplete-coverage"] = "true";
        return b.ToImmutable();
    }
}

public sealed record GateEvaluation(
    bool Passed,
    ImmutableArray<string> Violations,
    ImmutableDictionary<string, string> Policies);
