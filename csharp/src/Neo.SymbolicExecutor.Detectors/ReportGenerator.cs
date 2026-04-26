using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Neo.SymbolicExecutor.Detectors;

public sealed record AnalysisReport(
    ImmutableArray<Finding> Findings,
    RiskProfile Risk,
    GateEvaluation Gate,
    AnalysisMeta Meta);

public sealed record AnalysisMeta(
    string Tool = "Neo.SymbolicExecutor",
    string Version = "0.4.0",
    int StatesExplored = 0,
    int StepsExecuted = 0,
    bool BudgetExceeded = false,
    string? BudgetReason = null,
    bool SmtAvailable = false,
    bool SmtEngaged = false);

public static class ReportGenerator
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    public static string ToJson(AnalysisReport report) =>
        BuildJson(report).ToJsonString(JsonOpts);

    public static string ToMarkdown(AnalysisReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Neo Symbolic Executor — Analysis Report");
        sb.AppendLine();
        sb.AppendLine($"- **Tool:** {report.Meta.Tool} {report.Meta.Version}");
        sb.AppendLine($"- **States explored:** {report.Meta.StatesExplored}");
        sb.AppendLine($"- **Steps executed:** {report.Meta.StepsExecuted}");
        if (report.Meta.BudgetExceeded)
            sb.AppendLine($"- **Budget exceeded:** {report.Meta.BudgetReason ?? "(unspecified)"}");
        sb.AppendLine($"- **SMT available:** {report.Meta.SmtAvailable} · **SMT engaged:** {report.Meta.SmtEngaged}");
        sb.AppendLine();

        // Risk profile.
        sb.AppendLine("## Risk Profile");
        sb.AppendLine();
        sb.AppendLine($"- **Overall max severity:** `{report.Risk.OverallMaxSeverity.ToLowerString()}`");
        sb.AppendLine($"- **Total findings:** {report.Risk.TotalFindings}");
        sb.AppendLine($"- **Weighted score:** {report.Risk.WeightedScore}");
        sb.AppendLine($"- **Confidence-weighted score:** {report.Risk.ConfidenceWeightedScore}");
        sb.AppendLine();
        if (report.Risk.SeverityCounts.Count > 0)
        {
            sb.AppendLine("| Severity | Count |");
            sb.AppendLine("|---|---|");
            foreach (var s in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info })
            {
                int n = report.Risk.SeverityCounts.TryGetValue(s, out int x) ? x : 0;
                if (n == 0) continue;
                sb.AppendLine($"| {s.ToLowerString()} | {n} |");
            }
            sb.AppendLine();
        }
        if (report.Risk.DetectorMaxSeverity.Count > 0)
        {
            sb.AppendLine("| Detector | Max severity | Avg confidence |");
            sb.AppendLine("|---|---|---|");
            foreach (var (det, sev) in report.Risk.DetectorMaxSeverity.OrderByDescending(kv => (int)kv.Value).ThenBy(kv => kv.Key))
            {
                double conf = report.Risk.DetectorAverageConfidence.TryGetValue(det, out double c) ? c : 0;
                sb.AppendLine($"| `{det}` | {sev.ToLowerString()} | {conf:0.00} |");
            }
            sb.AppendLine();
        }

        // Gate evaluation.
        sb.AppendLine("## Gate Evaluation");
        sb.AppendLine();
        sb.AppendLine($"- **Passed:** {(report.Gate.Passed ? "YES" : "NO")}");
        if (report.Gate.Policies.Count > 0)
        {
            sb.AppendLine("- **Active policies:**");
            foreach (var (k, v) in report.Gate.Policies.OrderBy(kv => kv.Key))
                sb.AppendLine($"  - `{k}`: `{v}`");
        }
        if (!report.Gate.Passed)
        {
            sb.AppendLine("- **Violations:**");
            foreach (var v in report.Gate.Violations) sb.AppendLine($"  - {v}");
        }
        sb.AppendLine();

        // Findings.
        sb.AppendLine("## Findings");
        if (report.Findings.IsEmpty)
        {
            sb.AppendLine();
            sb.AppendLine("_No findings._");
            return sb.ToString();
        }
        foreach (var f in report.Findings)
        {
            sb.AppendLine();
            sb.AppendLine($"### `{f.Detector}` — {f.Title}");
            sb.AppendLine();
            sb.AppendLine($"- **Severity:** `{f.Severity.ToLowerString()}`");
            sb.AppendLine($"- **Offset:** `0x{f.Offset:X4}`");
            sb.AppendLine($"- **Confidence:** {f.Confidence:0.00}");
            sb.AppendLine($"- **Confidence rationale:** {f.ConfidenceReason}");
            if (f.PathSatisfiable.HasValue)
                sb.AppendLine($"- **Path satisfiable:** {f.PathSatisfiable.Value}");
            if (f.Tags.Count > 0)
                sb.AppendLine($"- **Tags:** {string.Join(", ", f.Tags.OrderBy(t => t).Select(t => $"`{t}`"))}");
            sb.AppendLine();
            sb.AppendLine(f.Description);
        }
        return sb.ToString();
    }

    public static void WriteJson(AnalysisReport report, string path) =>
        File.WriteAllText(path, ToJson(report));

    public static void WriteMarkdown(AnalysisReport report, string path) =>
        File.WriteAllText(path, ToMarkdown(report));

    private static JsonObject BuildJson(AnalysisReport report)
    {
        var root = new JsonObject
        {
            ["meta"] = new JsonObject
            {
                ["tool"] = report.Meta.Tool,
                ["version"] = report.Meta.Version,
                ["states_explored"] = report.Meta.StatesExplored,
                ["steps_executed"] = report.Meta.StepsExecuted,
                ["budget_exceeded"] = report.Meta.BudgetExceeded,
                ["budget_reason"] = report.Meta.BudgetReason,
                ["smt_available"] = report.Meta.SmtAvailable,
                ["smt_engaged"] = report.Meta.SmtEngaged,
            },
            ["risk_profile"] = BuildRiskJson(report.Risk),
            ["gate_evaluation"] = BuildGateJson(report.Gate),
            ["findings"] = BuildFindingsJson(report.Findings),
        };
        return root;
    }

    private static JsonObject BuildRiskJson(RiskProfile risk)
    {
        var sevCounts = new JsonObject();
        foreach (var (s, n) in risk.SeverityCounts) sevCounts[s.ToLowerString()] = n;
        var detMax = new JsonObject();
        foreach (var (d, s) in risk.DetectorMaxSeverity) detMax[d] = s.ToLowerString();
        var detConf = new JsonObject();
        foreach (var (d, c) in risk.DetectorAverageConfidence) detConf[d] = c;
        return new JsonObject
        {
            ["overall_max_severity"] = risk.OverallMaxSeverity.ToLowerString(),
            ["total_findings"] = risk.TotalFindings,
            ["weighted_score"] = risk.WeightedScore,
            ["confidence_weighted_score"] = risk.ConfidenceWeightedScore,
            ["severity_counts"] = sevCounts,
            ["detector_max_severity"] = detMax,
            ["detector_average_confidence"] = detConf,
        };
    }

    private static JsonObject BuildGateJson(GateEvaluation gate)
    {
        var policies = new JsonObject();
        foreach (var (k, v) in gate.Policies) policies[k] = v;
        var violations = new JsonArray();
        foreach (var v in gate.Violations) violations.Add(v);
        return new JsonObject
        {
            ["passed"] = gate.Passed,
            ["policies"] = policies,
            ["violations"] = violations,
        };
    }

    private static JsonArray BuildFindingsJson(IReadOnlyList<Finding> findings)
    {
        var arr = new JsonArray();
        foreach (var f in findings)
        {
            var tags = new JsonArray();
            foreach (var t in f.Tags.OrderBy(t => t)) tags.Add(t);
            arr.Add(new JsonObject
            {
                ["detector"] = f.Detector,
                ["severity"] = f.Severity.ToLowerString(),
                ["title"] = f.Title,
                ["description"] = f.Description,
                ["offset"] = f.Offset,
                ["confidence"] = f.Confidence,
                ["confidence_reason"] = f.ConfidenceReason,
                ["tags"] = tags,
                ["path_satisfiable"] = f.PathSatisfiable,
            });
        }
        return arr;
    }
}
