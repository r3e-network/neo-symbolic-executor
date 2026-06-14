using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Top-level analysis output. Bundles the deduplicated findings, the rolled-up
/// <see cref="Detectors.RiskProfile"/>, the result of the configured gate policy, and the run
/// metadata. Pass to <see cref="ReportGenerator.ToJson"/> or <see cref="ReportGenerator.ToMarkdown"/>
/// to render. The shape is stable across releases — JSON consumers can rely on the field names.
/// </summary>
public sealed record AnalysisReport(
    ImmutableArray<Finding> Findings,
    RiskProfile Risk,
    GateEvaluation Gate,
    AnalysisMeta Meta);

/// <summary>
/// Per-run diagnostics that travel alongside the findings. Tool name + version identify the
/// analyzer build; the budget fields explain why analysis stopped (if it stopped early); SMT
/// fields describe whether and how the SMT layer participated.
/// </summary>
public sealed record AnalysisMeta(
    string Tool = "Neo.SymbolicExecutor",
    int StatesExplored = 0,
    int StepsExecuted = 0,
    bool BudgetExceeded = false,
    string? BudgetReason = null,
    bool CoverageIncomplete = false,
    string? CoverageReason = null,
    bool SmtAvailable = false,
    bool SmtEngaged = false)
{
    /// <summary>
    /// Default-resolved at type init from this assembly's InformationalVersion attribute, so a
    /// bump of NeoSymExecVersion in Directory.Build.props automatically flows into report
    /// metadata. Tests/callers may still override via the init-only setter.
    /// </summary>
    public string Version { get; init; } = CurrentVersion;

    /// <summary>
    /// SMT solver diagnostics for SMT-engaged runs. Null when --smt was not passed. Surfaced
    /// in JSON reports (the doc on <see cref="Smt.ISmtBackend.GetStats"/> claims this; this
    /// field is what makes that claim true).
    /// </summary>
    public Smt.SmtStats? SmtStats { get; init; }

    /// <summary>
    /// Manifest ABI entrypoints skipped because their declared offsets were outside the script.
    /// Non-empty means the analysis did not cover every manifest-declared entrypoint.
    /// </summary>
    public ImmutableArray<string> SkippedEntrypoints { get; init; } = ImmutableArray<string>.Empty;

    public static readonly string CurrentVersion = ResolveAssemblyVersion();

    private static string ResolveAssemblyVersion()
    {
        var asm = typeof(AnalysisMeta).Assembly;
        string? info = asm.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (info is not null)
        {
            // The MSBuild-emitted InformationalVersion includes a "+<commit-sha>" suffix when
            // SourceLink runs; strip it so reports show "0.4.0", not "0.4.0+abcdef…".
            int plus = info.IndexOf('+');
            if (plus >= 0) info = info[..plus];
            if (info.Length > 0) return info;
        }
        return asm.GetName().Version?.ToString(3) ?? "unknown";
    }
}

/// <summary>
/// Renders an <see cref="AnalysisReport"/> to deterministic JSON or Markdown.
///
/// Determinism guarantees:
///   - All dictionary iterations sort keys with <see cref="System.StringComparer.Ordinal"/> so
///     output is byte-identical across machines and locales.
///   - All numeric formatting uses <see cref="System.Globalization.CultureInfo.InvariantCulture"/>.
///   - Severity bucket emission follows a critical-first canonical order shared by JSON and
///     Markdown so the two outputs always agree on row/key ordering.
///
/// CI consumers can rely on a SHA-256 of the JSON output as a stable artifact key.
/// </summary>
public static class ReportGenerator
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };

    // Critical-first canonical ordering for severity-bucket emission. Used by both the markdown
    // table and the JSON severity_counts dict so the two outputs agree on row/key order.
    private static readonly Severity[] SeverityCanonicalOrder =
    {
        Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Info,
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
            sb.AppendLine($"- **Budget exceeded:** {Md(report.Meta.BudgetReason ?? "(unspecified)")}");
        if (report.Meta.CoverageIncomplete)
        {
            sb.AppendLine($"- **Coverage incomplete:** {Md(report.Meta.CoverageReason ?? "(unspecified)")}");
            if (!report.Meta.SkippedEntrypoints.IsDefaultOrEmpty)
                sb.AppendLine($"- **Skipped entrypoints:** {string.Join(", ", report.Meta.SkippedEntrypoints.OrderBy(x => x, System.StringComparer.Ordinal).Select(Code))}");
        }
        sb.AppendLine($"- **SMT available:** {report.Meta.SmtAvailable} · **SMT engaged:** {report.Meta.SmtEngaged}");
        if (report.Meta.SmtStats is { } stats)
        {
            sb.AppendLine(
                $"- **SMT queries:** {stats.Queries}, cache_hits={stats.CacheHits}, "
                + $"sat={stats.Sat}, unsat={stats.Unsat}, unknowns={stats.Unknowns}, timeouts={stats.Timeouts}");
            if (stats.OpaqueTranslations > 0)
                sb.AppendLine(
                    $"- **SMT precision warning:** {stats.OpaqueTranslations} expression(s) were "
                    + "translated as unconstrained aux symbols (sound over-approximation; SAT/UNSAT verdicts may have lost precision).");
        }
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
            foreach (var s in SeverityCanonicalOrder)
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
            foreach (var (det, sev) in report.Risk.DetectorMaxSeverity
                         .OrderByDescending(kv => (int)kv.Value)
                         .ThenBy(kv => kv.Key, System.StringComparer.Ordinal))
            {
                double conf = report.Risk.DetectorAverageConfidence.TryGetValue(det, out double c) ? c : 0;
                sb.AppendLine($"| {Code(det)} | {sev.ToLowerString()} | {conf.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)} |");
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
            foreach (var (k, v) in report.Gate.Policies.OrderBy(kv => kv.Key, System.StringComparer.Ordinal))
                sb.AppendLine($"  - {Code(k)}: {Code(v)}");
        }
        if (!report.Gate.Passed)
        {
            sb.AppendLine("- **Violations:**");
            foreach (var v in report.Gate.Violations) sb.AppendLine($"  - {Md(v)}");
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
            sb.AppendLine($"### {Code(f.Detector)} — {Md(f.Title)}");
            sb.AppendLine();
            sb.AppendLine($"- **Severity:** `{f.Severity.ToLowerString()}`");
            sb.AppendLine($"- **Offset:** `0x{f.Offset:X4}`");
            sb.AppendLine($"- **Confidence:** {f.Confidence.ToString("0.00", System.Globalization.CultureInfo.InvariantCulture)}");
            sb.AppendLine($"- **Confidence rationale:** {Md(f.ConfidenceReason)}");
            if (f.PathSatisfiable.HasValue)
                sb.AppendLine($"- **Path satisfiable:** {f.PathSatisfiable.Value}");
            if (f.Tags.Count > 0)
                sb.AppendLine($"- **Tags:** {string.Join(", ", f.Tags.OrderBy(t => t, System.StringComparer.Ordinal).Select(Code))}");
            sb.AppendLine();
            sb.AppendLine(Md(f.Description));
            if (f.Witness is { Count: > 0 } w)
            {
                sb.AppendLine();
                sb.AppendLine("**Reproducer (concrete witness):**");
                sb.AppendLine();
                sb.AppendLine("| Symbol | Concrete value |");
                sb.AppendLine("|---|---|");
                foreach (var (k, v) in w.OrderBy(kv => kv.Key, System.StringComparer.Ordinal))
                    sb.AppendLine($"| {Code(k)} | {Code(FormatWitnessValue(v))} |");
            }
        }
        return sb.ToString();
    }

    public static void WriteJson(AnalysisReport report, string path) =>
        File.WriteAllText(path, ToJson(report));

    public static void WriteMarkdown(AnalysisReport report, string path) =>
        File.WriteAllText(path, ToMarkdown(report));

    private static JsonObject BuildJson(AnalysisReport report)
    {
        var meta = new JsonObject
        {
            ["tool"] = report.Meta.Tool,
            ["version"] = report.Meta.Version,
            ["states_explored"] = report.Meta.StatesExplored,
            ["steps_executed"] = report.Meta.StepsExecuted,
            ["budget_exceeded"] = report.Meta.BudgetExceeded,
            ["budget_reason"] = report.Meta.BudgetReason,
            ["coverage_incomplete"] = report.Meta.CoverageIncomplete,
            ["coverage_reason"] = report.Meta.CoverageReason,
            ["smt_available"] = report.Meta.SmtAvailable,
            ["smt_engaged"] = report.Meta.SmtEngaged,
        };
        var skipped = new JsonArray();
        var skippedEntries = report.Meta.SkippedEntrypoints.IsDefault
            ? Enumerable.Empty<string>()
            : report.Meta.SkippedEntrypoints.OrderBy(x => x, System.StringComparer.Ordinal);
        foreach (var entry in skippedEntries)
            skipped.Add(entry);
        meta["skipped_entrypoints"] = skipped;
        if (report.Meta.SmtStats is { } s)
        {
            meta["smt_stats"] = new JsonObject
            {
                ["queries"] = s.Queries,
                ["cache_hits"] = s.CacheHits,
                ["sat"] = s.Sat,
                ["unsat"] = s.Unsat,
                ["unknowns"] = s.Unknowns,
                ["timeouts"] = s.Timeouts,
                ["opaque_translations"] = s.OpaqueTranslations,
            };
        }
        return new JsonObject
        {
            ["meta"] = meta,
            ["risk_profile"] = BuildRiskJson(report.Risk),
            ["gate_evaluation"] = BuildGateJson(report.Gate),
            ["findings"] = BuildFindingsJson(report.Findings),
        };
    }

    private static JsonObject BuildRiskJson(RiskProfile risk)
    {
        // Sort dictionary iteration explicitly so JSON output is byte-identical across runs
        // even if upstream LINQ groupings ever reorder. Severity counts emit in canonical
        // critical-first order; detector dictionaries sort alphabetically by key.
        var sevCounts = new JsonObject();
        foreach (var s in SeverityCanonicalOrder)
            if (risk.SeverityCounts.TryGetValue(s, out int n))
                sevCounts[s.ToLowerString()] = n;
        var detMax = new JsonObject();
        foreach (var (d, s) in risk.DetectorMaxSeverity.OrderBy(kv => kv.Key, System.StringComparer.Ordinal))
            detMax[d] = s.ToLowerString();
        var detConf = new JsonObject();
        foreach (var (d, c) in risk.DetectorAverageConfidence.OrderBy(kv => kv.Key, System.StringComparer.Ordinal))
            detConf[d] = c;
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
        foreach (var (k, v) in gate.Policies.OrderBy(kv => kv.Key, System.StringComparer.Ordinal))
            policies[k] = v;
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
            foreach (var t in f.Tags.OrderBy(t => t, System.StringComparer.Ordinal)) tags.Add(t);
            JsonObject? witness = null;
            if (f.Witness is { Count: > 0 } w)
            {
                witness = new JsonObject();
                foreach (var (k, v) in w.OrderBy(kv => kv.Key, System.StringComparer.Ordinal))
                    witness[k] = FormatWitnessValue(v);
            }
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
                ["witness"] = witness,
            });
        }
        return arr;
    }

    private static string FormatWitnessValue(object v) => v switch
    {
        System.Numerics.BigInteger bi => bi.ToString(System.Globalization.CultureInfo.InvariantCulture),
        bool b => b ? "true" : "false",
        long l => l.ToString(System.Globalization.CultureInfo.InvariantCulture),
        byte[] bytes => "0x" + System.Convert.ToHexString(bytes),
        // Defensive: any future numeric witness type (int/double/decimal/DateTime/etc.)
        // implements IFormattable and so flows through the invariant path. Without this arm
        // an int witness would render via the locale-sensitive default ToString() and a
        // tr-TR machine could emit "1.234" as "1,234" — same class of bug fixed in 32b9c61.
        IFormattable f => f.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        _ => v?.ToString() ?? "<null>",
    };

    private static string Code(string value) => $"`{Md(value)}`";

    private static string Md(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(value.Length);
        bool lastWasSpace = false;
        foreach (char c in value)
        {
            if (c is '\r' or '\n' or '\t' || char.IsControl(c))
            {
                if (!lastWasSpace)
                {
                    sb.Append(' ');
                    lastWasSpace = true;
                }
                continue;
            }

            lastWasSpace = c == ' ';
            switch (c)
            {
                case '\\': sb.Append(@"\\"); break;
                case '`': sb.Append(@"\`"); break;
                case '*': sb.Append(@"\*"); break;
                case '_': sb.Append(@"\_"); break;
                case '[': sb.Append(@"\["); break;
                case ']': sb.Append(@"\]"); break;
                case '(': sb.Append(@"\("); break;
                case ')': sb.Append(@"\)"); break;
                case '#': sb.Append(@"\#"); break;
                case '|': sb.Append(@"\|"); break;
                case '<': sb.Append("&lt;"); break;
                case '>': sb.Append("&gt;"); break;
                default: sb.Append(c); break;
            }
        }
        return sb.ToString().Trim();
    }
}
