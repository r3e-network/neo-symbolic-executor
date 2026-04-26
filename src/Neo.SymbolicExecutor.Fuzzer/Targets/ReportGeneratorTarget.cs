using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Text.Json.Nodes;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Property: ReportGenerator produces well-formed JSON and Markdown for any finding set we
/// can synthesize. The JSON must round-trip through JsonNode.Parse without exception.
/// </summary>
public sealed class ReportGeneratorTarget : IFuzzTarget
{
    public string Name => "report";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var states = new List<ExecutionState> { StateGen.RandomState(rng) };
        var engine = new DetectorEngine(DefaultDetectorSet.All());
        var findings = engine.Run(new AnalysisContext { States = states });
        var risk = RiskProfile.FromFindings(findings);

        var policy = new GatePolicy
        {
            FailOnMaxSeverity = (Severity)rng.Next(0, 5),
            FailOnTotalFindings = rng.Next(1, 50),
        };
        var gate = policy.Evaluate(findings, risk);
        var meta = new AnalysisMeta(StatesExplored: rng.Next(1, 200), StepsExecuted: rng.Next(1, 1000));
        var report = new AnalysisReport(findings, risk, gate, meta);

        reproInput = System.Text.Encoding.UTF8.GetBytes($"seed={seed}");
        reason = null;

        string json = ReportGenerator.ToJson(report);
        var parsed = JsonNode.Parse(json);
        if (parsed is null) { reason = "JSON did not parse back"; return false; }
        if (parsed["meta"] is null || parsed["risk_profile"] is null
            || parsed["gate_evaluation"] is null || parsed["findings"] is null)
        {
            reason = "JSON missing required top-level keys";
            return false;
        }

        string md = ReportGenerator.ToMarkdown(report);
        if (!md.StartsWith("# Neo Symbolic Executor"))
        {
            reason = "Markdown did not begin with the expected H1";
            return false;
        }
        return true;
    }
}
