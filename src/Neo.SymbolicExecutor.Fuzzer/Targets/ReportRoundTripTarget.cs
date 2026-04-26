using System;
using System.Collections.Generic;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Oracle: the JSON encoding of an <see cref="AnalysisReport"/> is byte-stable across
/// repeated encodings — i.e., <c>ToJson(r) == ToJson(r)</c>. A divergence here means the
/// encoder enumerated something in non-deterministic order (e.g., a HashSet) and any
/// downstream consumer comparing two reports will see false diffs.
///
/// Also asserts: re-parsing the JSON via <c>JsonNode.Parse</c> succeeds and the parsed tree's
/// findings count matches the original.
/// </summary>
public sealed class ReportRoundTripTarget : IFuzzTarget
{
    public string Name => "report-roundtrip";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    private static readonly IReadOnlyList<IDetector> Detectors = DefaultDetectorSet.All();

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var states = new List<ExecutionState>();
        int n = rng.Next(1, 5);
        for (int i = 0; i < n; i++) states.Add(StateGen.RandomState(new Random(rng.Next())));

        reproInput = System.Text.Encoding.UTF8.GetBytes($"seed={seed},states={n}");
        reason = null;

        var dEngine = new DetectorEngine(Detectors);
        var findings = dEngine.Run(new AnalysisContext { States = states });
        var risk = RiskProfile.FromFindings(findings);
        var gate = new GatePolicy
        {
            FailOnMaxSeverity = (Severity)rng.Next(0, 5),
            FailOnTotalFindings = rng.Next(1, 50),
        }.Evaluate(findings, risk);
        var meta = new AnalysisMeta(StatesExplored: rng.Next(1, 200), StepsExecuted: rng.Next(1, 10000));
        var report = new AnalysisReport(findings, risk, gate, meta);

        string j1 = ReportGenerator.ToJson(report);
        string j2 = ReportGenerator.ToJson(report);
        if (j1 != j2)
        {
            reason = $"JSON encoder non-deterministic (len {j1.Length} vs {j2.Length})";
            return false;
        }

        var parsed = System.Text.Json.Nodes.JsonNode.Parse(j1);
        if (parsed?["findings"] is not System.Text.Json.Nodes.JsonArray arr)
        {
            reason = "round-trip lost findings array";
            return false;
        }
        if (arr.Count != findings.Length)
        {
            reason = $"round-trip findings count: encoded {findings.Length} vs parsed {arr.Count}";
            return false;
        }

        string m1 = ReportGenerator.ToMarkdown(report);
        string m2 = ReportGenerator.ToMarkdown(report);
        if (m1 != m2)
        {
            reason = $"Markdown encoder non-deterministic (len {m1.Length} vs {m2.Length})";
            return false;
        }
        if (!m1.StartsWith("# Neo Symbolic Executor"))
        {
            reason = "Markdown missing canonical H1";
            return false;
        }
        return true;
    }
}
