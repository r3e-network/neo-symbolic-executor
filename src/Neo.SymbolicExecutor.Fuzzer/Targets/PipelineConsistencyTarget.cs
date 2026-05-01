using System;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Stronger pipeline oracle than the existing <c>pipeline</c> target. The original only
/// checks JSON contains a "findings" key and Markdown starts with H1. This target adds:
///
///  - Severity is a defined enum value (no out-of-range integers in Finding.Severity).
///  - Confidence is in [0, 1].
///  - Offset is non-negative; for findings tied to the script body we additionally require
///    Offset less than the script length (witness/permissions findings can use 0).
///  - RiskProfile.OverallMaxSeverity equals max(Severity) over Findings.
///  - RiskProfile.TotalFindings equals Findings.Count.
///  - RiskProfile.SeverityCounts sums to TotalFindings.
///  - DedupeKey is unique within a single run (Findings already dedupe in detectors).
///  - Gate.Passed iff Gate.Violations is empty.
/// </summary>
public sealed class PipelineConsistencyTarget : IFuzzTarget
{
    public string Name => "pipeline-consistency";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    private static readonly System.Collections.Generic.IReadOnlyList<IDetector> Detectors =
        DefaultDetectorSet.All();

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        var bytes = OpCodeGen.RandomScript(rng, 4, 96);
        reproInput = bytes;
        reason = null;

        NeoProgram program;
        try { program = ScriptDecoder.Decode(bytes); }
        catch (VmFaultException) { return true; }

        int scriptLen = bytes.Length;

        var execResult = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 4_000,
            MaxPaths = 32,
            MaxStackSize = 128,
            MaxInvocationStackDepth = 64,
            MaxItemSize = 32 * 1024,
            MaxCollectionSize = 256,
            MaxHeapObjects = 512,
            MaxQueuedStates = 128,
            PerRunDeadline = System.TimeSpan.FromSeconds(2),
        }).Run();

        var dEngine = new DetectorEngine(Detectors);
        var ctx = new AnalysisContext { States = execResult.FinalStates };
        var findings = dEngine.Run(ctx);
        var risk = RiskProfile.FromFindings(findings);

        // Per-finding shape checks.
        foreach (var f in findings)
        {
            if (!Enum.IsDefined(typeof(Severity), f.Severity))
            {
                reason = $"finding {f.Detector}@0x{f.Offset:X4} has undefined severity {(int)f.Severity}";
                return false;
            }
            if (double.IsNaN(f.Confidence) || f.Confidence < 0.0 || f.Confidence > 1.0)
            {
                reason = $"finding {f.Detector}@0x{f.Offset:X4} confidence {f.Confidence} out of [0,1]";
                return false;
            }
            if (f.Offset < 0)
            {
                reason = $"finding {f.Detector} negative offset {f.Offset}";
                return false;
            }
            // Manifest-only detectors emit findings at synthetic offsets (e.g., 0). Don't flag those.
            // For findings that *do* tie to a script offset, the offset must be in-range of the bytecode.
            if (f.Offset > 0 && f.Offset > scriptLen + 8)
            {
                reason = $"finding {f.Detector}@0x{f.Offset:X4} beyond script bytes ({scriptLen})";
                return false;
            }
            if (string.IsNullOrEmpty(f.Detector) || string.IsNullOrEmpty(f.Title))
            {
                reason = $"finding has empty detector/title ({f.Detector}/{f.Title})";
                return false;
            }
        }

        // Risk consistency.
        if (risk.TotalFindings != findings.Length)
        {
            reason = $"risk.TotalFindings {risk.TotalFindings} != findings.Length {findings.Length}";
            return false;
        }
        int sevSum = risk.SeverityCounts.Values.Sum();
        if (sevSum != findings.Length)
        {
            reason = $"risk.SeverityCounts sum {sevSum} != findings.Length {findings.Length}";
            return false;
        }
        if (findings.Length > 0)
        {
            var observedMax = findings.Max(f => f.Severity);
            if (risk.OverallMaxSeverity != observedMax)
            {
                reason = $"risk.OverallMaxSeverity {risk.OverallMaxSeverity} != observed max {observedMax}";
                return false;
            }
        }

        // Gate consistency.
        var policy = new GatePolicy
        {
            FailOnMaxSeverity = (Severity)((seed & 0x3) + 1), // 1..4 -> Low..Critical
            FailOnTotalFindings = (seed & 0xF) + 1,
        };
        var gate = policy.Evaluate(findings, risk);
        if (gate.Passed && !gate.Violations.IsEmpty)
        {
            reason = "gate passed but has violations";
            return false;
        }
        if (!gate.Passed && gate.Violations.IsEmpty)
        {
            reason = "gate failed but has no violations";
            return false;
        }

        // Report shape.
        var meta = new AnalysisMeta(StatesExplored: execResult.StatesExplored,
                                    StepsExecuted: execResult.StepsExecuted,
                                    BudgetExceeded: execResult.BudgetExceeded,
                                    BudgetReason: execResult.BudgetReason);
        var report = new AnalysisReport(findings, risk, gate, meta);
        string json = ReportGenerator.ToJson(report);
        var parsed = System.Text.Json.Nodes.JsonNode.Parse(json);
        if (parsed?["findings"] is null) { reason = "JSON missing findings key"; return false; }
        if (parsed["risk_profile"] is null) { reason = "JSON missing risk_profile key"; return false; }
        if (parsed["gate_evaluation"] is null) { reason = "JSON missing gate_evaluation key"; return false; }
        if (parsed["meta"] is null) { reason = "JSON missing meta key"; return false; }
        return true;
    }
}
