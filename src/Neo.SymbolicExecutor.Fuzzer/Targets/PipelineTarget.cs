using System;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Property: end-to-end pipeline (decode → run → detectors → risk → gate → report) never
/// throws an unexpected exception, regardless of the input bytecode. JSON output of every
/// run round-trips through JsonNode.Parse; Markdown output starts with the canonical H1.
/// This is the most realistic fuzz target — it runs the same code path the CLI does.
/// </summary>
public sealed class PipelineTarget : IFuzzTarget
{
    public string Name => "pipeline";
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

        var execResult = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 4_000,
            MaxPaths = 32,
            MaxStackSize = 128,
            MaxInvocationStackDepth = 64,
            MaxItemSize = 64 * 1024,
            MaxCollectionSize = 256,
        }).Run();

        if (execResult.FinalStates.Any(s => s.Status == TerminalStatus.Running))
        {
            reason = "pipeline: state with status=Running after Run()";
            return false;
        }

        var dEngine = new DetectorEngine(Detectors);
        var ctx = new AnalysisContext { States = execResult.FinalStates };
        var findings = dEngine.Run(ctx);
        var risk = RiskProfile.FromFindings(findings);
        var gate = new GatePolicy().Evaluate(findings, risk);
        var report = new AnalysisReport(findings, risk, gate, new AnalysisMeta(
            StatesExplored: execResult.StatesExplored,
            StepsExecuted: execResult.StepsExecuted,
            BudgetExceeded: execResult.BudgetExceeded,
            BudgetReason: execResult.BudgetReason));

        string json = ReportGenerator.ToJson(report);
        var parsed = System.Text.Json.Nodes.JsonNode.Parse(json);
        if (parsed?["findings"] is null) { reason = "pipeline JSON missing findings"; return false; }

        string md = ReportGenerator.ToMarkdown(report);
        if (!md.StartsWith("# Neo Symbolic Executor")) { reason = "pipeline Markdown missing H1"; return false; }

        return true;
    }
}
