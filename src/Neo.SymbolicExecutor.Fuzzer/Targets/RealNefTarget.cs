using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Property: the full pipeline (NEF parse → script decode → engine run → detectors → report)
/// completes without unexpected exceptions on REAL Neo C# compiler output. This is the most
/// faithful test of "does it work on contracts users actually write."
///
/// The target scans a directory tree for *.nef files at startup; each iteration picks one
/// uniformly at random. If the directory tree is empty the target returns success and produces
/// no useful coverage — set NEO_SYM_FUZZ_NEF_DIR to enable.
///
/// Suggested directories to point at:
///   /home/neo/git/neo-devpack-dotnet/examples/**/bin/sc/   (DevPack examples)
///   docs/validation/devpack-corpus/extracted/              (snapshotted corpus)
/// </summary>
public sealed class RealNefTarget : IFuzzTarget
{
    public string Name => "real-nef";
    public Type[] ExpectedExceptions => Type.EmptyTypes;

    private readonly ImmutableArray<string> _files;
    private readonly IReadOnlyList<IDetector> _detectors = DefaultDetectorSet.All();

    public RealNefTarget()
    {
        var dir = Environment.GetEnvironmentVariable("NEO_SYM_FUZZ_NEF_DIR");
        if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
        {
            _files = ImmutableArray<string>.Empty;
            return;
        }
        try
        {
            _files = Directory.EnumerateFiles(dir, "*.nef", SearchOption.AllDirectories)
                .Take(2048)
                .ToImmutableArray();
        }
        catch (Exception)
        {
            _files = ImmutableArray<string>.Empty;
        }
    }

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        if (_files.IsDefaultOrEmpty)
        {
            reproInput = Array.Empty<byte>();
            reason = null;
            return true;  // no corpus configured -> trivially success
        }

        var rng = new Random(seed);
        string path = _files[rng.Next(_files.Length)];
        byte[] bytes;
        try { bytes = File.ReadAllBytes(path); }
        catch (IOException) { reproInput = Array.Empty<byte>(); reason = null; return true; }

        // Audit C# #24 fix: the reproducer must be the actual contract bytes, not the path
        // string — otherwise CrashMinimizer receives a path and shrinks it to garbage.
        reproInput = bytes;
        reason = null;

        NefFile nef;
        try { nef = NefFile.Parse(bytes, verifyChecksum: true); }
        catch (FormatException) { return true; }
        catch (EndOfStreamException) { return true; }

        // Try to find the manifest sidecar: <name>.manifest.json next to the .nef.
        ContractManifest? manifest = null;
        string manifestPath = Path.ChangeExtension(path, ".manifest.json");
        if (File.Exists(manifestPath))
        {
            try { manifest = ContractManifest.FromFile(manifestPath); }
            catch (Exception) { /* ignore: manifest parse failure isn't a fuzz failure */ }
        }

        NeoProgram program;
        try { program = ScriptDecoder.Decode(nef.Script).WithTokens(nef.Tokens.ToImmutableArray()); }
        catch (VmFaultException) { return true; }

        var execResult = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 8_000,
            MaxPaths = 64,
            MaxStackSize = 256,
            MaxInvocationStackDepth = 128,
            MaxItemSize = 256 * 1024,
            MaxCollectionSize = 1024,
        }).Run();

        if (execResult.FinalStates.Any(s => s.Status == TerminalStatus.Running))
        {
            reason = $"real-nef '{Path.GetFileName(path)}': state with status=Running after Run()";
            return false;
        }

        var dEngine = new DetectorEngine(_detectors);
        var ctx = new AnalysisContext
        {
            States = execResult.FinalStates,
            Manifest = manifest,
        };
        var findings = dEngine.Run(ctx);
        var risk = RiskProfile.FromFindings(findings);
        var gate = new GatePolicy().Evaluate(findings, risk);
        var report = new AnalysisReport(findings, risk, gate, new AnalysisMeta(
            StatesExplored: execResult.StatesExplored,
            StepsExecuted: execResult.StepsExecuted,
            BudgetExceeded: execResult.BudgetExceeded,
            BudgetReason: execResult.BudgetReason));

        // Emit JSON + Markdown to ensure both renderers handle real-world telemetry shapes.
        string json = ReportGenerator.ToJson(report);
        var parsed = System.Text.Json.Nodes.JsonNode.Parse(json);
        if (parsed?["findings"] is null) { reason = $"real-nef {path}: JSON missing findings"; return false; }
        string md = ReportGenerator.ToMarkdown(report);
        if (!md.StartsWith("# Neo Symbolic Executor")) { reason = $"real-nef {path}: Markdown missing H1"; return false; }
        return true;
    }
}
