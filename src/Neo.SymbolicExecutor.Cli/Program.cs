using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using Neo.SymbolicExecutor;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Cli;

internal static class Program
{
    /// <summary>
    /// Exit codes:
    ///   0 — success / gate passed.
    ///   1 — analyzer error (parse failure, unhandled exception).
    ///   2 — bad arguments.
    ///   3 — gate violation (analysis succeeded but a configured gate fired).
    /// </summary>
    public static int Main(string[] args)
    {
        if (args.Length == 0 || args[0] is "-h" or "--help")
        {
            PrintUsage();
            return 0;
        }
        try
        {
            return args[0] switch
            {
                "decode" => Decode(args[1..]),
                "explore" => Explore(args[1..]),
                "analyze" => Analyze(args[1..]),
                "version" => Version(),
                _ => Unknown(args[0]),
            };
        }
        catch (ArgumentException aex)
        {
            Console.Error.WriteLine($"error: {aex.Message}");
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            return 1;
        }
    }

    private static int Decode(string[] args)
    {
        if (args.Length < 1) throw new ArgumentException("usage: neo-sym decode <script.bin|.nef>");
        var program = LoadProgram(args[0]);
        Console.WriteLine($"Decoded {program.Instructions.Length} instructions from {program.Bytes.Length} bytes");
        foreach (var inst in program.Instructions)
        {
            string operand = inst.Operand.Length > 0 ? $" {Convert.ToHexString(inst.Operand.Span)}" : "";
            string target = inst.Target >= 0 ? $" -> 0x{inst.Target:X4}" : "";
            Console.WriteLine($"  0x{inst.Offset:X4}  {inst.OpCode}{operand}{target}");
        }
        return 0;
    }

    private static int Explore(string[] args)
    {
        if (args.Length < 1) throw new ArgumentException("usage: neo-sym explore <script.bin|.nef>");
        var program = LoadProgram(args[0]);
        var result = new SymbolicEngine(program).Run();
        Console.WriteLine($"Explored {result.StatesExplored} states ({result.StepsExecuted} steps).");
        Console.WriteLine($"Final states: {result.FinalStates.Length}.");
        if (result.BudgetExceeded) Console.WriteLine($"Budget exceeded: {result.BudgetReason}");
        foreach (var s in result.FinalStates)
            Console.WriteLine($"  {s.Status}: {s.TerminationReason ?? "<no reason>"}");
        // Audit C# #20: explore is a debug command; success regardless of FAULTED states.
        return 0;
    }

    private static int Analyze(string[] args)
    {
        var opts = AnalyzeOptions.Parse(args);
        var program = LoadProgram(opts.Path);
        ContractManifest? manifest = null;
        if (opts.ManifestPath is not null)
            manifest = ContractManifest.FromFile(opts.ManifestPath);
        SourceHints? sourceHints = opts.SourcePaths.Count > 0
            ? SourceHints.FromPaths(opts.SourcePaths)
            : null;

        if (opts.DanglingSmtFlags.Count > 0)
            Console.Error.WriteLine(
                $"warning: ignored {string.Join(", ", opts.DanglingSmtFlags)} — pass --smt to engage the SMT backend.");

        // Scope the backend so any per-analysis solver resources stay bounded for repeated hosts.
        Smt.ISmtBackend? smtBackend = null;
        Smt.Z3.Z3Backend? z3Owned = null;
        if (opts.UseSmt)
        {
            z3Owned = new Smt.Z3.Z3Backend(opts.SmtTimeoutMs, opts.SmtBytesBound);
            if (z3Owned.Version.StartsWith("portable fallback", StringComparison.Ordinal))
                Console.Error.WriteLine("warning: --smt using portable fallback; install z3 or set NEO_SYMBOLIC_EXECUTOR_Z3 for full SMT-LIB solving");
            smtBackend = z3Owned;
        }
        try
        {
            var defaults = ExecutionOptions.Default;
            var engineOptions = new ExecutionOptions
            {
                SmtBackend = smtBackend,
                MaxPaths = opts.MaxPaths ?? defaults.MaxPaths,
                MaxSteps = opts.MaxSteps ?? defaults.MaxSteps,
                PerRunDeadline = opts.PerRunDeadlineMs is int ms
                    ? System.TimeSpan.FromMilliseconds(ms)
                    : defaults.PerRunDeadline,
            };
            var execResult = RunAllManifestEntrypoints(program, manifest, engineOptions);

            var detectorEngine = new DetectorEngine(DefaultDetectorSet.All());
            var ctx = new AnalysisContext
            {
                States = execResult.FinalStates,
                Manifest = manifest,
                SourceHints = sourceHints,
                SmtBackend = smtBackend,
                DropUnsatFindings = opts.SmtDropUnsat,
            };
            var findings = detectorEngine.Run(ctx);
            var risk = RiskProfile.FromFindings(findings);
            var gate = opts.GatePolicy.Evaluate(findings, risk);
            var meta = new AnalysisMeta(
                StatesExplored: execResult.StatesExplored,
                StepsExecuted: execResult.StepsExecuted,
                BudgetExceeded: execResult.BudgetExceeded,
                BudgetReason: execResult.BudgetReason,
                SmtAvailable: smtBackend?.IsAvailable ?? false,
                SmtEngaged: smtBackend?.IsAvailable ?? false);
            var report = new AnalysisReport(findings, risk, gate, meta);

            // Always emit the report before deciding on gate exit code so CI artifacts exist.
            string output = opts.Format switch
            {
                "json" => ReportGenerator.ToJson(report),
                "markdown" or "md" => ReportGenerator.ToMarkdown(report),
                _ => throw new InvalidOperationException($"validated format '{opts.Format}' unexpectedly reached report generation"),
            };
            if (opts.OutputPath is null) Console.WriteLine(output);
            else File.WriteAllText(opts.OutputPath, output);

            if (!gate.Passed)
            {
                Console.Error.WriteLine($"gate failed ({gate.Violations.Length} violation(s))");
                foreach (var v in gate.Violations) Console.Error.WriteLine($"  - {v}");
                return 3;
            }
            return 0;
        }
        finally
        {
            z3Owned?.Dispose();
        }
    }

    private static NeoProgram LoadProgram(string path)
    {
        var bytes = File.ReadAllBytes(path);
        if (path.EndsWith(".nef", StringComparison.OrdinalIgnoreCase))
        {
            var nef = NefFile.Parse(bytes, verifyChecksum: true);
            // Wire MethodToken[] through to the engine so CALLT can pop the right number of
            // parameters and report a concrete target hash (audit M1 fix).
            return ScriptDecoder.Decode(nef.Script).WithTokens(nef.Tokens.ToImmutableArray());
        }
        return ScriptDecoder.Decode(bytes);
    }

    /// <summary>
    /// When a manifest is available, run the engine once per declared ABI entrypoint and merge
    /// the resulting final states. Without this the analyzer only ever runs from offset 0 with
    /// an empty eval stack, which faults at the first INITSLOT/LDARG and surfaces no
    /// telemetry for the detectors. With per-entrypoint runs, each method body is exercised
    /// with one fresh symbolic value per declared parameter.
    /// </summary>
    private static ExecutionResult RunAllManifestEntrypoints(
        NeoProgram program,
        ContractManifest? manifest,
        ExecutionOptions engineOptions)
    {
        if (manifest is null || manifest.Abi.Methods.Count == 0)
            return new SymbolicEngine(program, engineOptions).Run();

        var allStates = ImmutableArray.CreateBuilder<ExecutionState>();
        int totalStatesExplored = 0;
        int totalStepsExecuted = 0;
        bool budgetExceeded = false;
        string? budgetReason = null;
        int skippedOutOfRange = 0;
        foreach (var method in manifest.Abi.Methods)
        {
            if (method.Offset < 0 || method.Offset >= program.Bytes.Length)
            {
                skippedOutOfRange++;
                continue;
            }
            var engine = new SymbolicEngine(program, engineOptions);
            var entry = engine.CreateMethodEntryState(method.Offset, method.Parameters);
            var r = engine.Run(entry);
            allStates.AddRange(r.FinalStates);
            totalStatesExplored += r.StatesExplored;
            totalStepsExecuted += r.StepsExecuted;
            if (r.BudgetExceeded)
            {
                budgetExceeded = true;
                budgetReason ??= r.BudgetReason;
            }
        }

        if (skippedOutOfRange > 0)
            Console.Error.WriteLine(
                $"warning: skipped {skippedOutOfRange} manifest method(s) with offset outside script bytes — "
                + "the manifest may be stale relative to the .nef.");
        if (skippedOutOfRange == manifest.Abi.Methods.Count)
        {
            Console.Error.WriteLine(
                "warning: manifest declared no in-range entrypoints; falling back to single run from offset 0.");
            return new SymbolicEngine(program, engineOptions).Run();
        }

        return new ExecutionResult(
            allStates.ToImmutable(),
            totalStatesExplored,
            totalStepsExecuted,
            budgetExceeded,
            budgetReason);
    }

    private static int Version()
    {
        var asm = typeof(SymbolicEngine).Assembly.GetName();
        Console.WriteLine($"neo-sym {asm.Version}");
        return 0;
    }

    private static int Unknown(string cmd)
    {
        Console.Error.WriteLine($"error: unknown command '{cmd}'");
        PrintUsage();
        return 2;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Neo Symbolic Executor CLI

            Commands:
              neo-sym decode  <path>                  Disassemble a .bin or .nef script.
              neo-sym explore <path>                  Symbolic exploration without detectors.
              neo-sym analyze <path> [options]        Run detectors and emit a report.
              neo-sym version

            analyze options:
              --manifest <path.manifest.json>         Manifest sidecar (enables ABI detectors).
              --source <file-or-dir>                  Optional C# source hints for protocol detectors; repeatable.
              --format json|markdown                  Report format (default: markdown).
              --out <path>                            Write report to file (default: stdout).

              # SMT (optional Z3 backend):
              --smt                                   Engage Z3 for path pruning + finding validation.
              --smt-timeout <ms>                      Per-query timeout (default 5000).
              --smt-bytes-bound <n>                   Max modeled bytes length (default 64).
              --smt-drop-unsat                        Drop findings whose path conditions are UNSAT.

              # Engine budgets (per manifest entrypoint):
              --max-paths <n>                         Cap on terminal paths (default 512).
              --max-steps <n>                         Cap on symbolic steps (default 200000).
              --per-run-deadline-ms <ms>              Wall-clock cap on a single entrypoint run.

              # Gate flags:
              --fail-on-max-severity <sev>            sev in info|low|medium|high|critical
              --fail-on-total-findings <count>
              --fail-on-weighted-score <score>
              --fail-on-confidence-weighted-score <score>
              --fail-on-severity-count <sev>=<count>  Repeatable.
              --fail-on-detector-severity <det>=<sev> Repeatable.
              --min-confidence <sev>=<float>          Repeatable.
            """);
    }
}

internal sealed class AnalyzeOptions
{
    public required string Path { get; init; }
    public string? ManifestPath { get; init; }
    public IReadOnlyList<string> SourcePaths { get; init; } = Array.Empty<string>();
    public string Format { get; init; } = "markdown";
    public string? OutputPath { get; init; }
    public required GatePolicy GatePolicy { get; init; }
    public bool UseSmt { get; init; }
    public int SmtTimeoutMs { get; init; } = 5000;
    public int SmtBytesBound { get; init; } = 64;
    public bool SmtDropUnsat { get; init; }
    /// <summary>Names of SMT-only flags the user passed without --smt. Reported as a warning so
    /// the user does not assume their --smt-* settings took effect.</summary>
    public IReadOnlyList<string> DanglingSmtFlags { get; init; } = Array.Empty<string>();
    public int? MaxPaths { get; init; }
    public int? MaxSteps { get; init; }
    public int? PerRunDeadlineMs { get; init; }

    public static AnalyzeOptions Parse(string[] args)
    {
        if (args.Length < 1) throw new ArgumentException("usage: neo-sym analyze <path> [options]");
        string path = args[0];
        string? manifest = null;
        var sourcePaths = new List<string>();
        string format = "markdown";
        string? outPath = null;
        Severity? maxSev = null;
        int? totalCap = null;
        int? wsCap = null;
        int? cwsCap = null;
        var sevCounts = new Dictionary<Severity, int>();
        var detSev = new Dictionary<string, Severity>();
        var minConf = new Dictionary<Severity, double>();
        bool useSmt = false;
        int smtTimeout = 5000;
        int smtBytes = 64;
        bool smtDrop = false;
        var smtFlagsSeen = new List<string>();
        int? maxPaths = null;
        int? maxSteps = null;
        int? perRunDeadlineMs = null;

        // Audit C# #22 fix: int.Parse on overflow throws System.OverflowException with a
        // generic message. Wrap in a helper that surfaces the option name and bad value.
        for (int i = 1; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => ++i < args.Length
                ? args[i]
                : throw new ArgumentException($"missing value for {a}");
            int ParseInt(string label, string val) =>
                int.TryParse(val, out int n)
                    ? n
                    : throw new ArgumentException($"{label}: expected int32, got '{val}'");
            int ParsePositiveInt(string label, string val)
            {
                int n = ParseInt(label, val);
                return n > 0
                    ? n
                    : throw new ArgumentException($"{label}: expected positive int32, got '{val}'");
            }
            int ParseNonNegativeInt(string label, string val)
            {
                int n = ParseInt(label, val);
                return n >= 0
                    ? n
                    : throw new ArgumentException($"{label}: expected non-negative int32, got '{val}'");
            }
            switch (a)
            {
                case "--manifest": manifest = Next(); break;
                case "--source": sourcePaths.Add(Next()); break;
                case "--format": format = Next(); break;
                case "--out": outPath = Next(); break;
                case "--smt": useSmt = true; break;
                case "--smt-timeout": smtTimeout = ParsePositiveInt(a, Next()); smtFlagsSeen.Add(a); break;
                case "--smt-bytes-bound": smtBytes = ParsePositiveInt(a, Next()); smtFlagsSeen.Add(a); break;
                case "--smt-drop-unsat": smtDrop = true; smtFlagsSeen.Add(a); break;
                case "--max-paths": maxPaths = ParsePositiveInt(a, Next()); break;
                case "--max-steps": maxSteps = ParsePositiveInt(a, Next()); break;
                case "--per-run-deadline-ms": perRunDeadlineMs = ParsePositiveInt(a, Next()); break;
                case "--fail-on-max-severity": maxSev = ParseSeverity(Next()); break;
                case "--fail-on-total-findings": totalCap = ParseNonNegativeInt(a, Next()); break;
                case "--fail-on-weighted-score": wsCap = ParseNonNegativeInt(a, Next()); break;
                case "--fail-on-confidence-weighted-score": cwsCap = ParseNonNegativeInt(a, Next()); break;
                case "--fail-on-severity-count":
                    {
                        var parts = Next().Split('=', 2);
                        if (parts.Length != 2) throw new ArgumentException("expected sev=count");
                        sevCounts[ParseSeverity(parts[0])] = ParseNonNegativeInt(a, parts[1]);
                        break;
                    }
                case "--fail-on-detector-severity":
                    {
                        var parts = Next().Split('=', 2);
                        if (parts.Length != 2) throw new ArgumentException("expected detector=sev");
                        detSev[parts[0]] = ParseSeverity(parts[1]);
                        break;
                    }
                case "--min-confidence":
                    {
                        var parts = Next().Split('=', 2);
                        if (parts.Length != 2) throw new ArgumentException("expected sev=float");
                        if (!double.TryParse(parts[1], System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out double f)
                            || f < 0 || f > 1)
                            throw new ArgumentException($"invalid confidence floor '{parts[1]}'");
                        minConf[ParseSeverity(parts[0])] = f;
                        break;
                    }
                default:
                    throw new ArgumentException($"unknown option '{a}'");
            }
        }

        if (format is not ("json" or "markdown" or "md"))
            throw new ArgumentException($"unknown --format '{format}'; expected json|markdown");

        return new AnalyzeOptions
        {
            Path = path,
            ManifestPath = manifest,
            SourcePaths = sourcePaths.ToArray(),
            Format = format,
            OutputPath = outPath,
            UseSmt = useSmt,
            SmtTimeoutMs = smtTimeout,
            SmtBytesBound = smtBytes,
            SmtDropUnsat = smtDrop,
            DanglingSmtFlags = useSmt ? Array.Empty<string>() : smtFlagsSeen,
            MaxPaths = maxPaths,
            MaxSteps = maxSteps,
            PerRunDeadlineMs = perRunDeadlineMs,
            GatePolicy = new GatePolicy
            {
                FailOnMaxSeverity = maxSev,
                FailOnTotalFindings = totalCap,
                FailOnWeightedScore = wsCap,
                FailOnConfidenceWeightedScore = cwsCap,
                FailOnSeverityCount = sevCounts.Count > 0 ? sevCounts : null,
                FailOnDetectorSeverity = detSev.Count > 0 ? detSev : null,
                MinConfidence = minConf.Count > 0 ? minConf : null,
            },
        };
    }

    private static Severity ParseSeverity(string s) => s.ToLowerInvariant() switch
    {
        "info" => Severity.Info,
        "low" => Severity.Low,
        "medium" => Severity.Medium,
        "high" => Severity.High,
        "critical" => Severity.Critical,
        _ => throw new ArgumentException($"unknown severity '{s}'"),
    };
}
