using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Neo.SymbolicExecutor;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Verification;

namespace Neo.SymbolicExecutor.Cli;

internal static class Program
{
    private const long MaxNefFileBytes = 1_048_576;

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
        // --verbose / NEO_SYM_VERBOSE preserves stack traces on the error path. Off by default
        // because end-user error output should be one short line; on for triage.
        bool verbose = args.Contains("--verbose")
            || string.Equals(Environment.GetEnvironmentVariable("NEO_SYM_VERBOSE"), "1", StringComparison.Ordinal);
        if (verbose)
            args = args.Where(a => a != "--verbose").ToArray();
        try
        {
            return args[0] switch
            {
                "decode" => Decode(args[1..]),
                "explore" => Explore(args[1..]),
                "analyze" => Analyze(args[1..]),
                "verify" => Verify(args[1..]),
                "version" => Version(),
                _ => Unknown(args[0]),
            };
        }
        catch (ArgumentException aex)
        {
            Console.Error.WriteLine($"error: {aex.Message}");
            if (verbose) Console.Error.WriteLine(aex);
            return 2;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"error: {ex.Message}");
            if (verbose) Console.Error.WriteLine(ex);
            return 1;
        }
    }

    private static int Decode(string[] args)
    {
        if (args.Length != 1) throw new ArgumentException("usage: neo-sym decode <script.bin|.nef>");
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
        if (args.Length != 1) throw new ArgumentException("usage: neo-sym explore <script.bin|.nef>");
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
        // Review fix (#78): also protect the `--source` hint paths from an `--out` collision, matching
        // the thoroughness of the verify-side checks (verify has no --source option).
        RejectOutputPathCollisions(
            "--out",
            opts.OutputPath,
            new[] { opts.Path }
                .Concat(opts.ManifestPath is null ? Array.Empty<string>() : new[] { opts.ManifestPath })
                .Concat(opts.SourcePaths));
        var program = LoadProgram(opts.Path);
        ContractManifest? manifest = null;
        if (opts.ManifestPath is not null)
            manifest = ContractManifest.FromFile(opts.ManifestPath);
        SourceHints? sourceHints = opts.SourcePaths.Count > 0
            ? SourceHints.FromPaths(opts.SourcePaths)
            : null;
        if (sourceHints is not null)
        {
            // Diagnostic stderr line so users who pass --source know the scan actually picked up
            // method bodies. A 0 here usually means the path resolved to a directory with no .cs
            // files, or that everything was filtered by the generated/dependency-dir skiplist.
            var inv = System.Globalization.CultureInfo.InvariantCulture;
            Console.Error.WriteLine(
                $"neo-sym: source hints loaded — {sourceHints.MethodNameCount.ToString(inv)} method name(s), {sourceHints.MethodBodyCount.ToString(inv)} body/bodies indexed");
        }

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
                MaxQueuedStates = opts.MaxQueuedStates ?? defaults.MaxQueuedStates,
                MaxVisitsPerOffset = opts.MaxVisitsPerOffset ?? defaults.MaxVisitsPerOffset,
                MaxConcretizations = opts.MaxConcretizations ?? defaults.MaxConcretizations,
                MaxStackSize = opts.MaxStackSize ?? defaults.MaxStackSize,
                MaxInvocationStackDepth = opts.MaxInvocationStackDepth ?? defaults.MaxInvocationStackDepth,
                MaxTryDepth = opts.MaxTryDepth ?? defaults.MaxTryDepth,
                MaxItemSize = opts.MaxItemSize ?? defaults.MaxItemSize,
                MaxCollectionSize = opts.MaxCollectionSize ?? defaults.MaxCollectionSize,
                MaxHeapObjects = opts.MaxHeapObjects ?? defaults.MaxHeapObjects,
                MaxShiftCount = opts.MaxShiftCount ?? defaults.MaxShiftCount,
                MaxPowExponent = opts.MaxPowExponent ?? defaults.MaxPowExponent,
                SelfCallResolver = manifest is null
                    ? null
                    : ManifestSelfCallResolver.Build(manifest),
            };
            var execResult = RunAllManifestEntrypoints(program, manifest, engineOptions, opts.MaxEntrypoints);

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
            var gate = opts.GatePolicy.Evaluate(
                findings,
                risk,
                execResult.BudgetExceeded,
                execResult.CoverageIncomplete,
                execResult.CoverageReason);
            var meta = new AnalysisMeta(
                StatesExplored: execResult.StatesExplored,
                StepsExecuted: execResult.StepsExecuted,
                BudgetExceeded: execResult.BudgetExceeded,
                BudgetReason: execResult.BudgetReason,
                CoverageIncomplete: execResult.CoverageIncomplete,
                CoverageReason: execResult.CoverageReason,
                // SmtAvailable reflects whether the high-precision external solver actually ran;
                // SmtEngaged reflects whether the user asked for SMT. These differ when --smt
                // is passed on a machine without z3 (engaged=true, available=false). Reporting
                // both keeps CI consumers honest about which solver verdict they got.
                SmtAvailable: smtBackend?.IsExternalSolver ?? false,
                SmtEngaged: opts.UseSmt)
            {
                SmtStats = smtBackend?.GetStats(),
                SkippedEntrypoints = execResult.SkippedEntrypoints.IsDefault
                    ? ImmutableArray<string>.Empty
                    : execResult.SkippedEntrypoints,
            };
            var report = new AnalysisReport(findings, risk, gate, meta);

            // Always emit the report before deciding on gate exit code so CI artifacts exist.
            string output = opts.Format switch
            {
                "json" => ReportGenerator.ToJson(report),
                "markdown" or "md" => ReportGenerator.ToMarkdown(report),
                _ => throw new InvalidOperationException($"validated format '{opts.Format}' unexpectedly reached report generation"),
            };
            if (opts.OutputPath is null)
            {
                Console.WriteLine(output);
            }
            else
            {
                // Auto-create the parent directory so users can pass `--out reports/foo.json`
                // without first mkdir-ing reports/. The DevPack targets file already MakeDirs
                // its output dir; this just brings the standalone CLI to parity.
                string? parent = Path.GetDirectoryName(opts.OutputPath);
                if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
                File.WriteAllText(opts.OutputPath, output);
            }

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

    private static int Verify(string[] args)
    {
        var opts = VerifyOptions.Parse(args);
        var dependencyProofArtifactPaths = opts.DependencyProofArtifacts
            .SelectMany(binding => new[] { binding.ProgramPath, binding.ManifestPath })
            .ToArray();
        var inputPaths = new[] { opts.Path, opts.ManifestPath }
            .Concat(opts.SpecPath is null ? Array.Empty<string>() : new[] { opts.SpecPath })
            .Concat(opts.DependencyProofSummaryPaths)
            .Concat(dependencyProofArtifactPaths);
        RejectOutputPathCollisions("--out", opts.OutputPath, inputPaths);
        RejectOutputPathCollisions(
            "--emit-dependency-proof-summary",
            opts.EmitDependencyProofSummaryPath,
            opts.OutputPath is null ? inputPaths : inputPaths.Concat(new[] { opts.OutputPath }));
        ContractManifest manifest;
        try
        {
            manifest = ContractManifest.FromFile(opts.ManifestPath);
        }
        catch (FormatException ex)
        {
            var invalidManifestReport = BuildManifestFormatViolationReport(opts, ex);
            WriteVerificationReport(opts, invalidManifestReport);
            Console.Error.WriteLine($"verification gate failed ({invalidManifestReport.GateEvaluation!.Violations.Length} violation(s))");
            foreach (var violation in invalidManifestReport.GateEvaluation.Violations)
                Console.Error.WriteLine($"  - {violation}");
            return 3;
        }

        var spec = (opts.SpecPath is null
                ? VerificationSpec.Empty
                : VerificationSpec.FromFile(opts.SpecPath))
            .WithAdditionalProfiles(opts.ProfileNames);

        using var smt = new Smt.Z3.Z3Backend(opts.SmtTimeoutMs, opts.SmtBytesBound);
        if (smt.Version.StartsWith("portable fallback", StringComparison.Ordinal))
            Console.Error.WriteLine("warning: verify using portable SMT fallback; install z3 or set NEO_SYMBOLIC_EXECUTOR_Z3 for full SMT-LIB solving");

        var defaults = ExecutionOptions.Default;
        var engineOptions = new ExecutionOptions
        {
            SmtBackend = smt,
            MaxPaths = opts.MaxPaths ?? defaults.MaxPaths,
            MaxSteps = opts.MaxSteps ?? defaults.MaxSteps,
            PerRunDeadline = opts.PerRunDeadlineMs is int ms
                ? System.TimeSpan.FromMilliseconds(ms)
                : defaults.PerRunDeadline,
            MaxQueuedStates = opts.MaxQueuedStates ?? defaults.MaxQueuedStates,
            MaxVisitsPerOffset = opts.MaxVisitsPerOffset ?? defaults.MaxVisitsPerOffset,
            MaxConcretizations = opts.MaxConcretizations ?? defaults.MaxConcretizations,
            MaxStackSize = opts.MaxStackSize ?? defaults.MaxStackSize,
            MaxInvocationStackDepth = opts.MaxInvocationStackDepth ?? defaults.MaxInvocationStackDepth,
            MaxTryDepth = opts.MaxTryDepth ?? defaults.MaxTryDepth,
            MaxItemSize = opts.MaxItemSize ?? defaults.MaxItemSize,
            MaxCollectionSize = opts.MaxCollectionSize ?? defaults.MaxCollectionSize,
            MaxHeapObjects = opts.MaxHeapObjects ?? defaults.MaxHeapObjects,
            MaxShiftCount = opts.MaxShiftCount ?? defaults.MaxShiftCount,
            MaxPowExponent = opts.MaxPowExponent ?? defaults.MaxPowExponent,
        };

        NeoProgram program;
        VerificationContractIdentity contractIdentity;
        try
        {
            program = LoadProgram(opts.Path);
            contractIdentity = BuildContractIdentity(opts.Path, manifest, opts.DeploySenderHash);
        }
        catch (FormatException ex) when (IsProgramFormatViolation(opts.Path, ex))
        {
            var invalidProgramReport = BuildProgramFormatViolationReport(opts, manifest, spec, engineOptions, smt, ex);
            WriteVerificationReport(opts, invalidProgramReport);
            Console.Error.WriteLine($"verification gate failed ({invalidProgramReport.GateEvaluation!.Violations.Length} violation(s))");
            foreach (var violation in invalidProgramReport.GateEvaluation.Violations)
                Console.Error.WriteLine($"  - {violation}");
            return 3;
        }

        if (opts.EmitDependencyProofSummaryPath is not null && contractIdentity.ContractHash is null)
        {
            throw new ArgumentException(
                "--emit-dependency-proof-summary requires a .nef input and --deploy-sender-hash so the Neo N3 dependency contract hash is known");
        }

        if (opts.DependencyProofSummaryPaths.Count != 0
            && opts.TrustDependencyProofSummaries
            && opts.DependencyProofArtifacts.Count == 0
            && !opts.AllowUnboundDependencyProofSummaries)
        {
            var dependencyProofInputReport = BuildDependencyProofInputViolationReport(
                opts,
                spec,
                engineOptions,
                smt,
                contractIdentity,
                "--trust-dependency-proof-summaries requires at least one --dependency-proof-artifact <hash=program,manifest>; "
                + "pass --allow-unbound-dependency-proof-summaries only for legacy summaries whose artifacts were verified outside neo-sym");
            WriteVerificationReport(opts, dependencyProofInputReport);
            Console.Error.WriteLine($"verification gate failed ({dependencyProofInputReport.GateEvaluation!.Violations.Length} violation(s))");
            foreach (var violation in dependencyProofInputReport.GateEvaluation.Violations)
                Console.Error.WriteLine($"  - {violation}");
            return 3;
        }

        DependencyProofSummarySet dependencyProofs;
        try
        {
            dependencyProofs = DependencyProofSummarySet.FromFiles(
                opts.DependencyProofSummaryPaths,
                trustedForExternalCalls: opts.TrustDependencyProofSummaries,
                artifactBindings: opts.DependencyProofArtifacts);
        }
        catch (FormatException ex)
        {
            var dependencyProofInputReport = BuildDependencyProofInputViolationReport(
                opts,
                spec,
                engineOptions,
                smt,
                contractIdentity,
                ex.Message);
            WriteVerificationReport(opts, dependencyProofInputReport);
            Console.Error.WriteLine($"verification gate failed ({dependencyProofInputReport.GateEvaluation!.Violations.Length} violation(s))");
            foreach (var violation in dependencyProofInputReport.GateEvaluation.Violations)
                Console.Error.WriteLine($"  - {violation}");
            return 3;
        }

        byte[]? contractHash = contractIdentity.ContractHash is { } hash
            ? Convert.FromHexString(hash)
            : null;
        var report = FormalVerifier.Verify(
            program,
            manifest,
            spec,
            engineOptions,
            smt,
            opts.MaxEntrypoints,
            contractHash,
            dependencyProofs,
            requireExternalSmtDependencyProofs: opts.RequireExternalSmt);
        report = AddContractIdentityProfileCoverage(report, spec, contractIdentity);
        bool unproved = report.Summary.Violated > 0
            || report.Summary.Unknown > 0
            || report.Summary.Incomplete > 0;
        bool externalSmtRequiredButMissing = opts.RequireExternalSmt && !smt.IsExternalSolver;
        bool unqualifiedProofsRequiredButMissing = opts.RequireUnqualifiedProofs
            && report.Summary.ProvedWithAssumptions > 0;
        var gateViolations = ImmutableArray.CreateBuilder<string>();
        if (report.Summary.Total == 0)
            gateViolations.Add("verification produced zero proof results; check --spec or --profile inputs");
        if (opts.FailOnUnproved && unproved)
        {
            gateViolations.Add(
                $"unproved verification results: proved={report.Summary.Proved}, violated={report.Summary.Violated}, "
                + $"unknown={report.Summary.Unknown}, incomplete={report.Summary.Incomplete}");
        }
        // Review fix (#8): a Violated result is a counterexample-backed proven-UNSAFE path — the
        // semantic opposite of "unproved". `--allow-unproved` (FailOnUnproved=false) is meant to
        // tolerate Unknown/Incomplete coverage only; it must NEVER silence a proven violation.
        // Fail the gate on any violation independently of FailOnUnproved so the build-breaking gate
        // cannot pass on a contract with a known counterexample-backed reachable fault/violation.
        if (!opts.FailOnUnproved && report.Summary.Violated > 0)
        {
            gateViolations.Add(
                $"verification found {report.Summary.Violated} violated (proven-unsafe) result(s) with counterexample(s); "
                + "--allow-unproved tolerates incomplete/unknown coverage but never tolerates a proven violation");
        }
        // Review fix (#49): belt-and-suspenders — fail the gate directly on Meta-level
        // CoverageIncomplete/BudgetExceeded so a passing gate structurally implies complete, in-budget
        // coverage even if a future obligation builder neglects to emit an Incomplete result. This is
        // redundant with the unproved (Incomplete>0) check today (every execution-based obligation
        // funnels through IncompleteReasons), but removes the latent fragility where
        // Meta.CoverageIncomplete could be true while the gate passes. Only adds a violation in the
        // otherwise-missed case (when `unproved` did not already fire).
        if (opts.FailOnUnproved && !unproved
            && (report.Meta.CoverageIncomplete || report.Meta.BudgetExceeded))
        {
            gateViolations.Add(
                "verification meta reports incomplete coverage or exceeded budget without a corresponding "
                + "incomplete result; failing closed");
        }
        if (externalSmtRequiredButMissing)
            gateViolations.Add("external SMT solver required but verify used the portable fallback");
        if (unqualifiedProofsRequiredButMissing)
            gateViolations.Add(
                $"unqualified proofs required but {report.Summary.ProvedWithAssumptions} result(s) were proved only under explicit assumptions");

        var gate = new VerificationGateEvaluation(
            Passed: gateViolations.Count == 0,
            Policies: new VerificationGatePolicy(
                FailOnUnproved: opts.FailOnUnproved,
                RequireExternalSmt: opts.RequireExternalSmt,
                RequireUnqualifiedProofs: opts.RequireUnqualifiedProofs),
            Unproved: unproved,
            ExternalSmtRequiredButMissing: externalSmtRequiredButMissing,
            Violations: gateViolations.ToImmutable(),
            AssumptionBackedProofs: report.Summary.ProvedWithAssumptions);
        report = report with
        {
            Meta = report.Meta with
            {
                Inputs = BuildVerificationInputProvenance(opts),
                SmtSolverVersion = smt.Version,
                SmtTimeoutMs = opts.SmtTimeoutMs,
                SmtBytesBound = opts.SmtBytesBound,
                RequireExternalSmt = opts.RequireExternalSmt,
                EngineOptions = VerificationEngineOptions.From(engineOptions),
                ContractIdentity = contractIdentity,
            },
            GateEvaluation = gate,
        };
        WriteVerificationReport(opts, report);

        if (gate.Passed && opts.EmitDependencyProofSummaryPath is { } proofSummaryPath)
        {
            var summary = DependencyProofSummarySet.FromVerifiedContract(
                manifest,
                contractIdentity.ContractHash!,
                report);
            if (summary.IsEmpty)
            {
                throw new InvalidOperationException(
                    "no ABI method has unqualified proved security.vm_surface, security.vm_fault_free, and security.abi_return_type profile results; run with --profile neo-n3-security and fix unproved profile results before emitting a dependency proof summary");
            }

            string? parent = Path.GetDirectoryName(proofSummaryPath);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            File.WriteAllText(proofSummaryPath, summary.ToJson());
        }

        if (!gate.Passed)
        {
            Console.Error.WriteLine($"verification gate failed ({gate.Violations.Length} violation(s))");
            foreach (var violation in gate.Violations)
                Console.Error.WriteLine($"  - {violation}");
            return 3;
        }
        return 0;
    }

    private static bool IsProgramFormatViolation(string path, FormatException ex) =>
        path.EndsWith(".nef", StringComparison.OrdinalIgnoreCase);

    private static VerificationReport BuildProgramFormatViolationReport(
        VerifyOptions opts,
        ContractManifest manifest,
        VerificationSpec spec,
        ExecutionOptions engineOptions,
        Smt.ISmtBackend smt,
        FormatException ex)
    {
        string reason = ProgramFormatViolationReason(ex);
        var results = ImmutableArray.CreateBuilder<VerificationPropertyResult>();

        foreach (var property in spec.Properties)
        {
            results.Add(new VerificationPropertyResult(
                property.Id,
                property.Method,
                property.Description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: reason,
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: property.MethodOffset));
        }

        if (spec.Profiles.Any(profile => string.Equals(profile, "neo-n3-security", StringComparison.OrdinalIgnoreCase)))
        {
            foreach (var method in manifest.Abi.Methods.Take(opts.MaxEntrypoints))
            {
                string id = ProfileMethodResultId(manifest, method, $"security.vm_fault_free.{method.Name}");
                results.Add(new VerificationPropertyResult(
                    id,
                    method.Name,
                    "Every ABI entrypoint path must avoid reachable NeoVM and syscall faults.",
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: 1,
                    Reason: reason,
                    FailedCondition: ProgramFormatViolationFailedCondition(ex),
                    Counterexample: null,
                    MethodOffset: method.Offset,
                    SourceProfile: "neo-n3-security"));
            }
        }

        var immutableResults = results.ToImmutable();
        var summary = VerificationSummary.FromResults(immutableResults);
        var gateViolations = ImmutableArray.CreateBuilder<string>();
        gateViolations.Add($"program failed Neo N3 NEF validation: {reason}");
        bool externalSmtRequiredButMissing = opts.RequireExternalSmt && !smt.IsExternalSolver;
        if (externalSmtRequiredButMissing)
            gateViolations.Add("external SMT solver required but verify used the portable fallback");

        var gate = new VerificationGateEvaluation(
            Passed: false,
            Policies: new VerificationGatePolicy(
                FailOnUnproved: opts.FailOnUnproved,
                RequireExternalSmt: opts.RequireExternalSmt,
                RequireUnqualifiedProofs: opts.RequireUnqualifiedProofs),
            Unproved: true,
            ExternalSmtRequiredButMissing: externalSmtRequiredButMissing,
            Violations: gateViolations.ToImmutable(),
            AssumptionBackedProofs: summary.ProvedWithAssumptions);

        var meta = new VerificationMeta(
            StatesExplored: 0,
            StepsExecuted: 0,
            BudgetExceeded: false,
            BudgetReason: null,
            CoverageIncomplete: true,
            CoverageReason: $"program failed Neo N3 NEF validation: {reason}",
            SmtAvailable: smt.IsExternalSolver,
            SmtEngaged: true,
            SpecVersion: spec.Version)
        {
            Profiles = spec.Profiles,
            SmtStats = smt.GetStats(),
            Inputs = BuildVerificationInputProvenance(opts),
            SmtSolverVersion = smt.Version,
            SmtTimeoutMs = opts.SmtTimeoutMs,
            SmtBytesBound = opts.SmtBytesBound,
            RequireExternalSmt = opts.RequireExternalSmt,
            EngineOptions = VerificationEngineOptions.From(engineOptions),
            ContractIdentity = new VerificationContractIdentity(
                Status: "invalid_nef",
                SourceKind: "nef",
                ManifestName: manifest.Name,
                DeploySenderHash: opts.DeploySenderHash,
                NefChecksum: null,
                NefChecksumHex: null,
                ContractHash: null,
                Reason: reason),
        };

        return new VerificationReport(meta, summary, immutableResults, gate);
    }

    private static string ProgramFormatViolationReason(FormatException ex)
    {
        if (ex.Message.Contains("MethodToken callFlags", StringComparison.Ordinal))
            return $"CALLT MethodToken invalid call flags in NEF metadata: {ex.Message}";
        if (ex.Message.Contains("MethodToken hasReturnValue", StringComparison.Ordinal))
            return $"CALLT MethodToken invalid return metadata in NEF metadata: {ex.Message}";
        if (ex.Message.Contains("MethodToken", StringComparison.Ordinal))
            return $"CALLT MethodToken metadata is not valid Neo N3 NEF: {ex.Message}";
        return $"NEF file is not valid Neo N3 NEF: {ex.Message}";
    }

    private static string ProgramFormatViolationFailedCondition(FormatException ex) =>
        ex.Message.Contains("MethodToken", StringComparison.Ordinal)
            ? "nef.method_token"
            : "nef.format";

    private static string ProfileMethodResultId(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        string id) =>
        manifest.Abi.Methods.Count(m => string.Equals(m.Name, method.Name, StringComparison.Ordinal)) > 1
            ? $"{id}@{method.Offset}"
            : id;

    private static VerificationReport BuildManifestFormatViolationReport(
        VerifyOptions opts,
        FormatException ex)
    {
        string reason = $"manifest failed validation: {ex.Message}";
        var results = ImmutableArray.Create(new VerificationPropertyResult(
            "security.manifest.parse",
            "*",
            "Verification manifest must contain proof-critical Neo N3 ABI metadata.",
            VerificationStatus.Incomplete,
            CheckedPaths: 0,
            IgnoredFaultedPaths: 0,
            StoppedPaths: 0,
            ObligationsChecked: 1,
            Reason: reason,
            FailedCondition: "manifest.parse",
            Counterexample: null));
        var summary = VerificationSummary.FromResults(results);
        var gateViolations = ImmutableArray.Create(reason);
        var gate = new VerificationGateEvaluation(
            Passed: false,
            Policies: new VerificationGatePolicy(
                FailOnUnproved: opts.FailOnUnproved,
                RequireExternalSmt: opts.RequireExternalSmt,
                RequireUnqualifiedProofs: opts.RequireUnqualifiedProofs),
            Unproved: true,
            ExternalSmtRequiredButMissing: false,
            Violations: gateViolations,
            AssumptionBackedProofs: summary.ProvedWithAssumptions);

        var defaults = ExecutionOptions.Default;
        var engineOptions = new ExecutionOptions
        {
            MaxPaths = opts.MaxPaths ?? defaults.MaxPaths,
            MaxSteps = opts.MaxSteps ?? defaults.MaxSteps,
            PerRunDeadline = opts.PerRunDeadlineMs is int ms
                ? System.TimeSpan.FromMilliseconds(ms)
                : defaults.PerRunDeadline,
            MaxQueuedStates = opts.MaxQueuedStates ?? defaults.MaxQueuedStates,
            MaxVisitsPerOffset = opts.MaxVisitsPerOffset ?? defaults.MaxVisitsPerOffset,
            MaxConcretizations = opts.MaxConcretizations ?? defaults.MaxConcretizations,
            MaxStackSize = opts.MaxStackSize ?? defaults.MaxStackSize,
            MaxInvocationStackDepth = opts.MaxInvocationStackDepth ?? defaults.MaxInvocationStackDepth,
            MaxTryDepth = opts.MaxTryDepth ?? defaults.MaxTryDepth,
            MaxItemSize = opts.MaxItemSize ?? defaults.MaxItemSize,
            MaxCollectionSize = opts.MaxCollectionSize ?? defaults.MaxCollectionSize,
            MaxHeapObjects = opts.MaxHeapObjects ?? defaults.MaxHeapObjects,
            MaxShiftCount = opts.MaxShiftCount ?? defaults.MaxShiftCount,
            MaxPowExponent = opts.MaxPowExponent ?? defaults.MaxPowExponent,
        };
        var meta = new VerificationMeta(
            StatesExplored: 0,
            StepsExecuted: 0,
            BudgetExceeded: false,
            BudgetReason: null,
            CoverageIncomplete: true,
            CoverageReason: reason,
            SmtAvailable: false,
            SmtEngaged: true)
        {
            Profiles = opts.ProfileNames.ToImmutableArray(),
            Inputs = BuildVerificationInputProvenance(opts),
            SmtTimeoutMs = opts.SmtTimeoutMs,
            SmtBytesBound = opts.SmtBytesBound,
            RequireExternalSmt = opts.RequireExternalSmt,
            EngineOptions = VerificationEngineOptions.From(engineOptions),
            ContractIdentity = new VerificationContractIdentity(
                Status: "invalid_manifest",
                SourceKind: opts.Path.EndsWith(".nef", StringComparison.OrdinalIgnoreCase) ? "nef" : "raw_script",
                ManifestName: "",
                DeploySenderHash: opts.DeploySenderHash,
                NefChecksum: null,
                NefChecksumHex: null,
                ContractHash: null,
                Reason: reason),
        };

        return new VerificationReport(meta, summary, results, gate);
    }

    private static VerificationReport BuildDependencyProofInputViolationReport(
        VerifyOptions opts,
        VerificationSpec spec,
        ExecutionOptions engineOptions,
        Smt.ISmtBackend smt,
        VerificationContractIdentity contractIdentity,
        string reasonDetail)
    {
        string reason = $"dependency proof input failed validation: {reasonDetail}";
        var results = ImmutableArray.Create(new VerificationPropertyResult(
            "security.dependency_proof.input",
            "*",
            "Dependency proof summaries must be bound to the local audited Neo N3 artifacts before closing external-call obligations.",
            VerificationStatus.Incomplete,
            CheckedPaths: 0,
            IgnoredFaultedPaths: 0,
            StoppedPaths: 0,
            ObligationsChecked: 1,
            Reason: reason,
            FailedCondition: "dependency_proof.input",
            Counterexample: null,
            SourceProfile: "neo-n3-security"));
        var summary = VerificationSummary.FromResults(results);
        bool externalSmtRequiredButMissing = opts.RequireExternalSmt && !smt.IsExternalSolver;
        var gateViolations = ImmutableArray.CreateBuilder<string>();
        gateViolations.Add(reason);
        if (externalSmtRequiredButMissing)
            gateViolations.Add("external SMT solver required but verify used the portable fallback");

        var gate = new VerificationGateEvaluation(
            Passed: false,
            Policies: new VerificationGatePolicy(
                FailOnUnproved: opts.FailOnUnproved,
                RequireExternalSmt: opts.RequireExternalSmt,
                RequireUnqualifiedProofs: opts.RequireUnqualifiedProofs),
            Unproved: true,
            ExternalSmtRequiredButMissing: externalSmtRequiredButMissing,
            Violations: gateViolations.ToImmutable(),
            AssumptionBackedProofs: summary.ProvedWithAssumptions);

        var meta = new VerificationMeta(
            StatesExplored: 0,
            StepsExecuted: 0,
            BudgetExceeded: false,
            BudgetReason: null,
            CoverageIncomplete: true,
            CoverageReason: reason,
            SmtAvailable: smt.IsExternalSolver,
            SmtEngaged: true,
            SpecVersion: spec.Version)
        {
            Profiles = spec.Profiles,
            SmtStats = smt.GetStats(),
            Inputs = BuildVerificationInputProvenance(opts),
            SmtSolverVersion = smt.Version,
            SmtTimeoutMs = opts.SmtTimeoutMs,
            SmtBytesBound = opts.SmtBytesBound,
            RequireExternalSmt = opts.RequireExternalSmt,
            EngineOptions = VerificationEngineOptions.From(engineOptions),
            ContractIdentity = contractIdentity,
        };

        return new VerificationReport(meta, summary, results, gate);
    }

    private static VerificationInputProvenance BuildVerificationInputProvenance(VerifyOptions opts) =>
        new(
            ProgramPath: opts.Path,
            ProgramSha256: Sha256File(opts.Path),
            ManifestPath: opts.ManifestPath,
            ManifestSha256: Sha256File(opts.ManifestPath),
            SpecPath: opts.SpecPath,
            SpecSha256: opts.SpecPath is null ? null : Sha256File(opts.SpecPath),
            DependencyProofSummaries: opts.DependencyProofSummaryPaths
                .Select(path => new VerificationDependencyProofSummaryProvenance(path, Sha256File(path)))
                .ToImmutableArray(),
            DependencyProofArtifacts: opts.DependencyProofArtifacts
                .Select(binding => new VerificationDependencyProofArtifactProvenance(
                    "0x" + ContractIdentity.NormalizeUInt160LittleEndianHex(binding.ContractHash),
                    binding.ProgramPath,
                    Sha256File(binding.ProgramPath),
                    binding.ManifestPath,
                    Sha256File(binding.ManifestPath)))
                .ToImmutableArray(),
            DependencyProofPolicy: opts.DependencyProofSummaryPaths.Count == 0
                ? null
                : new VerificationDependencyProofPolicy(
                    TrustedForExternalCalls: opts.TrustDependencyProofSummaries,
                    ArtifactBindingRequired: opts.TrustDependencyProofSummaries
                        && !opts.AllowUnboundDependencyProofSummaries,
                    UnboundSummariesAllowed: opts.AllowUnboundDependencyProofSummaries));

    private static void WriteVerificationReport(VerifyOptions opts, VerificationReport report)
    {
        string output = opts.Format switch
        {
            "json" => VerificationReportRenderer.ToJson(report),
            "markdown" or "md" => VerificationReportRenderer.ToMarkdown(report),
            _ => throw new InvalidOperationException($"validated format '{opts.Format}' unexpectedly reached verification report generation"),
        };
        if (opts.OutputPath is null)
        {
            Console.WriteLine(output);
        }
        else
        {
            string? parent = Path.GetDirectoryName(opts.OutputPath);
            if (!string.IsNullOrEmpty(parent)) Directory.CreateDirectory(parent);
            File.WriteAllText(opts.OutputPath, output);
        }
    }

    private static void RejectOutputPathCollisions(
        string optionName,
        string? outputPath,
        IEnumerable<string> protectedPaths)
    {
        if (string.IsNullOrWhiteSpace(outputPath))
            return;

        if (Path.Exists(outputPath))
        {
            throw new ArgumentException(
                $"{optionName} path must not already exist; choose a fresh output path to avoid overwriting input or sibling output artifacts");
        }

        var outputAliases = PathAliases(outputPath).ToArray();
        var comparer = OperatingSystem.IsWindows()
            ? StringComparer.OrdinalIgnoreCase
            : StringComparer.Ordinal;
        foreach (string protectedPath in protectedPaths.Where(path => !string.IsNullOrWhiteSpace(path)))
        {
            var protectedAliases = PathAliases(protectedPath).ToArray();
            if (outputAliases.Any(outputAlias => protectedAliases.Any(protectedAlias =>
                    comparer.Equals(outputAlias, protectedAlias))))
            {
                throw new ArgumentException(
                    $"{optionName} path must not overwrite input or sibling output artifact '{protectedPath}'");
            }
        }
    }

    private static IEnumerable<string> PathAliases(string path)
    {
        yield return Path.GetFullPath(path);

        FileSystemInfo? resolved = null;
        try
        {
            if (File.Exists(path))
                resolved = File.ResolveLinkTarget(path, returnFinalTarget: true);
            else if (Directory.Exists(path))
                resolved = Directory.ResolveLinkTarget(path, returnFinalTarget: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }

        if (resolved is not null)
            yield return Path.GetFullPath(resolved.FullName);
    }

    private static string Sha256File(string path) =>
        Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant();

    private static VerificationContractIdentity BuildContractIdentity(
        string programPath,
        ContractManifest manifest,
        string? deploySenderHash)
    {
        if (!programPath.EndsWith(".nef", StringComparison.OrdinalIgnoreCase))
        {
            return new VerificationContractIdentity(
                Status: "raw_script",
                SourceKind: "raw_script",
                ManifestName: manifest.Name,
                DeploySenderHash: null,
                NefChecksum: null,
                NefChecksumHex: null,
                ContractHash: null,
                Reason: "contract hash requires a NEF input; raw scripts have no NEF checksum");
        }

        var nef = NefFile.Parse(File.ReadAllBytes(programPath), verifyChecksum: true);
        string checksumHex = $"0x{nef.Checksum:x8}";
        if (string.IsNullOrWhiteSpace(deploySenderHash))
        {
            return new VerificationContractIdentity(
                Status: "sender_required",
                SourceKind: "nef",
                ManifestName: manifest.Name,
                DeploySenderHash: null,
                NefChecksum: nef.Checksum,
                NefChecksumHex: checksumHex,
                ContractHash: null,
                Reason: "Neo N3 contract hash depends on the deployment sender; pass --deploy-sender-hash to compute it");
        }

        byte[] sender = ContractIdentity.ParseUInt160LittleEndianHex(deploySenderHash);
        string normalizedSender = ContractIdentity.NormalizeUInt160LittleEndianHex(deploySenderHash);
        string contractHash = ContractIdentity.ComputeContractHashHex(nef, manifest, sender);
        return new VerificationContractIdentity(
            Status: "computed",
            SourceKind: "nef",
            ManifestName: manifest.Name,
            DeploySenderHash: normalizedSender,
            NefChecksum: nef.Checksum,
            NefChecksumHex: checksumHex,
            ContractHash: contractHash,
            Reason: null);
    }

    private static VerificationReport AddContractIdentityProfileCoverage(
        VerificationReport report,
        VerificationSpec spec,
        VerificationContractIdentity contractIdentity)
    {
        bool hasNeoN3SecurityProfile = spec.Profiles.Any(profile =>
            string.Equals(profile, "neo-n3-security", StringComparison.OrdinalIgnoreCase));
        if (!hasNeoN3SecurityProfile || contractIdentity.ContractHash is not null)
        {
            return report;
        }

        string reason = contractIdentity.Reason
            ?? "Neo N3 contract hash is unavailable; pass --deploy-sender-hash to bind the proof to the deployed contract";
        var identityResult = new VerificationPropertyResult(
            Id: "security.contract_identity.*",
            Method: "*",
            Description: "Neo N3 security profile must be bound to a deployed contract hash.",
            Status: VerificationStatus.Incomplete,
            CheckedPaths: 0,
            IgnoredFaultedPaths: 0,
            StoppedPaths: 0,
            ObligationsChecked: 0,
            Reason: reason,
            FailedCondition: null,
            Counterexample: null,
            SourceProfile: "neo-n3-security");

        var results = report.Results.Add(identityResult);
        var summary = VerificationSummary.FromResults(results);
        var coverageReasons = new[] { report.Meta.CoverageReason, reason }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Distinct(StringComparer.Ordinal);
        return report with
        {
            Summary = summary,
            Results = results,
            Meta = report.Meta with
            {
                CoverageIncomplete = true,
                CoverageReason = string.Join("; ", coverageReasons),
            },
        };
    }

    private static NeoProgram LoadProgram(string path)
    {
        bool isNef = path.EndsWith(".nef", StringComparison.OrdinalIgnoreCase);
        EnsureInputFileSize(
            path,
            isNef ? MaxNefFileBytes : ScriptDecoder.MaxRawScriptSize,
            isNef ? "NEF file" : "raw script");
        var bytes = File.ReadAllBytes(path);
        if (isNef)
        {
            var nef = NefFile.Parse(bytes, verifyChecksum: true);
            // Wire MethodToken[] through to the engine so CALLT can pop the right number of
            // parameters and report a concrete target hash (audit M1 fix).
            return ScriptDecoder.Decode(nef.Script).WithTokens(nef.Tokens.ToImmutableArray());
        }
        return ScriptDecoder.Decode(bytes);
    }

    private static void EnsureInputFileSize(string path, long maxBytes, string label)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
            throw new FileNotFoundException($"{label} not found: {path}", path);
        if (info.Length > maxBytes)
            throw new ArgumentException(
                $"{label} '{path}' is {info.Length} bytes, exceeds max {maxBytes} bytes");
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
        ExecutionOptions engineOptions,
        int maxEntrypoints)
    {
        if (manifest is null || manifest.Abi.Methods.Count == 0)
        {
            // Review fix (#23): with no manifest (or a manifest declaring no ABI methods) the engine
            // runs only once from offset 0 with an empty stack. A real DevPack dispatcher faults at
            // INITSLOT before any user code runs, so this single run covers essentially nothing — yet
            // a cleanly-halting offset-0 run previously reported CoverageIncomplete=false and passed
            // the default --fail-on-incomplete-coverage gate. Flag coverage incomplete so the gate
            // fails closed instead of reporting a false-clean pass over a near-empty analysis.
            Console.Error.WriteLine(
                "warning: no manifest ABI methods to analyze; only the offset-0 entry was explored with an empty stack. "
                + "Supply --manifest for per-method DevPack analysis.");
            var single = new SymbolicEngine(program, engineOptions).Run();
            return single with
            {
                CoverageIncomplete = true,
                CoverageReason = manifest is null
                    ? "no manifest supplied; only the offset-0 entry was explored with an empty stack (no ABI entrypoints analyzed)"
                    : "manifest declares no ABI methods; only the offset-0 entry was explored with an empty stack",
            };
        }

        var allStates = ImmutableArray.CreateBuilder<ExecutionState>();
        int totalStatesExplored = 0;
        int totalStepsExecuted = 0;
        bool budgetExceeded = false;
        string? budgetReason = null;
        var skippedEntrypoints = ImmutableArray.CreateBuilder<string>();
        var coverageReasons = new List<string>();
        var methodsToRun = manifest.Abi.Methods.Take(maxEntrypoints).ToArray();
        if (manifest.Abi.Methods.Count > maxEntrypoints)
        {
            var capped = manifest.Abi.Methods.Skip(maxEntrypoints).ToArray();
            foreach (var method in capped)
                skippedEntrypoints.Add($"{method.Name}@{method.Offset}");
            coverageReasons.Add(
                $"manifest declares {manifest.Abi.Methods.Count} ABI method(s), exceeding --max-entrypoints {maxEntrypoints}; "
                + "skipped "
                + string.Join(", ", capped.Select(method => $"{method.Name}@{method.Offset}")));
        }

        foreach (var method in methodsToRun)
        {
            if (ManifestEntrypointCoverageReason(program, method) is { } entrypointCoverageReason)
            {
                skippedEntrypoints.Add($"{method.Name}@{method.Offset}");
                coverageReasons.Add(entrypointCoverageReason);
                continue;
            }
            var entryBuilder = new SymbolicEngine(program, engineOptions);
            foreach (var entry in entryBuilder.CreateMethodEntryStates(method.Offset, method.Parameters))
            {
                var engine = new SymbolicEngine(program, engineOptions);
                var r = engine.Run(entry);
                allStates.AddRange(r.FinalStates);
                totalStatesExplored += r.StatesExplored;
                totalStepsExecuted += r.StepsExecuted;
                if (r.BudgetExceeded)
                {
                    budgetExceeded = true;
                    budgetReason ??= r.BudgetReason;
                }
                if (r.CoverageIncomplete && !string.IsNullOrWhiteSpace(r.CoverageReason))
                    coverageReasons.Add($"{method.Name}@{method.Offset}: {r.CoverageReason}");
            }
        }

        if (skippedEntrypoints.Count > 0)
            coverageReasons.Insert(
                0,
                "skipped manifest entrypoint(s) outside script bytes or not decoded instruction boundaries: "
                + string.Join(", ", skippedEntrypoints.OrderBy(x => x, StringComparer.Ordinal)));

        bool coverageIncomplete = coverageReasons.Count > 0;
        string? coverageReason = coverageIncomplete
            ? string.Join("; ", coverageReasons.Distinct(StringComparer.Ordinal))
            : null;

        if (coverageIncomplete)
            Console.Error.WriteLine(
                $"warning: skipped {skippedEntrypoints.Count} manifest method(s) with stale ABI offset — "
                + "the manifest may be stale relative to the .nef.");
        if (methodsToRun.Length == 0 || methodsToRun.All(method => ManifestEntrypointCoverageReason(program, method) is not null))
        {
            Console.Error.WriteLine(
                "warning: manifest declared no in-range entrypoints; falling back to single run from offset 0.");
            var fallback = new SymbolicEngine(program, engineOptions).Run();
            return fallback with
            {
                CoverageIncomplete = true,
                CoverageReason = coverageReason,
                SkippedEntrypoints = skippedEntrypoints.ToImmutable(),
            };
        }

        return new ExecutionResult(
            allStates.ToImmutable(),
            totalStatesExplored,
            totalStepsExecuted,
            budgetExceeded,
            budgetReason,
            coverageIncomplete,
            coverageReason,
            skippedEntrypoints.ToImmutable());
    }

    private static string? ManifestEntrypointCoverageReason(
        NeoProgram program,
        ContractMethodDescriptor method)
    {
        if (method.Offset < 0 || method.Offset >= program.Bytes.Length)
            return $"manifest method '{method.Name}' offset {method.Offset} is outside script bytes";

        if (!program.IsDecodedInstructionBoundary(method.Offset))
            return $"manifest method '{method.Name}' offset {method.Offset} is not a decoded instruction boundary";

        return null;
    }

    private static int Version()
    {
        // Use the same resolved version that flows into report metadata so `neo-sym version`
        // and report.meta.version are byte-identical (avoids confusing users who see "0.4.0.0"
        // from the CLI but "0.4.0" in the JSON report).
        Console.WriteLine($"neo-sym {AnalysisMeta.CurrentVersion}");
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
              neo-sym verify  <path> [options]        Prove spec properties or emit counterexamples.
              neo-sym version

            Global options:
              --verbose                               Print full stack trace on error
                                                      (also enabled by NEO_SYM_VERBOSE=1).

            analyze options:
              --manifest <path.manifest.json>         Manifest sidecar (enables ABI detectors).
              --source <file-or-dir>                  Optional C# source hints for protocol detectors; repeatable.
              --format json|markdown                  Report format (default: markdown).
              --out <path>                            Write report to file (default: stdout).

              # SMT (external Z3 or portable fallback):
              --smt                                   Engage SMT path pruning + finding validation.
              --smt-timeout <ms>                      Per-query timeout (default 5000).
              --smt-bytes-bound <n>                   Max modeled bytes length (default 64).
              --smt-drop-unsat                        Drop findings whose path conditions are UNSAT.

              # Engine budgets (per manifest entrypoint):
              --max-entrypoints <n>                   Cap manifest ABI entrypoints analyzed/proved by default budget (default 128).
              --max-paths <n>                         Cap on terminal paths (default 512).
              --max-steps <n>                         Cap on symbolic steps (default 200000).
              --per-run-deadline-ms <ms>              Wall-clock cap on a single entrypoint run.
              --max-queued-states <n>                 Cap on worklist size; primary path-explosion escape valve (default 4096; 0 disables).
              --max-visits-per-offset <n>             Cap revisits of the same PC (default 16; cuts tight symbolic loops).
              --max-concretizations <n>               Cap SMT concretizations per state (default 8; 0 disables concretization).
              --max-stack-size <n>                    Eval-stack ceiling (default 2048).
              --max-invocation-stack-depth <n>        Call-frame ceiling (default 1024).
              --max-try-depth <n>                     TRY-frame ceiling (default 16).
              --max-item-size <n>                     Per-item byte ceiling (default 65536).
              --max-collection-size <n>               Compound-collection element ceiling (default 512).
              --max-heap-objects <n>                  Live-heap object ceiling (default 1024).
              --max-shift-count <n>                   SHL/SHR amount ceiling (default 256).
              --max-pow-exponent <n>                  POW exponent ceiling (default 256).

              # Gate flags:
              --fail-on-max-severity <sev>            sev in info|low|medium|high|critical (default: high)
              --fail-on-total-findings <count>
              --fail-on-weighted-score <score>
              --fail-on-confidence-weighted-score <score>
              --fail-on-severity-count <sev>=<count>  Repeatable.
              --fail-on-detector-severity <det>=<sev> Repeatable.
              --min-confidence <sev>=<float>          Repeatable.
              --fail-on-budget-exceeded               Fail when analysis hit a budget cap (default).
              --fail-on-incomplete-coverage           Fail when manifest entrypoints are skipped (default).
              --allow-incomplete-coverage             Do not fail when manifest entrypoints are skipped.

            verify options:
              --manifest <path.manifest.json>         Required manifest sidecar; supplies ABI methods and parameters.
              --spec <path.neo-sym.json>              Formal verification spec; optional when --profile is supplied.
              --profile neo-n3-security               Add a built-in Neo N3 safety proof profile; repeatable.
              --dependency-proof-summary <path.json>   External contract proof summary; repeatable.
              --dependency-proof-artifact <hash=program,manifest>
                                                      Bind a dependency proof summary to local artifact SHA-256 values; repeatable.
              --trust-dependency-proof-summaries       Allow provided summaries to close external-call proofs after out-of-band artifact trust.
              --allow-unbound-dependency-proof-summaries
                                                      Permit trusted summaries without local artifact binding (legacy/offline only).
              --emit-dependency-proof-summary <path>   Write a reusable proof summary for this verified NEF dependency.
              --deploy-sender-hash <hash160>          Optional 20-byte little-endian UInt160 deploy sender for contract hash metadata.
              --format json|markdown                  Verification report format (default: markdown).
              --out <path>                            Write verification report to file (default: stdout).
              --smt-timeout <ms>                      Per-query timeout (default 5000).
              --smt-bytes-bound <n>                   Max modeled bytes length (default 64).
              --require-external-smt                  Fail if z3 is unavailable and portable fallback is used.
              --require-unqualified-proofs            Require unqualified proofs (default; kept for explicit CI policy).
              --allow-assumption-backed-proofs        Do not fail when properties are proved only under explicit assumptions.
              --fail-on-unproved                      Fail on violated, unknown, or incomplete properties (default).
              --allow-unproved                        Emit report but do not fail on unproved properties.
              Engine budget flags above also apply to verify.

            Exit codes:
              0   OK / gate passed
              1   Analyzer error (parse failure, etc.)
              2   Bad arguments
              3   Gate violation
            """);
    }
}

internal static class CliNumericBounds
{
    public const int MaxSmtTimeoutMs = 3_600_000;
    public const int MaxSmtBytesBound = 4_096;
    public const int DefaultMaxEntrypoints = 128;
    public const int MaxEntrypoints = ContractManifest.MaxAbiMethods;
    public const int MaxPaths = 1_000_000;
    public const int MaxSteps = 50_000_000;
    public const int MaxPerRunDeadlineMs = 3_600_000;
    public const int MaxQueuedStates = 1_000_000;
    public const int MaxVisitsPerOffset = 100_000;
    public const int MaxConcretizations = 10_000;
    public const int MaxStackSize = 100_000;
    public const int MaxInvocationStackDepth = 10_000;
    public const int MaxTryDepth = 1_000;
    public const int MaxItemSize = 1_048_576;
    public const int MaxCollectionSize = 100_000;
    public const int MaxHeapObjects = 100_000;
    public const int MaxShiftCount = 4_096;
    public const int MaxPowExponent = 4_096;

    public static int ParseBoundedPositiveInt(string label, string value, int max)
    {
        int n = ParseInt(label, value);
        if (n <= 0)
            throw new ArgumentException($"{label}: expected positive int32, got '{value}'");
        if (n > max)
            throw new ArgumentException($"{label}: expected <= {max}, got '{value}'");
        return n;
    }

    public static int ParseBoundedNonNegativeInt(string label, string value, int max)
    {
        int n = ParseInt(label, value);
        if (n < 0)
            throw new ArgumentException($"{label}: expected non-negative int32, got '{value}'");
        if (n > max)
            throw new ArgumentException($"{label}: expected <= {max}, got '{value}'");
        return n;
    }

    private static int ParseInt(string label, string value) =>
        int.TryParse(value, out int n)
            ? n
            : throw new ArgumentException($"{label}: expected int32, got '{value}'");
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
    public bool FailOnIncompleteCoverage { get; init; } = true;
    /// <summary>Names of SMT-only flags the user passed without --smt. Reported as a warning so
    /// the user does not assume their --smt-* settings took effect.</summary>
    public IReadOnlyList<string> DanglingSmtFlags { get; init; } = Array.Empty<string>();
    public int MaxEntrypoints { get; init; } = CliNumericBounds.DefaultMaxEntrypoints;
    public int? MaxPaths { get; init; }
    public int? MaxSteps { get; init; }
    public int? PerRunDeadlineMs { get; init; }
    public int? MaxQueuedStates { get; init; }
    public int? MaxVisitsPerOffset { get; init; }
    public int? MaxConcretizations { get; init; }
    public int? MaxStackSize { get; init; }
    public int? MaxInvocationStackDepth { get; init; }
    public int? MaxTryDepth { get; init; }
    public int? MaxItemSize { get; init; }
    public int? MaxCollectionSize { get; init; }
    public int? MaxHeapObjects { get; init; }
    public int? MaxShiftCount { get; init; }
    public int? MaxPowExponent { get; init; }

    public static AnalyzeOptions Parse(string[] args)
    {
        if (args.Length < 1) throw new ArgumentException("usage: neo-sym analyze <path> [options]");
        string path = args[0];
        string? manifest = null;
        var sourcePaths = new List<string>();
        string format = "markdown";
        string? outPath = null;
        Severity? maxSev = Severity.High;
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
        bool failOnIncompleteCoverage = true;
        int maxEntrypoints = CliNumericBounds.DefaultMaxEntrypoints;
        int? maxPaths = null;
        int? maxSteps = null;
        int? perRunDeadlineMs = null;
        int? maxQueuedStates = null;
        int? maxVisitsPerOffset = null;
        int? maxConcretizations = null;
        int? maxStackSize = null;
        int? maxInvocationStackDepth = null;
        int? maxTryDepth = null;
        int? maxItemSize = null;
        int? maxCollectionSize = null;
        int? maxHeapObjects = null;
        int? maxShiftCount = null;
        int? maxPowExponent = null;
        bool failOnBudget = true;

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
                case "--smt-timeout": smtTimeout = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxSmtTimeoutMs); smtFlagsSeen.Add(a); break;
                case "--smt-bytes-bound": smtBytes = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxSmtBytesBound); smtFlagsSeen.Add(a); break;
                case "--smt-drop-unsat": smtDrop = true; smtFlagsSeen.Add(a); break;
                case "--allow-incomplete-coverage": failOnIncompleteCoverage = false; break;
                case "--fail-on-incomplete-coverage": failOnIncompleteCoverage = true; break;
                case "--fail-on-budget-exceeded": failOnBudget = true; break;
                case "--max-entrypoints": maxEntrypoints = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxEntrypoints); break;
                case "--max-paths": maxPaths = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxPaths); break;
                case "--max-steps": maxSteps = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxSteps); break;
                case "--per-run-deadline-ms": perRunDeadlineMs = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxPerRunDeadlineMs); break;
                // Concurrency / path-explosion escape valves: when --max-paths fires after
                // millions of states queue up, --max-queued-states is the only thing that
                // bounds peak memory. --max-visits-per-offset cuts tight loops earlier.
                case "--max-queued-states": maxQueuedStates = CliNumericBounds.ParseBoundedNonNegativeInt(a, Next(), CliNumericBounds.MaxQueuedStates); break;
                case "--max-visits-per-offset": maxVisitsPerOffset = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxVisitsPerOffset); break;
                case "--max-concretizations": maxConcretizations = CliNumericBounds.ParseBoundedNonNegativeInt(a, Next(), CliNumericBounds.MaxConcretizations); break;
                // Capacity ceilings — usually leave at defaults; raise only when a real contract
                // legitimately needs more than the conservative analyzer-side bound.
                case "--max-stack-size": maxStackSize = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxStackSize); break;
                case "--max-invocation-stack-depth": maxInvocationStackDepth = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxInvocationStackDepth); break;
                case "--max-try-depth": maxTryDepth = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxTryDepth); break;
                case "--max-item-size": maxItemSize = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxItemSize); break;
                case "--max-collection-size": maxCollectionSize = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxCollectionSize); break;
                case "--max-heap-objects": maxHeapObjects = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxHeapObjects); break;
                case "--max-shift-count": maxShiftCount = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxShiftCount); break;
                case "--max-pow-exponent": maxPowExponent = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxPowExponent); break;
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
            FailOnIncompleteCoverage = failOnIncompleteCoverage,
            DanglingSmtFlags = useSmt ? Array.Empty<string>() : smtFlagsSeen,
            MaxEntrypoints = maxEntrypoints,
            MaxPaths = maxPaths,
            MaxSteps = maxSteps,
            PerRunDeadlineMs = perRunDeadlineMs,
            MaxQueuedStates = maxQueuedStates,
            MaxVisitsPerOffset = maxVisitsPerOffset,
            MaxConcretizations = maxConcretizations,
            MaxStackSize = maxStackSize,
            MaxInvocationStackDepth = maxInvocationStackDepth,
            MaxTryDepth = maxTryDepth,
            MaxItemSize = maxItemSize,
            MaxCollectionSize = maxCollectionSize,
            MaxHeapObjects = maxHeapObjects,
            MaxShiftCount = maxShiftCount,
            MaxPowExponent = maxPowExponent,
            GatePolicy = new GatePolicy
            {
                FailOnMaxSeverity = maxSev,
                FailOnTotalFindings = totalCap,
                FailOnWeightedScore = wsCap,
                FailOnConfidenceWeightedScore = cwsCap,
                FailOnSeverityCount = sevCounts.Count > 0 ? sevCounts : null,
                FailOnDetectorSeverity = detSev.Count > 0 ? detSev : null,
                MinConfidence = minConf.Count > 0 ? minConf : null,
                FailOnBudgetExceeded = failOnBudget,
                FailOnIncompleteCoverage = failOnIncompleteCoverage,
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

internal sealed class VerifyOptions
{
    public required string Path { get; init; }
    public required string ManifestPath { get; init; }
    public string? SpecPath { get; init; }
    public IReadOnlyList<string> ProfileNames { get; init; } = Array.Empty<string>();
    public IReadOnlyList<string> DependencyProofSummaryPaths { get; init; } = Array.Empty<string>();
    public IReadOnlyList<DependencyProofArtifactBinding> DependencyProofArtifacts { get; init; } =
        Array.Empty<DependencyProofArtifactBinding>();
    public bool TrustDependencyProofSummaries { get; init; }
    public bool AllowUnboundDependencyProofSummaries { get; init; }
    public string? EmitDependencyProofSummaryPath { get; init; }
    public string? DeploySenderHash { get; init; }
    public string Format { get; init; } = "markdown";
    public string? OutputPath { get; init; }
    public int SmtTimeoutMs { get; init; } = 5000;
    public int SmtBytesBound { get; init; } = 64;
    public bool RequireExternalSmt { get; init; }
    public bool RequireUnqualifiedProofs { get; init; }
    public bool FailOnUnproved { get; init; } = true;
    public int MaxEntrypoints { get; init; } = CliNumericBounds.DefaultMaxEntrypoints;
    public int? MaxPaths { get; init; }
    public int? MaxSteps { get; init; }
    public int? PerRunDeadlineMs { get; init; }
    public int? MaxQueuedStates { get; init; }
    public int? MaxVisitsPerOffset { get; init; }
    public int? MaxConcretizations { get; init; }
    public int? MaxStackSize { get; init; }
    public int? MaxInvocationStackDepth { get; init; }
    public int? MaxTryDepth { get; init; }
    public int? MaxItemSize { get; init; }
    public int? MaxCollectionSize { get; init; }
    public int? MaxHeapObjects { get; init; }
    public int? MaxShiftCount { get; init; }
    public int? MaxPowExponent { get; init; }

    public static VerifyOptions Parse(string[] args)
    {
        if (args.Length < 1) throw new ArgumentException("usage: neo-sym verify <path> --manifest <manifest.json> (--spec <spec.json>|--profile neo-n3-security) [options]");
        string path = args[0];
        string? manifest = null;
        string? spec = null;
        string? deploySenderHash = null;
        var profiles = new List<string>();
        var dependencyProofSummaries = new List<string>();
        var dependencyProofArtifacts = new List<DependencyProofArtifactBinding>();
        bool trustDependencyProofSummaries = false;
        bool allowUnboundDependencyProofSummaries = false;
        string? emitDependencyProofSummaryPath = null;
        string format = "markdown";
        string? outPath = null;
        int smtTimeout = 5000;
        int smtBytes = 64;
        bool requireExternalSmt = false;
        bool requireUnqualifiedProofs = true;
        bool failOnUnproved = true;
        int maxEntrypoints = CliNumericBounds.DefaultMaxEntrypoints;
        int? maxPaths = null;
        int? maxSteps = null;
        int? perRunDeadlineMs = null;
        int? maxQueuedStates = null;
        int? maxVisitsPerOffset = null;
        int? maxConcretizations = null;
        int? maxStackSize = null;
        int? maxInvocationStackDepth = null;
        int? maxTryDepth = null;
        int? maxItemSize = null;
        int? maxCollectionSize = null;
        int? maxHeapObjects = null;
        int? maxShiftCount = null;
        int? maxPowExponent = null;

        for (int i = 1; i < args.Length; i++)
        {
            string a = args[i];
            string Next() => ++i < args.Length
                ? args[i]
                : throw new ArgumentException($"missing value for {a}");

            switch (a)
            {
                case "--manifest": manifest = Next(); break;
                case "--spec": spec = Next(); break;
                case "--profile": profiles.Add(ValidateProfileName(Next())); break;
                case "--dependency-proof-summary": dependencyProofSummaries.Add(Next()); break;
                case "--dependency-proof-artifact": dependencyProofArtifacts.Add(ParseDependencyProofArtifactBinding(Next())); break;
                case "--trust-dependency-proof-summaries": trustDependencyProofSummaries = true; break;
                case "--allow-unbound-dependency-proof-summaries": allowUnboundDependencyProofSummaries = true; break;
                case "--emit-dependency-proof-summary": emitDependencyProofSummaryPath = Next(); break;
                case "--deploy-sender-hash":
                    deploySenderHash = ContractIdentity.NormalizeUInt160LittleEndianHex(Next());
                    break;
                case "--format": format = Next(); break;
                case "--out": outPath = Next(); break;
                case "--smt-timeout": smtTimeout = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxSmtTimeoutMs); break;
                case "--smt-bytes-bound": smtBytes = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxSmtBytesBound); break;
                case "--require-external-smt":
                case "--fail-on-smt-fallback":
                    requireExternalSmt = true;
                    break;
                case "--require-unqualified-proofs":
                    requireUnqualifiedProofs = true;
                    break;
                case "--allow-assumption-backed-proofs":
                    requireUnqualifiedProofs = false;
                    break;
                case "--fail-on-unproved": failOnUnproved = true; break;
                case "--allow-unproved": failOnUnproved = false; break;
                case "--max-entrypoints": maxEntrypoints = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxEntrypoints); break;
                case "--max-paths": maxPaths = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxPaths); break;
                case "--max-steps": maxSteps = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxSteps); break;
                case "--per-run-deadline-ms": perRunDeadlineMs = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxPerRunDeadlineMs); break;
                case "--max-queued-states": maxQueuedStates = CliNumericBounds.ParseBoundedNonNegativeInt(a, Next(), CliNumericBounds.MaxQueuedStates); break;
                case "--max-visits-per-offset": maxVisitsPerOffset = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxVisitsPerOffset); break;
                case "--max-concretizations": maxConcretizations = CliNumericBounds.ParseBoundedNonNegativeInt(a, Next(), CliNumericBounds.MaxConcretizations); break;
                case "--max-stack-size": maxStackSize = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxStackSize); break;
                case "--max-invocation-stack-depth": maxInvocationStackDepth = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxInvocationStackDepth); break;
                case "--max-try-depth": maxTryDepth = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxTryDepth); break;
                case "--max-item-size": maxItemSize = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxItemSize); break;
                case "--max-collection-size": maxCollectionSize = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxCollectionSize); break;
                case "--max-heap-objects": maxHeapObjects = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxHeapObjects); break;
                case "--max-shift-count": maxShiftCount = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxShiftCount); break;
                case "--max-pow-exponent": maxPowExponent = CliNumericBounds.ParseBoundedPositiveInt(a, Next(), CliNumericBounds.MaxPowExponent); break;
                default:
                    throw new ArgumentException($"unknown option '{a}'");
            }
        }

        if (manifest is null)
            throw new ArgumentException("verify requires --manifest <path.manifest.json>");
        if (spec is null && profiles.Count == 0)
            throw new ArgumentException("verify requires --spec <path.neo-sym.json> or --profile neo-n3-security");
        if (format is not ("json" or "markdown" or "md"))
            throw new ArgumentException($"unknown --format '{format}'; expected json|markdown");

        return new VerifyOptions
        {
            Path = path,
            ManifestPath = manifest,
            SpecPath = spec,
            ProfileNames = profiles.ToArray(),
            DependencyProofSummaryPaths = dependencyProofSummaries.ToArray(),
            DependencyProofArtifacts = dependencyProofArtifacts.ToArray(),
            TrustDependencyProofSummaries = trustDependencyProofSummaries,
            AllowUnboundDependencyProofSummaries = allowUnboundDependencyProofSummaries,
            EmitDependencyProofSummaryPath = emitDependencyProofSummaryPath,
            DeploySenderHash = deploySenderHash,
            Format = format,
            OutputPath = outPath,
            SmtTimeoutMs = smtTimeout,
            SmtBytesBound = smtBytes,
            RequireExternalSmt = requireExternalSmt,
            RequireUnqualifiedProofs = requireUnqualifiedProofs,
            FailOnUnproved = failOnUnproved,
            MaxEntrypoints = maxEntrypoints,
            MaxPaths = maxPaths,
            MaxSteps = maxSteps,
            PerRunDeadlineMs = perRunDeadlineMs,
            MaxQueuedStates = maxQueuedStates,
            MaxVisitsPerOffset = maxVisitsPerOffset,
            MaxConcretizations = maxConcretizations,
            MaxStackSize = maxStackSize,
            MaxInvocationStackDepth = maxInvocationStackDepth,
            MaxTryDepth = maxTryDepth,
            MaxItemSize = maxItemSize,
            MaxCollectionSize = maxCollectionSize,
            MaxHeapObjects = maxHeapObjects,
            MaxShiftCount = maxShiftCount,
            MaxPowExponent = maxPowExponent,
        };
    }

    private static string ValidateProfileName(string profileName)
    {
        string normalized = profileName.Trim();
        if (string.IsNullOrWhiteSpace(normalized))
            throw new ArgumentException("profile names must be non-empty strings");
        return normalized;
    }

    private static DependencyProofArtifactBinding ParseDependencyProofArtifactBinding(string value)
    {
        int equals = value.IndexOf('=');
        if (equals <= 0 || equals == value.Length - 1)
        {
            throw new ArgumentException(
                "--dependency-proof-artifact expects <contract_hash>=<program_path>,<manifest_path>");
        }

        int comma = value.IndexOf(',', equals + 1);
        if (comma <= equals + 1 || comma == value.Length - 1)
        {
            throw new ArgumentException(
                "--dependency-proof-artifact expects <contract_hash>=<program_path>,<manifest_path>");
        }

        string contractHash = value[..equals].Trim();
        string programPath = value[(equals + 1)..comma].Trim();
        string manifestPath = value[(comma + 1)..].Trim();
        if (string.IsNullOrWhiteSpace(contractHash)
            || string.IsNullOrWhiteSpace(programPath)
            || string.IsNullOrWhiteSpace(manifestPath))
        {
            throw new ArgumentException(
                "--dependency-proof-artifact expects <contract_hash>=<program_path>,<manifest_path>");
        }

        return new DependencyProofArtifactBinding(contractHash, programPath, manifestPath);
    }
}
