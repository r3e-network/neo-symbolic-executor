using System.Collections.Immutable;
using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public enum VerificationStatus
{
    Proved,
    Violated,
    Unknown,
    Incomplete,
}

public sealed record VerificationReport(
    VerificationMeta Meta,
    VerificationSummary Summary,
    ImmutableArray<VerificationPropertyResult> Results,
    VerificationGateEvaluation? GateEvaluation = null);

public sealed record VerificationGatePolicy(
    bool FailOnUnproved,
    bool RequireExternalSmt,
    bool RequireUnqualifiedProofs = false)
{
    public bool UnprovedAllowed => !FailOnUnproved;
}

public sealed record VerificationGateEvaluation(
    bool Passed,
    VerificationGatePolicy Policies,
    bool Unproved,
    bool ExternalSmtRequiredButMissing,
    ImmutableArray<string> Violations,
    int AssumptionBackedProofs = 0);

public sealed record VerificationMeta(
    string Tool = "Neo.SymbolicExecutor.Verify",
    int StatesExplored = 0,
    int StepsExecuted = 0,
    bool BudgetExceeded = false,
    string? BudgetReason = null,
    bool CoverageIncomplete = false,
    string? CoverageReason = null,
    bool SmtAvailable = false,
    bool SmtEngaged = false,
    int SpecVersion = 1)
{
    public string Version { get; init; } = CurrentVersion;
    public ImmutableArray<string> Profiles { get; init; } = ImmutableArray<string>.Empty;
    public SmtStats? SmtStats { get; init; }
    public VerificationInputProvenance? Inputs { get; init; }
    public string? SmtSolverVersion { get; init; }
    public int? SmtTimeoutMs { get; init; }
    public int? SmtBytesBound { get; init; }
    public bool RequireExternalSmt { get; init; }
    public VerificationEngineOptions? EngineOptions { get; init; }
    public VerificationContractIdentity? ContractIdentity { get; init; }

    public static readonly string CurrentVersion = ResolveAssemblyVersion();

    private static string ResolveAssemblyVersion()
    {
        var asm = typeof(VerificationMeta).Assembly;
        string? info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (info is not null)
        {
            int plus = info.IndexOf('+');
            if (plus >= 0) info = info[..plus];
            if (info.Length > 0) return info;
        }
        return asm.GetName().Version?.ToString(3) ?? "unknown";
    }
}

public sealed record VerificationInputProvenance(
    string ProgramPath,
    string ProgramSha256,
    string ManifestPath,
    string ManifestSha256,
    string? SpecPath,
    string? SpecSha256,
    ImmutableArray<VerificationDependencyProofSummaryProvenance> DependencyProofSummaries = default,
    ImmutableArray<VerificationDependencyProofArtifactProvenance> DependencyProofArtifacts = default,
    VerificationDependencyProofPolicy? DependencyProofPolicy = null);

public sealed record VerificationDependencyProofSummaryProvenance(
    string Path,
    string Sha256);

public sealed record VerificationDependencyProofPolicy(
    bool TrustedForExternalCalls,
    bool ArtifactBindingRequired,
    bool UnboundSummariesAllowed);

public sealed record VerificationDependencyProofArtifactProvenance(
    string ContractHash,
    string ProgramPath,
    string ProgramSha256,
    string ManifestPath,
    string ManifestSha256);

public sealed record VerificationContractIdentity(
    string Status,
    string SourceKind,
    string ManifestName,
    string? DeploySenderHash,
    long? NefChecksum,
    string? NefChecksumHex,
    string? ContractHash,
    string? Reason);

public sealed record VerificationEngineOptions(
    int MaxPaths,
    int MaxSteps,
    int? PerRunDeadlineMs,
    int MaxQueuedStates,
    int MaxVisitsPerOffset,
    int MaxConcretizations,
    int MaxStackSize,
    int MaxInvocationStackDepth,
    int MaxTryDepth,
    int MaxItemSize,
    int MaxCollectionSize,
    int MaxHeapObjects,
    int MaxShiftCount,
    int MaxPowExponent,
    int InitialCallFlags,
    int DefaultRuntimeTrigger)
{
    public static VerificationEngineOptions From(ExecutionOptions options) =>
        new(
            options.MaxPaths,
            options.MaxSteps,
            options.PerRunDeadline is { } deadline ? (int)deadline.TotalMilliseconds : null,
            options.MaxQueuedStates,
            options.MaxVisitsPerOffset,
            options.MaxConcretizations,
            options.MaxStackSize,
            options.MaxInvocationStackDepth,
            options.MaxTryDepth,
            options.MaxItemSize,
            options.MaxCollectionSize,
            options.MaxHeapObjects,
            options.MaxShiftCount,
            options.MaxPowExponent,
            options.InitialCallFlags,
            options.RuntimeTrigger);
}

public sealed record VerificationSummary(
    int Total,
    int Proved,
    int Violated,
    int Unknown,
    int Incomplete,
    int ProvedWithoutAssumptions = 0,
    int ProvedWithAssumptions = 0)
{
    public bool AllProved => Total > 0 && Proved == Total;
    public bool AllProvedWithoutAssumptions => Total > 0 && ProvedWithoutAssumptions == Total;

    public static VerificationSummary FromResults(IReadOnlyList<VerificationPropertyResult> results) =>
        new(
            results.Count,
            results.Count(r => r.Status == VerificationStatus.Proved),
            results.Count(r => r.Status == VerificationStatus.Violated),
            results.Count(r => r.Status == VerificationStatus.Unknown),
            results.Count(r => r.Status == VerificationStatus.Incomplete),
            results.Count(r => r.Status == VerificationStatus.Proved && r.Assumptions.IsDefaultOrEmpty),
            results.Count(r => r.Status == VerificationStatus.Proved && !r.Assumptions.IsDefaultOrEmpty));
}

public sealed record VerificationPropertyResult(
    string Id,
    string Method,
    string? Description,
    VerificationStatus Status,
    int CheckedPaths,
    int IgnoredFaultedPaths,
    int StoppedPaths,
    int ObligationsChecked,
    string Reason,
    string? FailedCondition,
    ImmutableDictionary<string, object>? Counterexample,
    int? MethodOffset = null,
    ImmutableArray<VerificationAssumption> Assumptions = default,
    string? SourceProfile = null);

public sealed record VerificationAssumption(
    string Id,
    string Description,
    string? Source = null);

public static class VerificationReportRenderer
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
    };

    public static string ToJson(VerificationReport report) =>
        BuildJson(report).ToJsonString(JsonOpts);

    public static string ToMarkdown(VerificationReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Neo Symbolic Executor - Formal Verification Report");
        sb.AppendLine();
        sb.AppendLine($"- **Tool:** {report.Meta.Tool} {report.Meta.Version}");
        sb.AppendLine($"- **States explored:** {report.Meta.StatesExplored}");
        sb.AppendLine($"- **Steps executed:** {report.Meta.StepsExecuted}");
        sb.AppendLine($"- **SMT available:** {report.Meta.SmtAvailable} · **SMT engaged:** {report.Meta.SmtEngaged}");
        if (!string.IsNullOrWhiteSpace(report.Meta.SmtSolverVersion))
            sb.AppendLine($"- **SMT solver:** {Md(report.Meta.SmtSolverVersion)}");
        if (report.Meta.SmtTimeoutMs is int smtTimeoutMs)
            sb.AppendLine($"- **SMT timeout:** `{smtTimeoutMs} ms`");
        if (report.Meta.SmtBytesBound is int smtBytesBound)
            sb.AppendLine($"- **SMT bytes bound:** `{smtBytesBound}`");
        if (report.Meta.EngineOptions is { } engineOptions)
        {
            sb.AppendLine(
                "- **Engine options:** "
                + string.Join(", ", new[]
                {
                    $"max_paths `{engineOptions.MaxPaths}`",
                    $"max_steps `{engineOptions.MaxSteps}`",
                    $"per_run_deadline_ms `{FormatNullableInt(engineOptions.PerRunDeadlineMs)}`",
                    $"max_queued_states `{engineOptions.MaxQueuedStates}`",
                    $"max_visits_per_offset `{engineOptions.MaxVisitsPerOffset}`",
                    $"max_concretizations `{engineOptions.MaxConcretizations}`",
                    $"max_stack_size `{engineOptions.MaxStackSize}`",
                    $"max_invocation_stack_depth `{engineOptions.MaxInvocationStackDepth}`",
                    $"max_try_depth `{engineOptions.MaxTryDepth}`",
                    $"max_item_size `{engineOptions.MaxItemSize}`",
                    $"max_collection_size `{engineOptions.MaxCollectionSize}`",
                    $"max_heap_objects `{engineOptions.MaxHeapObjects}`",
                    $"max_shift_count `{engineOptions.MaxShiftCount}`",
                    $"max_pow_exponent `{engineOptions.MaxPowExponent}`",
                    $"initial_call_flags `{engineOptions.InitialCallFlags}`",
                    $"default_runtime_trigger `{engineOptions.DefaultRuntimeTrigger}`",
                }));
        }
        if (report.Meta.Inputs is { } inputs)
        {
            sb.AppendLine($"- **Program input:** {Md(inputs.ProgramPath)} (`{Md(inputs.ProgramSha256)}`)");
            sb.AppendLine($"- **Program SHA-256:** `{Md(inputs.ProgramSha256)}`");
            sb.AppendLine($"- **Manifest input:** {Md(inputs.ManifestPath)} (`{Md(inputs.ManifestSha256)}`)");
            sb.AppendLine($"- **Manifest SHA-256:** `{Md(inputs.ManifestSha256)}`");
            if (inputs.SpecSha256 is not null)
            {
                sb.AppendLine($"- **Spec input:** {Md(inputs.SpecPath ?? "<none>")} (`{Md(inputs.SpecSha256)}`)");
                sb.AppendLine($"- **Spec SHA-256:** `{Md(inputs.SpecSha256)}`");
            }
            if (!inputs.DependencyProofSummaries.IsDefaultOrEmpty)
            {
                foreach (var summary in inputs.DependencyProofSummaries)
                    sb.AppendLine($"- **Dependency proof summary SHA-256:** `{Md(summary.Sha256)}` ({Md(summary.Path)})");
            }
            if (!inputs.DependencyProofArtifacts.IsDefaultOrEmpty)
            {
                foreach (var artifact in inputs.DependencyProofArtifacts)
                {
                    sb.AppendLine(
                        "- **Dependency proof artifact:** "
                        + $"`{Md(artifact.ContractHash)}` "
                        + $"program `{Md(artifact.ProgramSha256)}` ({Md(artifact.ProgramPath)}), "
                        + $"manifest `{Md(artifact.ManifestSha256)}` ({Md(artifact.ManifestPath)})");
                }
            }
            if (inputs.DependencyProofPolicy is { } dependencyProofPolicy)
            {
                sb.AppendLine(
                    "- **Dependency proof policy:** "
                    + $"trusted `{dependencyProofPolicy.TrustedForExternalCalls}`, "
                    + $"artifact binding required `{dependencyProofPolicy.ArtifactBindingRequired}`, "
                    + $"unbound summaries allowed `{dependencyProofPolicy.UnboundSummariesAllowed}`");
            }
        }
        if (!report.Meta.Profiles.IsDefaultOrEmpty)
            sb.AppendLine($"- **Profiles:** {Md(string.Join(", ", report.Meta.Profiles))}");
        if (report.Meta.ContractIdentity is { } identity)
        {
            sb.AppendLine($"- **Contract identity:** {Md(identity.Status)}");
            if (!string.IsNullOrWhiteSpace(identity.ContractHash))
                sb.AppendLine($"- **Contract hash:** `{Md(identity.ContractHash)}`");
            if (!string.IsNullOrWhiteSpace(identity.DeploySenderHash))
                sb.AppendLine($"- **Deploy sender hash:** `{Md(identity.DeploySenderHash)}`");
            if (!string.IsNullOrWhiteSpace(identity.NefChecksumHex))
                sb.AppendLine($"- **NEF checksum:** `{Md(identity.NefChecksumHex)}`");
            if (!string.IsNullOrWhiteSpace(identity.Reason))
                sb.AppendLine($"- **Contract identity gap:** {Md(identity.Reason)}");
        }
        if (report.GateEvaluation is { } gate)
        {
            sb.AppendLine($"- **Gate passed:** {gate.Passed}");
            sb.AppendLine($"- **Fail on unproved:** {gate.Policies.FailOnUnproved}");
            sb.AppendLine($"- **Require external SMT:** {gate.Policies.RequireExternalSmt}");
            sb.AppendLine($"- **Require unqualified proofs:** {gate.Policies.RequireUnqualifiedProofs}");
            if (gate.AssumptionBackedProofs > 0)
                sb.AppendLine($"- **Assumption-backed proofs:** {gate.AssumptionBackedProofs}");
            if (gate.Violations.Length > 0)
                sb.AppendLine($"- **Gate violations:** {Md(string.Join("; ", gate.Violations))}");
        }
        if (report.Meta.CoverageIncomplete)
            sb.AppendLine($"- **Coverage incomplete:** {Md(report.Meta.CoverageReason ?? "(unspecified)")}");
        if (report.Meta.BudgetExceeded)
            sb.AppendLine($"- **Budget exceeded:** {Md(report.Meta.BudgetReason ?? "(unspecified)")}");
        if (report.Meta.SmtStats is { } stats)
            sb.AppendLine($"- **SMT queries:** {stats.Queries}, sat={stats.Sat}, unsat={stats.Unsat}, unknowns={stats.Unknowns}");
        sb.AppendLine();
        sb.AppendLine("## Summary");
        sb.AppendLine();
        sb.AppendLine($"- **Total:** {report.Summary.Total}");
        sb.AppendLine($"- **Proved:** {report.Summary.Proved}");
        sb.AppendLine($"- **Proved without assumptions:** {report.Summary.ProvedWithoutAssumptions}");
        sb.AppendLine($"- **Proved with assumptions:** {report.Summary.ProvedWithAssumptions}");
        sb.AppendLine($"- **Violated:** {report.Summary.Violated}");
        sb.AppendLine($"- **Unknown:** {report.Summary.Unknown}");
        sb.AppendLine($"- **Incomplete:** {report.Summary.Incomplete}");
        sb.AppendLine();
        sb.AppendLine("## Properties");
        foreach (var result in MarkdownResults(report.Results))
        {
            sb.AppendLine();
            sb.AppendLine($"### `{Md(result.Id)}`");
            sb.AppendLine();
            sb.AppendLine($"- **Method:** `{Md(result.Method)}`");
            if (!string.IsNullOrWhiteSpace(result.SourceProfile))
                sb.AppendLine($"- **Source profile:** `{Md(result.SourceProfile)}`");
            if (result.MethodOffset is int methodOffset)
                sb.AppendLine($"- **Method offset:** `{methodOffset}`");
            sb.AppendLine($"- **Status:** `{StatusString(result)}`");
            sb.AppendLine($"- **Checked paths:** {result.CheckedPaths}");
            sb.AppendLine($"- **Ignored faulted paths:** {result.IgnoredFaultedPaths}");
            sb.AppendLine($"- **Stopped paths:** {result.StoppedPaths}");
            sb.AppendLine($"- **Obligations checked:** {result.ObligationsChecked}");
            sb.AppendLine($"- **Reason:** {Md(result.Reason)}");
            if (result.FailedCondition is not null)
                sb.AppendLine($"- **Failed condition:** `{Md(result.FailedCondition)}`");
            if (!result.Assumptions.IsDefaultOrEmpty)
            {
                sb.AppendLine("- **Assumptions:**");
                foreach (var assumption in result.Assumptions)
                {
                    string source = string.IsNullOrWhiteSpace(assumption.Source)
                        ? ""
                        : $" ({Md(assumption.Source)})";
                    sb.AppendLine($"  - `{Md(assumption.Id)}`: {Md(assumption.Description)}{source}");
                }
            }
            if (result.Counterexample is { Count: > 0 } witness)
            {
                sb.AppendLine();
                sb.AppendLine("| Symbol | Concrete value |");
                sb.AppendLine("|---|---|");
                foreach (var (key, value) in witness.OrderBy(kv => kv.Key, StringComparer.Ordinal))
                    sb.AppendLine($"| `{Md(key)}` | `{Md(FormatValue(value))}` |");
            }
        }
        return sb.ToString();
    }

    private static string FormatNullableInt(int? value) =>
        value is int concrete
            ? concrete.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : "null";

    private static JsonObject BuildJson(VerificationReport report)
    {
        var profiles = new JsonArray();
        foreach (var profile in report.Meta.Profiles)
            profiles.Add(profile);

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
            ["smt_solver_version"] = report.Meta.SmtSolverVersion,
            ["smt_timeout_ms"] = report.Meta.SmtTimeoutMs,
            ["smt_bytes_bound"] = report.Meta.SmtBytesBound,
            ["require_external_smt"] = report.Meta.RequireExternalSmt,
            ["spec_version"] = report.Meta.SpecVersion,
            ["profiles"] = profiles,
        };
        if (report.Meta.Inputs is { } inputs)
        {
            var inputsJson = new JsonObject
            {
                ["program_path"] = inputs.ProgramPath,
                ["program_sha256"] = inputs.ProgramSha256,
                ["manifest_path"] = inputs.ManifestPath,
                ["manifest_sha256"] = inputs.ManifestSha256,
                ["spec_path"] = inputs.SpecPath,
                ["spec_sha256"] = inputs.SpecSha256,
            };
            if (!inputs.DependencyProofSummaries.IsDefaultOrEmpty)
            {
                var summaries = new JsonArray();
                foreach (var summary in inputs.DependencyProofSummaries)
                {
                    summaries.Add(new JsonObject
                    {
                        ["path"] = summary.Path,
                        ["sha256"] = summary.Sha256,
                    });
                }
                inputsJson["dependency_proof_summaries"] = summaries;
            }
            if (!inputs.DependencyProofArtifacts.IsDefaultOrEmpty)
            {
                var artifacts = new JsonArray();
                foreach (var artifact in inputs.DependencyProofArtifacts)
                {
                    artifacts.Add(new JsonObject
                    {
                        ["contract_hash"] = artifact.ContractHash,
                        ["program_path"] = artifact.ProgramPath,
                        ["program_sha256"] = artifact.ProgramSha256,
                        ["manifest_path"] = artifact.ManifestPath,
                        ["manifest_sha256"] = artifact.ManifestSha256,
                    });
                }
                inputsJson["dependency_proof_artifacts"] = artifacts;
            }
            if (inputs.DependencyProofPolicy is { } dependencyProofPolicy)
            {
                inputsJson["dependency_proof_policy"] = new JsonObject
                {
                    ["trusted_for_external_calls"] = dependencyProofPolicy.TrustedForExternalCalls,
                    ["artifact_binding_required"] = dependencyProofPolicy.ArtifactBindingRequired,
                    ["unbound_summaries_allowed"] = dependencyProofPolicy.UnboundSummariesAllowed,
                };
            }
            meta["inputs"] = inputsJson;
        }
        if (report.Meta.EngineOptions is { } engineOptions)
        {
            meta["engine_options"] = new JsonObject
            {
                ["max_paths"] = engineOptions.MaxPaths,
                ["max_steps"] = engineOptions.MaxSteps,
                ["per_run_deadline_ms"] = engineOptions.PerRunDeadlineMs,
                ["max_queued_states"] = engineOptions.MaxQueuedStates,
                ["max_visits_per_offset"] = engineOptions.MaxVisitsPerOffset,
                ["max_concretizations"] = engineOptions.MaxConcretizations,
                ["max_stack_size"] = engineOptions.MaxStackSize,
                ["max_invocation_stack_depth"] = engineOptions.MaxInvocationStackDepth,
                ["max_try_depth"] = engineOptions.MaxTryDepth,
                ["max_item_size"] = engineOptions.MaxItemSize,
                ["max_collection_size"] = engineOptions.MaxCollectionSize,
                ["max_heap_objects"] = engineOptions.MaxHeapObjects,
                ["max_shift_count"] = engineOptions.MaxShiftCount,
                ["max_pow_exponent"] = engineOptions.MaxPowExponent,
                ["initial_call_flags"] = engineOptions.InitialCallFlags,
                ["default_runtime_trigger"] = engineOptions.DefaultRuntimeTrigger,
            };
        }
        if (report.Meta.ContractIdentity is { } identity)
        {
            meta["contract_identity"] = new JsonObject
            {
                ["status"] = identity.Status,
                ["source_kind"] = identity.SourceKind,
                ["manifest_name"] = identity.ManifestName,
                ["deploy_sender_hash"] = identity.DeploySenderHash,
                ["nef_checksum"] = identity.NefChecksum,
                ["nef_checksum_hex"] = identity.NefChecksumHex,
                ["contract_hash"] = identity.ContractHash,
                ["reason"] = identity.Reason,
            };
        }
        if (report.Meta.SmtStats is { } stats)
        {
            meta["smt_stats"] = new JsonObject
            {
                ["queries"] = stats.Queries,
                ["cache_hits"] = stats.CacheHits,
                ["sat"] = stats.Sat,
                ["unsat"] = stats.Unsat,
                ["unknowns"] = stats.Unknowns,
                ["timeouts"] = stats.Timeouts,
                ["opaque_translations"] = stats.OpaqueTranslations,
            };
        }

        var root = new JsonObject
        {
            ["meta"] = meta,
            ["summary"] = new JsonObject
            {
                ["total"] = report.Summary.Total,
                ["proved"] = report.Summary.Proved,
                ["proved_without_assumptions"] = report.Summary.ProvedWithoutAssumptions,
                ["proved_with_assumptions"] = report.Summary.ProvedWithAssumptions,
                ["violated"] = report.Summary.Violated,
                ["unknown"] = report.Summary.Unknown,
                ["incomplete"] = report.Summary.Incomplete,
                ["all_proved"] = report.Summary.AllProved,
                ["all_proved_without_assumptions"] = report.Summary.AllProvedWithoutAssumptions,
            },
            ["results"] = BuildResults(report.Results),
        };
        if (report.GateEvaluation is { } gate)
            root["gate_evaluation"] = BuildGateEvaluation(gate);
        return root;
    }

    private static JsonObject BuildGateEvaluation(VerificationGateEvaluation gate)
    {
        var violations = new JsonArray();
        foreach (string violation in gate.Violations)
            violations.Add(violation);

        return new JsonObject
        {
            ["passed"] = gate.Passed,
            ["unproved"] = gate.Unproved,
            ["external_smt_required_but_missing"] = gate.ExternalSmtRequiredButMissing,
            ["assumption_backed_proofs"] = gate.AssumptionBackedProofs,
            ["policies"] = new JsonObject
            {
                ["fail_on_unproved"] = gate.Policies.FailOnUnproved,
                ["allow_unproved"] = gate.Policies.UnprovedAllowed,
                ["unproved_allowed"] = gate.Policies.UnprovedAllowed,
                ["require_external_smt"] = gate.Policies.RequireExternalSmt,
                ["require_unqualified_proofs"] = gate.Policies.RequireUnqualifiedProofs,
            },
            ["violations"] = violations,
        };
    }

    private static JsonArray BuildResults(IEnumerable<VerificationPropertyResult> results)
    {
        var arr = new JsonArray();
        foreach (var result in results.OrderBy(r => r.Id, StringComparer.Ordinal))
        {
            JsonObject? witness = null;
            if (result.Counterexample is { Count: > 0 } counterexample)
            {
                witness = new JsonObject();
                foreach (var (key, value) in counterexample.OrderBy(kv => kv.Key, StringComparer.Ordinal))
                    witness[key] = FormatValue(value);
            }

            var assumptions = new JsonArray();
            if (!result.Assumptions.IsDefaultOrEmpty)
            {
                foreach (var assumption in result.Assumptions.OrderBy(a => a.Id, StringComparer.Ordinal))
                {
                    assumptions.Add(new JsonObject
                    {
                        ["id"] = assumption.Id,
                        ["description"] = assumption.Description,
                        ["source"] = assumption.Source,
                    });
                }
            }

            arr.Add(new JsonObject
            {
                ["id"] = result.Id,
                ["method"] = result.Method,
                ["method_offset"] = result.MethodOffset,
                ["description"] = result.Description,
                ["source_profile"] = result.SourceProfile,
                ["status"] = StatusString(result),
                ["base_status"] = StatusString(result.Status),
                ["proved_under_assumptions"] = result.Status == VerificationStatus.Proved
                    && !result.Assumptions.IsDefaultOrEmpty,
                ["checked_paths"] = result.CheckedPaths,
                ["ignored_faulted_paths"] = result.IgnoredFaultedPaths,
                ["stopped_paths"] = result.StoppedPaths,
                ["obligations_checked"] = result.ObligationsChecked,
                ["reason"] = result.Reason,
                ["failed_condition"] = result.FailedCondition,
                ["counterexample"] = witness,
                ["assumptions"] = assumptions,
            });
        }
        return arr;
    }

    private static IEnumerable<VerificationPropertyResult> MarkdownResults(IEnumerable<VerificationPropertyResult> results) =>
        results
            .OrderBy(r => MarkdownStatusRank(r.Status))
            .ThenBy(r => r.Id, StringComparer.Ordinal);

    private static string StatusString(VerificationPropertyResult result) =>
        result.Status == VerificationStatus.Proved && !result.Assumptions.IsDefaultOrEmpty
            ? "proved_with_assumptions"
            : StatusString(result.Status);

    private static string StatusString(VerificationStatus status) => status switch
    {
        VerificationStatus.Proved => "proved",
        VerificationStatus.Violated => "violated",
        VerificationStatus.Unknown => "unknown",
        VerificationStatus.Incomplete => "incomplete",
        _ => status.ToString().ToLowerInvariant(),
    };

    private static int MarkdownStatusRank(VerificationStatus status) => status switch
    {
        VerificationStatus.Violated => 0,
        VerificationStatus.Unknown => 1,
        VerificationStatus.Incomplete => 2,
        VerificationStatus.Proved => 3,
        _ => 4,
    };

    private static string FormatValue(object value) => value switch
    {
        System.Numerics.BigInteger bi => bi.ToString(System.Globalization.CultureInfo.InvariantCulture),
        bool b => b ? "true" : "false",
        IFormattable formattable => formattable.ToString(null, System.Globalization.CultureInfo.InvariantCulture),
        _ => value.ToString() ?? "",
    };

    private static string Md(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        var sb = new StringBuilder(value.Length);
        foreach (char c in value)
        {
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
                default:
                    if (!char.IsControl(c)) sb.Append(c);
                    break;
            }
        }
        return sb.ToString().Trim();
    }
}
