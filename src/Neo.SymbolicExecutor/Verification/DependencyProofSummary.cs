using System.Collections.Immutable;
using System.Text.Json;
using System.Text.Json.Nodes;
using Neo.SymbolicExecutor;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Verification;

public sealed record DependencyProofSummarySet(
    ImmutableArray<DependencyContractProofSummary> Contracts,
    bool TrustedForExternalCalls = false,
    ImmutableHashSet<string>? ProvidedSummarySha256s = null,
    bool RequiresUnboundArtifactTrust = false)
{
    public const int CurrentVersion = 3;
    public const long MaxSummaryBytes = 1_048_576;
    public const int MaxContracts = 1_024;
    public const int MaxMethodsPerContract = 1_024;
    public const int MaxParametersPerMethod = 64;
    public const string PrimitiveEqualityReturnConstraint = "IntegerOrByteString";
    private static readonly ImmutableHashSet<string> RootFields =
        ImmutableHashSet.Create(StringComparer.Ordinal, "version", "contracts");
    private static readonly ImmutableHashSet<string> ContractFields =
        ImmutableHashSet.Create(StringComparer.Ordinal, "hash", "proof", "methods");
    private static readonly ImmutableHashSet<string> ProofFields =
        ImmutableHashSet.Create(
            StringComparer.Ordinal,
            "tool",
            "tool_version",
            "source_profile",
            "gate_passed",
            "require_external_smt",
            "require_unqualified_proofs",
            "assumption_backed_proofs",
            "program_sha256",
            "manifest_sha256",
            "contract_hash",
            "deploy_sender_hash",
            "nef_checksum_hex",
            "smt_solver_version",
            "dependency_proof_summaries");
    private static readonly ImmutableHashSet<string> MethodFields =
        ImmutableHashSet.Create(
            StringComparer.Ordinal,
            "name",
            "parameter_count",
            "parameters",
            "return_type",
            "initial_call_flags",
            "initial_runtime_trigger",
            "fault_free");
    private static readonly ImmutableHashSet<string> ParameterFields =
        ImmutableHashSet.Create(StringComparer.Ordinal, "name", "type");
    private static readonly ImmutableHashSet<string> DependencyProofSummaryReferenceFields =
        ImmutableHashSet.Create(StringComparer.Ordinal, "sha256");
    private static readonly ImmutableHashSet<string> NeoAbiParameterTypes =
        ImmutableHashSet.Create(
            StringComparer.OrdinalIgnoreCase,
            "Any",
            "Boolean",
            "Integer",
            "ByteString",
            "ByteArray",
            "String",
            "Hash160",
            "UInt160",
            "Hash256",
            "UInt256",
            "PublicKey",
            "Signature",
            "Array",
            "Map",
            "Struct",
            "InteropInterface");
    private static readonly ImmutableHashSet<string> NeoAbiReturnTypes =
        NeoAbiParameterTypes.Add("Void");

    public static readonly DependencyProofSummarySet Empty =
        new(
            ImmutableArray<DependencyContractProofSummary>.Empty,
            TrustedForExternalCalls: true,
            ImmutableHashSet<string>.Empty,
            RequiresUnboundArtifactTrust: false);

    public bool IsEmpty => Contracts.IsDefaultOrEmpty;

    public static DependencyProofSummarySet FromFiles(
        IEnumerable<string> paths,
        bool trustedForExternalCalls = false,
        IEnumerable<DependencyProofArtifactBinding>? artifactBindings = null)
    {
        var contracts = ImmutableArray.CreateBuilder<DependencyContractProofSummary>();
        var providedSummarySha256s = ImmutableHashSet.CreateBuilder<string>(StringComparer.Ordinal);
        foreach (string path in paths)
        {
            var (json, sha256) = ReadSummaryFile(path);
            var parsedSummary = FromJson(json);
            contracts.AddRange(parsedSummary.Contracts);
            providedSummarySha256s.Add(sha256);
        }

        var summarySet = FromContracts(
            contracts.ToImmutable(),
            trustedForExternalCalls,
            providedSummarySha256s.ToImmutable(),
            requiresUnboundArtifactTrust: trustedForExternalCalls);
        return artifactBindings is null
            ? summarySet
            : summarySet.RequireArtifactBindings(artifactBindings);
    }

    public static DependencyProofSummarySet FromFile(
        string path,
        bool trustedForExternalCalls = false)
    {
        var (json, sha256) = ReadSummaryFile(path);
        return FromContracts(
            FromJson(json).Contracts,
            trustedForExternalCalls,
            ImmutableHashSet.Create(StringComparer.Ordinal, sha256),
            requiresUnboundArtifactTrust: trustedForExternalCalls);
    }

    private static (string Json, string Sha256) ReadSummaryFile(string path)
    {
        var info = new FileInfo(path);
        if (!info.Exists)
            throw new FileNotFoundException($"dependency proof summary not found: {path}", path);
        if (info.Length > MaxSummaryBytes)
            throw new FormatException(
                $"Dependency proof summary file '{path}' is {info.Length} bytes, exceeds max {MaxSummaryBytes} bytes");

        byte[] bytes = File.ReadAllBytes(path);
        string sha256 = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
        return (System.Text.Encoding.UTF8.GetString(bytes), sha256);
    }

    private static string Sha256File(string path, string artifactKind, string contractHash)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"dependency proof {artifactKind} artifact for {contractHash} not found: {path}",
                path);
        }

        return Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(path)))
            .ToLowerInvariant();
    }

    public static DependencyProofSummarySet FromJson(
        string json,
        bool trustedForExternalCalls = false)
    {
        JsonNode? node;
        try
        {
            node = JsonNode.Parse(json);
        }
        catch (JsonException jex)
        {
            throw new FormatException($"Dependency proof summary is not valid JSON: {jex.Message}", jex);
        }

        var root = RequireObject(node, "dependency proof summary");
        RejectUnknownFields(root, "dependency proof summary", RootFields);
        int version = OptionalInt(root, "version", "version", defaultValue: 1);
        if (version != CurrentVersion)
            throw new FormatException($"Dependency proof summary version {version} is not supported");

        var contractsNode = RequireArray(root["contracts"], "contracts");
        if (contractsNode.Count > MaxContracts)
            throw new FormatException($"Dependency proof summary contract count {contractsNode.Count} exceeds max {MaxContracts}");

        var contracts = ImmutableArray.CreateBuilder<DependencyContractProofSummary>();
        for (int i = 0; i < contractsNode.Count; i++)
        {
            var contract = RequireObject(contractsNode[i], $"contracts[{i}]");
            RejectUnknownFields(contract, $"contracts[{i}]", ContractFields);
            string hash = NormalizeHash(RequireString(contract["hash"], $"contracts[{i}].hash"), $"contracts[{i}].hash");
            var proof = ParseProof(contract["proof"], $"contracts[{i}].proof", hash);
            var methodsNode = RequireArray(contract["methods"], $"contracts[{i}].methods");
            if (methodsNode.Count > MaxMethodsPerContract)
            {
                throw new FormatException(
                    $"Dependency proof summary methods count {methodsNode.Count} exceeds max {MaxMethodsPerContract}");
            }

            var methods = ImmutableArray.CreateBuilder<DependencyMethodProofSummary>();
            for (int j = 0; j < methodsNode.Count; j++)
                methods.Add(ParseMethod(methodsNode[j], $"contracts[{i}].methods[{j}]"));

            contracts.Add(new DependencyContractProofSummary(hash, proof, methods.ToImmutable()));
        }

        return FromContracts(
            contracts.ToImmutable(),
            trustedForExternalCalls,
            requiresUnboundArtifactTrust: trustedForExternalCalls);
    }

    public static DependencyProofSummarySet FromVerifiedContract(
        ContractManifest manifest,
        string contractHashHex,
        VerificationReport report)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(report);

        string hash = NormalizeHash(contractHashHex, "contract_hash");
        var proof = DependencyProofMetadata.FromReport(report, hash);
        var methods = ImmutableArray.CreateBuilder<DependencyMethodProofSummary>();
        foreach (var method in manifest.Abi.Methods.OrderBy(m => m.Offset).ThenBy(m => m.Name, StringComparer.Ordinal))
        {
            if (!HasProvedProfileResult(report, method, "security.vm_surface.")
                || !HasProvedProfileResult(report, method, "security.vm_fault_free.")
                || !HasProvedProfileResult(report, method, "security.abi_return_type."))
            {
                continue;
            }

            methods.Add(new DependencyMethodProofSummary(
                method.Name,
                method.Parameters.Count,
                method.Parameters
                    .Select(p => new DependencyMethodParameterProofSummary(p.Name, p.Type))
                    .ToImmutableArray(),
                method.ReturnType,
                InitialCallFlags: report.Meta.EngineOptions?.InitialCallFlags
                    ?? throw new InvalidOperationException(
                        "dependency proof summary emission requires engine options provenance"),
                InitialRuntimeTrigger: RuntimeTriggerForMethod(report, method),
                FaultFree: true));
        }

        if (methods.Count == 0)
            return Empty;

        return FromContracts(ImmutableArray.Create(
            new DependencyContractProofSummary(hash, proof, methods.ToImmutable())));
    }

    public string ToJson()
    {
        var contracts = new JsonArray();
        foreach (var contract in Contracts.OrderBy(c => c.Hash, StringComparer.Ordinal))
        {
            var methods = new JsonArray();
            foreach (var method in contract.Methods
                         .OrderBy(m => m.Name, StringComparer.Ordinal)
                         .ThenBy(m => m.ParameterCount)
                         .ThenBy(m => m.ReturnType, StringComparer.Ordinal))
            {
                var parameters = new JsonArray();
                foreach (var parameter in method.Parameters)
                {
                    parameters.Add(new JsonObject
                    {
                        ["name"] = parameter.Name,
                        ["type"] = parameter.Type,
                    });
                }

                methods.Add(new JsonObject
                {
                    ["name"] = method.Name,
                    ["parameter_count"] = method.ParameterCount,
                    ["parameters"] = parameters,
                    ["return_type"] = method.ReturnType,
                    ["initial_call_flags"] = method.InitialCallFlags,
                    ["initial_runtime_trigger"] = method.InitialRuntimeTrigger,
                    ["fault_free"] = method.FaultFree,
                });
            }

            contracts.Add(new JsonObject
            {
                ["hash"] = contract.Hash,
                ["proof"] = BuildProofJson(contract.Proof),
                ["methods"] = methods,
            });
        }

        var root = new JsonObject
        {
            ["version"] = CurrentVersion,
            ["contracts"] = contracts,
        };
        return root.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
    }

    public DependencyProofSummarySet RequireArtifactBindings(
        IEnumerable<DependencyProofArtifactBinding> artifactBindings)
    {
        ArgumentNullException.ThrowIfNull(artifactBindings);
        var bindings = artifactBindings.ToArray();
        if (bindings.Length == 0)
            return this;

        var byContractHash = new Dictionary<string, DependencyProofArtifactBinding>(StringComparer.Ordinal);
        foreach (var binding in bindings)
        {
            string contractHash = NormalizeHash(
                binding.ContractHash,
                "dependency proof artifact contract_hash");
            if (string.IsNullOrWhiteSpace(binding.ProgramPath))
                throw new FormatException($"Dependency proof artifact binding for {contractHash} requires a program path");
            if (string.IsNullOrWhiteSpace(binding.ManifestPath))
                throw new FormatException($"Dependency proof artifact binding for {contractHash} requires a manifest path");
            if (!byContractHash.TryAdd(contractHash, binding))
                throw new FormatException($"Duplicate dependency proof artifact binding for contract {contractHash}");
        }

        foreach (var contract in Contracts)
        {
            if (!byContractHash.TryGetValue(contract.Hash, out var binding))
            {
                throw new FormatException(
                    $"Missing dependency proof artifact binding for contract {contract.Hash}");
            }

            string programSha256 = Sha256File(binding.ProgramPath, "program", contract.Hash);
            if (!string.Equals(programSha256, contract.Proof.ProgramSha256, StringComparison.Ordinal))
            {
                throw new FormatException(
                    $"Dependency proof artifact binding for {contract.Hash} program_sha256 mismatch: "
                    + $"summary has {contract.Proof.ProgramSha256}, artifact has {programSha256}");
            }

            string manifestSha256 = Sha256File(binding.ManifestPath, "manifest", contract.Hash);
            if (!string.Equals(manifestSha256, contract.Proof.ManifestSha256, StringComparison.Ordinal))
            {
                throw new FormatException(
                    $"Dependency proof artifact binding for {contract.Hash} manifest_sha256 mismatch: "
                    + $"summary has {contract.Proof.ManifestSha256}, artifact has {manifestSha256}");
            }

            var nef = NefFile.Parse(File.ReadAllBytes(binding.ProgramPath), verifyChecksum: true);
            string nefChecksumHex = $"0x{nef.Checksum:x8}";
            if (contract.Proof.NefChecksumHex is null)
            {
                throw new FormatException(
                    $"Dependency proof artifact binding for {contract.Hash} requires nef_checksum_hex metadata");
            }

            if (!string.Equals(nefChecksumHex, contract.Proof.NefChecksumHex, StringComparison.Ordinal))
            {
                throw new FormatException(
                    $"Dependency proof artifact binding for {contract.Hash} nef_checksum_hex mismatch: "
                    + $"summary has {contract.Proof.NefChecksumHex}, artifact has {nefChecksumHex}");
            }

            if (contract.Proof.DeploySenderHash is null)
            {
                throw new FormatException(
                    $"Dependency proof artifact binding for {contract.Hash} requires deploy_sender_hash metadata");
            }

            var manifest = ContractManifest.FromFile(binding.ManifestPath);
            ValidateBoundManifestMethods(contract, manifest);
            string computedContractHash = "0x" + ContractIdentity.ComputeContractHashHex(
                nef,
                manifest,
                ContractIdentity.ParseUInt160LittleEndianHex(contract.Proof.DeploySenderHash));
            if (!string.Equals(computedContractHash, contract.Hash, StringComparison.Ordinal))
            {
                throw new FormatException(
                    $"Dependency proof artifact binding for {contract.Hash} contract_hash mismatch: "
                    + $"bound artifacts compute {computedContractHash}");
            }
        }

        var summaryContracts = Contracts.Select(contract => contract.Hash).ToHashSet(StringComparer.Ordinal);
        foreach (string unusedContractHash in byContractHash.Keys
                     .Where(contractHash => !summaryContracts.Contains(contractHash))
                     .OrderBy(contractHash => contractHash, StringComparer.Ordinal))
        {
            throw new FormatException(
                $"Unused dependency proof artifact binding for contract {unusedContractHash}");
        }

        return this with { RequiresUnboundArtifactTrust = false };
    }

    private static void ValidateBoundManifestMethods(
        DependencyContractProofSummary contract,
        ContractManifest manifest)
    {
        foreach (var method in contract.Methods)
        {
            var manifestMethod = manifest.Abi.Methods.FirstOrDefault(candidate =>
                string.Equals(candidate.Name, method.Name, StringComparison.Ordinal)
                && candidate.Parameters.Count == method.ParameterCount);
            if (manifestMethod is null)
            {
                throw new FormatException(
                    $"Dependency proof summary method {contract.Hash}.{method.Name}/{method.ParameterCount} "
                    + "is not declared by the bound manifest ABI");
            }

            if (!string.Equals(manifestMethod.ReturnType, method.ReturnType, StringComparison.Ordinal))
            {
                throw new FormatException(
                    $"Dependency proof summary method {contract.Hash}.{method.Name}/{method.ParameterCount} "
                    + $"return_type {method.ReturnType} does not match bound manifest returntype {manifestMethod.ReturnType}");
            }

            if (method.Parameters.Length != manifestMethod.Parameters.Count)
            {
                throw new FormatException(
                    $"Dependency proof summary method {contract.Hash}.{method.Name}/{method.ParameterCount} "
                    + $"declares {method.Parameters.Length} typed parameter(s), but bound manifest declares "
                    + $"{manifestMethod.Parameters.Count}");
            }

            for (int i = 0; i < method.Parameters.Length; i++)
            {
                var summaryParameter = method.Parameters[i];
                var manifestParameter = manifestMethod.Parameters[i];
                if (!string.Equals(summaryParameter.Name, manifestParameter.Name, StringComparison.Ordinal))
                {
                    throw new FormatException(
                        $"Dependency proof summary method {contract.Hash}.{method.Name}/{method.ParameterCount} "
                        + $"parameter {i} name {summaryParameter.Name} does not match bound manifest name "
                        + manifestParameter.Name);
                }

                if (!string.Equals(summaryParameter.Type, manifestParameter.Type, StringComparison.Ordinal))
                {
                    throw new FormatException(
                        $"Dependency proof summary method {contract.Hash}.{method.Name}/{method.ParameterCount} "
                        + $"parameter {i} type {summaryParameter.Type} does not match bound manifest type "
                        + manifestParameter.Type);
                }
            }
        }
    }

    private static JsonObject BuildProofJson(DependencyProofMetadata proof)
    {
        var proofJson = new JsonObject
        {
            ["tool"] = proof.Tool,
            ["tool_version"] = proof.ToolVersion,
            ["source_profile"] = proof.SourceProfile,
            ["gate_passed"] = proof.GatePassed,
            ["require_external_smt"] = proof.RequireExternalSmt,
            ["require_unqualified_proofs"] = proof.RequireUnqualifiedProofs,
            ["assumption_backed_proofs"] = proof.AssumptionBackedProofs,
            ["program_sha256"] = proof.ProgramSha256,
            ["manifest_sha256"] = proof.ManifestSha256,
            ["contract_hash"] = proof.ContractHash,
            ["deploy_sender_hash"] = proof.DeploySenderHash,
            ["nef_checksum_hex"] = proof.NefChecksumHex,
            ["smt_solver_version"] = proof.SmtSolverVersion,
        };

        if (!proof.DependencyProofSummaries.IsDefaultOrEmpty)
        {
            var transitiveSummaries = new JsonArray();
            foreach (var summary in proof.DependencyProofSummaries.OrderBy(s => s.Sha256, StringComparer.Ordinal))
            {
                transitiveSummaries.Add(new JsonObject
                {
                    ["sha256"] = summary.Sha256,
                });
            }

            proofJson["dependency_proof_summaries"] = transitiveSummaries;
        }

        return proofJson;
    }

    public DependencyProofCoverage CheckExternalCall(
        byte[] targetHash,
        string methodName,
        int parameterCount,
        bool hasReturnValue,
        string? expectedReturnType,
        int callFlags,
        bool callFlagsDynamic,
        int runtimeTrigger,
        bool requireExternalSmt,
        bool returnValueDeclaredByMethodToken = false)
    {
        if (IsEmpty)
            return DependencyProofCoverage.NotCovered("no dependency proof summary was provided");

        if (!TrustedForExternalCalls)
        {
            return DependencyProofCoverage.NotCovered(
                "dependency proof summary was provided but not explicitly trusted; pass --trust-dependency-proof-summaries only for summaries emitted by a trusted neo-sym verification pipeline after checking the recorded program_sha256 and manifest_sha256 artifacts");
        }

        var unresolvedTransitiveProofSummaries = UnresolvedTransitiveDependencyProofSummaryHashes();
        if (unresolvedTransitiveProofSummaries.Length > 0)
        {
            return DependencyProofCoverage.NotCovered(
                "dependency proof summary bundle is missing transitive dependency proof summary SHA-256 value(s): "
                + string.Join(", ", unresolvedTransitiveProofSummaries));
        }

        string target = FormatHash(targetHash);
        var contracts = Contracts
            .Where(c => string.Equals(c.Hash, target, StringComparison.Ordinal))
            .ToArray();
        if (contracts.Length == 0)
            return DependencyProofCoverage.NotCovered($"no dependency proof summary covers target contract {target}");

        var contract = contracts.Single();
        if (requireExternalSmt && !contract.Proof.RequireExternalSmt)
        {
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target} was not produced with --require-external-smt");
        }

        var methods = contracts
            .SelectMany(c => c.Methods)
            .Where(m => string.Equals(m.Name, methodName, StringComparison.Ordinal))
            .ToArray();
        if (methods.Length == 0)
        {
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target} does not declare method '{methodName}'");
        }

        var arityMatches = methods
            .Where(m => m.ParameterCount == parameterCount)
            .ToArray();
        if (arityMatches.Length == 0)
        {
            string counts = string.Join(", ", methods.Select(m => m.ParameterCount).Distinct().OrderBy(c => c));
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target}.{methodName} declares parameter count(s) {counts}, got {parameterCount}");
        }

        var returnMatches = arityMatches
            .Where(m => ReturnShapeCompatible(
                m,
                hasReturnValue,
                expectedReturnType,
                returnValueDeclaredByMethodToken))
            .ToArray();
        if (returnMatches.Length == 0)
        {
            string expected = hasReturnValue
                ? returnValueDeclaredByMethodToken
                    ? "a non-Void return value declared by CALLT MethodToken"
                    : expectedReturnType is null
                        ? "a return value or an unconsumed Void return"
                    : $"a {expectedReturnType} return value"
                : "no return value";
            string declared = string.Join(
                ", ",
                arityMatches
                    .Select(m => m.HasReturnValue ? $"{m.ReturnType} return value" : "Void/no return value")
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(s => s, StringComparer.Ordinal));
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target}.{methodName}/{parameterCount} declares {declared}, caller expects {expected}");
        }

        if (!string.IsNullOrWhiteSpace(expectedReturnType))
        {
            var returnTypeMatches = returnMatches
                .Where(m => ReturnTypesCompatible(m.ReturnType, expectedReturnType))
                .ToArray();
            if (returnTypeMatches.Length == 0)
            {
                string declaredTypes = string.Join(
                    ", ",
                    returnMatches
                        .Select(m => m.ReturnType)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .OrderBy(s => s, StringComparer.OrdinalIgnoreCase));
                return DependencyProofCoverage.NotCovered(
                    $"dependency proof summary for {target}.{methodName}/{parameterCount} declares return type(s) {declaredTypes}, caller expects {expectedReturnType}");
            }

            returnMatches = returnTypeMatches;
        }

        if (callFlagsDynamic)
        {
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target}.{methodName}/{parameterCount} cannot cover dynamic call flags");
        }

        if (callFlags < NeoCallFlags.None || callFlags > NeoCallFlags.All)
        {
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target}.{methodName}/{parameterCount} cannot cover invalid call flags {callFlags}");
        }

        var flagMatches = returnMatches
            .Where(m => m.InitialCallFlags == callFlags)
            .ToArray();
        if (flagMatches.Length == 0)
        {
            string provedFlags = string.Join(
                ", ",
                returnMatches
                    .Select(m => $"{m.InitialCallFlags} ({FormatCallFlags(m.InitialCallFlags)})")
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(s => s, StringComparer.Ordinal));
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target}.{methodName}/{parameterCount} was proved with effective call flags {provedFlags}; caller uses {callFlags} ({FormatCallFlags(callFlags)})");
        }

        var triggerMatches = flagMatches
            .Where(m => m.InitialRuntimeTrigger == runtimeTrigger)
            .ToArray();
        if (triggerMatches.Length == 0)
        {
            string provedTriggers = string.Join(
                ", ",
                flagMatches
                    .Select(m => m.InitialRuntimeTrigger is int trigger
                        ? $"{trigger} ({FormatRuntimeTrigger(trigger)})"
                        : "missing")
                    .Distinct(StringComparer.Ordinal)
                    .OrderBy(s => s, StringComparer.Ordinal));
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target}.{methodName}/{parameterCount} was proved with runtime trigger {provedTriggers}; caller uses {runtimeTrigger} ({FormatRuntimeTrigger(runtimeTrigger)})");
        }

        if (!triggerMatches.Any(m => m.FaultFree))
        {
            return DependencyProofCoverage.NotCovered(
                $"dependency proof summary for {target}.{methodName}/{parameterCount} with effective call flags {callFlags} and runtime trigger {runtimeTrigger} is not marked fault_free");
        }

        return DependencyProofCoverage.Covered(
            triggerMatches.Single(m => m.FaultFree),
            RequiresUnboundArtifactTrust);
    }

    private ImmutableArray<string> UnresolvedTransitiveDependencyProofSummaryHashes()
    {
        var provided = ProvidedSummarySha256s ?? ImmutableHashSet<string>.Empty;
        if (provided.IsEmpty)
        {
            return Contracts
                .SelectMany(c => c.Proof.DependencyProofSummaries)
                .Select(r => r.Sha256)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(s => s, StringComparer.Ordinal)
                .ToImmutableArray();
        }

        return Contracts
            .SelectMany(c => c.Proof.DependencyProofSummaries)
            .Select(r => r.Sha256)
            .Where(sha => !provided.Contains(sha))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static bool ReturnTypesCompatible(string actual, string expected) =>
        string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase)
        || IsPrimitiveEqualityCompatibleReturn(actual, expected)
        || IsByteStringCompatibleReturn(actual, expected)
        || IsFixedByteAliasCompatibleReturn(actual, expected)
        || IsFixedByteSubtypeOfByteStringReturn(actual, expected);

    private static bool ReturnShapeCompatible(
        DependencyMethodProofSummary method,
        bool callerHasReturnValue,
        string? expectedReturnType,
        bool returnValueDeclaredByMethodToken)
    {
        if (!callerHasReturnValue)
            return !method.HasReturnValue;

        if (returnValueDeclaredByMethodToken)
            return method.HasReturnValue;

        if (!string.IsNullOrWhiteSpace(expectedReturnType))
            return method.HasReturnValue;

        return method.HasReturnValue
            || string.Equals(method.ReturnType, "Void", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsByteStringCompatibleReturn(string actual, string expected) =>
        IsByteStringLike(actual) && IsByteStringLike(expected);

    private static bool IsPrimitiveEqualityCompatibleReturn(string actual, string expected) =>
        IsAbiType(expected, PrimitiveEqualityReturnConstraint)
        && (IsAbiType(actual, "Integer") || IsRuntimeByteStringReturn(actual));

    private static bool IsFixedByteAliasCompatibleReturn(string actual, string expected) =>
        SameAbiAliasGroup(actual, expected, "Hash160", "UInt160")
        || SameAbiAliasGroup(actual, expected, "Hash256", "UInt256");

    private static bool IsFixedByteSubtypeOfByteStringReturn(string actual, string expected) =>
        IsFixedByteLike(actual) && IsByteStringLike(expected);

    private static bool IsRuntimeByteStringReturn(string value) =>
        IsByteStringLike(value)
        || IsFixedByteLike(value)
        || IsAbiType(value, "String");

    private static bool SameAbiAliasGroup(string actual, string expected, string first, string second) =>
        (IsAbiType(actual, first) || IsAbiType(actual, second))
        && (IsAbiType(expected, first) || IsAbiType(expected, second));

    private static bool IsFixedByteLike(string value) =>
        IsAbiType(value, "Hash160")
        || IsAbiType(value, "UInt160")
        || IsAbiType(value, "Hash256")
        || IsAbiType(value, "UInt256")
        || IsAbiType(value, "PublicKey")
        || IsAbiType(value, "Signature");

    private static bool IsByteStringLike(string value) =>
        IsAbiType(value, "ByteString")
        || IsAbiType(value, "ByteArray");

    private static bool IsAbiType(string actual, string expected) =>
        string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);

    private static DependencyMethodProofSummary ParseMethod(JsonNode? node, string path)
    {
        var method = RequireObject(node, path);
        RejectUnknownFields(method, path, MethodFields);
        string name = RequireString(method["name"], $"{path}.name");
        if (string.IsNullOrWhiteSpace(name))
            throw new FormatException($"Dependency proof summary '{path}.name' must be non-empty");

        int? parameterCount = OptionalInt(method, "parameter_count", $"{path}.parameter_count");
        ImmutableArray<DependencyMethodParameterProofSummary> typedParameters = ImmutableArray<DependencyMethodParameterProofSummary>.Empty;
        if (method["parameters"] is JsonArray parameters)
        {
            if (parameters.Count > MaxParametersPerMethod)
            {
                throw new FormatException(
                    $"Dependency proof summary parameter count {parameters.Count} exceeds max {MaxParametersPerMethod}");
            }

            var parsedParameters = ImmutableArray.CreateBuilder<DependencyMethodParameterProofSummary>(parameters.Count);
            for (int i = 0; i < parameters.Count; i++)
            {
                var parameter = RequireObject(parameters[i], $"{path}.parameters[{i}]");
                RejectUnknownFields(parameter, $"{path}.parameters[{i}]", ParameterFields);
                string parameterType = RequireSupportedNeoAbiType(
                    parameter["type"],
                    $"{path}.parameters[{i}].type",
                    allowVoid: false);
                parsedParameters.Add(new DependencyMethodParameterProofSummary(
                    OptionalString(parameter, "name", $"{path}.parameters[{i}].name") ?? "",
                    parameterType));
            }

            if (parameterCount is { } declared && declared != parameters.Count)
            {
                throw new FormatException(
                    $"Dependency proof summary '{path}' has parameter_count {declared} but parameters length {parameters.Count}");
            }

            parameterCount = parameters.Count;
            typedParameters = parsedParameters.ToImmutable();
        }

        if (parameterCount is not { } count)
            throw new FormatException($"Dependency proof summary '{path}' requires parameter_count or parameters");
        if (count < 0 || count > MaxParametersPerMethod)
        {
            throw new FormatException(
                $"Dependency proof summary '{path}.parameter_count' must be between 0 and {MaxParametersPerMethod}");
        }
        if (count > 0 && typedParameters.IsDefaultOrEmpty)
        {
            throw new FormatException(
                $"Dependency proof summary '{path}' requires typed parameters for non-zero parameter_count");
        }

        string returnType = RequireSupportedNeoAbiType(
            method["return_type"],
            $"{path}.return_type",
            allowVoid: true);

        int initialCallFlags = RequireCallFlags(method["initial_call_flags"], $"{path}.initial_call_flags");
        int? initialRuntimeTrigger = OptionalRuntimeTrigger(
            method,
            "initial_runtime_trigger",
            $"{path}.initial_runtime_trigger");
        bool faultFree = RequireBool(method["fault_free"], $"{path}.fault_free");
        return new DependencyMethodProofSummary(
            name,
            count,
            typedParameters,
            returnType,
            initialCallFlags,
            initialRuntimeTrigger,
            faultFree);
    }

    private static DependencyProofMetadata ParseProof(JsonNode? node, string path, string contractHash)
    {
        var proof = RequireObject(node, path);
        RejectUnknownFields(proof, path, ProofFields);

        string tool = RequireNonEmptyString(proof["tool"], $"{path}.tool");
        if (!string.Equals(tool, "Neo.SymbolicExecutor.Verify", StringComparison.Ordinal))
            throw new FormatException($"Dependency proof summary '{path}.tool' must be Neo.SymbolicExecutor.Verify");

        string sourceProfile = RequireNonEmptyString(proof["source_profile"], $"{path}.source_profile");
        if (!string.Equals(sourceProfile, FormalVerifier.NeoN3SecurityProfile, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"Dependency proof summary '{path}.source_profile' must be {FormalVerifier.NeoN3SecurityProfile}");
        }

        bool gatePassed = RequireBool(proof["gate_passed"], $"{path}.gate_passed");
        if (!gatePassed)
            throw new FormatException($"Dependency proof summary '{path}.gate_passed' must be true");

        bool requireUnqualifiedProofs = RequireBool(
            proof["require_unqualified_proofs"],
            $"{path}.require_unqualified_proofs");
        if (!requireUnqualifiedProofs)
        {
            throw new FormatException(
                $"Dependency proof summary '{path}.require_unqualified_proofs' must be true");
        }

        int assumptionBackedProofs = OptionalInt(
            proof,
            "assumption_backed_proofs",
            $"{path}.assumption_backed_proofs",
            defaultValue: 0);
        if (assumptionBackedProofs != 0)
        {
            throw new FormatException(
                $"Dependency proof summary '{path}.assumption_backed_proofs' must be 0");
        }

        string proofContractHash = NormalizeHash(
            RequireString(proof["contract_hash"], $"{path}.contract_hash"),
            $"{path}.contract_hash");
        if (!string.Equals(proofContractHash, contractHash, StringComparison.Ordinal))
        {
            throw new FormatException(
                $"Dependency proof summary '{path}.contract_hash' must match contracts[].hash");
        }

        var transitiveDependencyProofSummaries = ParseDependencyProofSummaryReferences(
            proof["dependency_proof_summaries"],
            $"{path}.dependency_proof_summaries");
        bool requireExternalSmt = OptionalBool(
            proof,
            "require_external_smt",
            $"{path}.require_external_smt",
            defaultValue: false);
        string? smtSolverVersion = OptionalString(proof, "smt_solver_version", $"{path}.smt_solver_version");
        ValidateExternalSmtProofClaim(requireExternalSmt, smtSolverVersion, path);

        return new DependencyProofMetadata(
            tool,
            RequireNonEmptyString(proof["tool_version"], $"{path}.tool_version"),
            sourceProfile,
            gatePassed,
            requireExternalSmt,
            requireUnqualifiedProofs,
            assumptionBackedProofs,
            RequireSha256(proof["program_sha256"], $"{path}.program_sha256"),
            RequireSha256(proof["manifest_sha256"], $"{path}.manifest_sha256"),
            proofContractHash,
            OptionalUInt160Hex(proof, "deploy_sender_hash", $"{path}.deploy_sender_hash"),
            OptionalNefChecksumHex(proof, "nef_checksum_hex", $"{path}.nef_checksum_hex"),
            smtSolverVersion,
            transitiveDependencyProofSummaries);
    }

    private static void ValidateExternalSmtProofClaim(
        bool requireExternalSmt,
        string? smtSolverVersion,
        string path)
    {
        if (!requireExternalSmt)
            return;

        if (string.IsNullOrWhiteSpace(smtSolverVersion))
        {
            throw new FormatException(
                $"Dependency proof summary '{path}.require_external_smt' requires an external SMT solver version in '{path}.smt_solver_version'");
        }

        if (smtSolverVersion.TrimStart().StartsWith("portable fallback", StringComparison.OrdinalIgnoreCase))
        {
            throw new FormatException(
                $"Dependency proof summary '{path}.require_external_smt' requires an external SMT solver version, but '{path}.smt_solver_version' records portable fallback");
        }
    }

    private static ImmutableArray<DependencyProofSummaryReference> ParseDependencyProofSummaryReferences(
        JsonNode? node,
        string path)
    {
        if (node is null)
            return ImmutableArray<DependencyProofSummaryReference>.Empty;

        var references = RequireArray(node, path);
        if (references.Count > MaxContracts)
        {
            throw new FormatException(
                $"Dependency proof summary transitive dependency count {references.Count} exceeds max {MaxContracts}");
        }

        var parsed = ImmutableArray.CreateBuilder<DependencyProofSummaryReference>(references.Count);
        for (int i = 0; i < references.Count; i++)
        {
            var reference = RequireObject(references[i], $"{path}[{i}]");
            RejectUnknownFields(reference, $"{path}[{i}]", DependencyProofSummaryReferenceFields);
            parsed.Add(new DependencyProofSummaryReference(
                RequireSha256(reference["sha256"], $"{path}[{i}].sha256")));
        }

        return parsed
            .Distinct()
            .OrderBy(r => r.Sha256, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static DependencyProofSummarySet FromContracts(
        ImmutableArray<DependencyContractProofSummary> contracts,
        bool trustedForExternalCalls = true,
        ImmutableHashSet<string>? providedSummarySha256s = null,
        bool requiresUnboundArtifactTrust = false)
    {
        if (contracts.IsDefaultOrEmpty)
        {
            return new DependencyProofSummarySet(
                ImmutableArray<DependencyContractProofSummary>.Empty,
                trustedForExternalCalls,
                providedSummarySha256s ?? ImmutableHashSet<string>.Empty,
                RequiresUnboundArtifactTrust: false);
        }

        ValidateSupportedNeoAbiTypes(contracts);
        ValidateUniqueContractHashes(contracts);
        ValidateUniqueExternalCallSelectors(contracts);
        return new DependencyProofSummarySet(
            contracts,
            trustedForExternalCalls,
            providedSummarySha256s ?? ImmutableHashSet<string>.Empty,
            requiresUnboundArtifactTrust && trustedForExternalCalls);
    }

    private static void ValidateSupportedNeoAbiTypes(
        ImmutableArray<DependencyContractProofSummary> contracts)
    {
        for (int contractIndex = 0; contractIndex < contracts.Length; contractIndex++)
        {
            var contract = contracts[contractIndex];
            for (int methodIndex = 0; methodIndex < contract.Methods.Length; methodIndex++)
            {
                var method = contract.Methods[methodIndex];
                string methodPath = $"contracts[{contractIndex}].methods[{methodIndex}]";
                _ = RequireSupportedNeoAbiType(method.ReturnType, $"{methodPath}.return_type", allowVoid: true);
                for (int parameterIndex = 0; parameterIndex < method.Parameters.Length; parameterIndex++)
                {
                    _ = RequireSupportedNeoAbiType(
                        method.Parameters[parameterIndex].Type,
                        $"{methodPath}.parameters[{parameterIndex}].type",
                        allowVoid: false);
                }
            }
        }
    }

    private static void ValidateUniqueContractHashes(
        ImmutableArray<DependencyContractProofSummary> contracts)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var contract in contracts)
        {
            if (!seen.Add(contract.Hash))
            {
                throw new FormatException(
                    $"Dependency proof summary contains duplicate contract hash {contract.Hash}");
            }
        }
    }

    private static void ValidateUniqueExternalCallSelectors(
        ImmutableArray<DependencyContractProofSummary> contracts)
    {
        var seen = new HashSet<(string Hash, string Name, int ParameterCount, int InitialCallFlags, int? InitialRuntimeTrigger)>();
        foreach (var contract in contracts)
        {
            foreach (var method in contract.Methods)
            {
                var key = (
                    contract.Hash,
                    method.Name,
                    method.ParameterCount,
                    method.InitialCallFlags,
                    method.InitialRuntimeTrigger);
                if (!seen.Add(key))
                {
                    string returnShape = method.HasReturnValue ? "return value" : "no return value";
                    throw new FormatException(
                        $"Dependency proof summary for {contract.Hash} contains duplicate method selector '{method.Name}/{method.ParameterCount}/{returnShape}/call_flags:{method.InitialCallFlags}/runtime_trigger:{method.InitialRuntimeTrigger?.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "missing"}'");
                }
            }
        }
    }

    private static int RuntimeTriggerForMethod(
        VerificationReport report,
        ContractMethodDescriptor method)
    {
        if (string.Equals(method.Name, "verify", StringComparison.Ordinal))
            return NeoTriggerTypes.Verification;

        return report.Meta.EngineOptions?.DefaultRuntimeTrigger
            ?? NeoTriggerTypes.Application;
    }

    private static bool HasProvedProfileResult(
        VerificationReport report,
        ContractMethodDescriptor method,
        string idPrefix) =>
        report.Results.Any(result =>
            string.Equals(result.Method, method.Name, StringComparison.Ordinal)
            && result.Status == VerificationStatus.Proved
            && result.Assumptions.IsDefaultOrEmpty
            && string.Equals(result.SourceProfile, FormalVerifier.NeoN3SecurityProfile, StringComparison.Ordinal)
            && result.MethodOffset == method.Offset
            && ProfileResultIdMatches(result.Id, idPrefix, method));

    private static bool ProfileResultIdMatches(
        string id,
        string idPrefix,
        ContractMethodDescriptor method)
    {
        string baseId = idPrefix + method.Name;
        return string.Equals(id, baseId, StringComparison.Ordinal)
            || string.Equals(id, $"{baseId}@{method.Offset}", StringComparison.Ordinal);
    }

    private static void RejectUnknownFields(
        JsonObject obj,
        string path,
        ImmutableHashSet<string> allowedFields)
    {
        foreach (var field in obj)
        {
            if (allowedFields.Contains(field.Key))
                continue;

            string display = path == "dependency proof summary"
                ? field.Key
                : $"{path}.{field.Key}";
            throw new FormatException($"unknown dependency proof summary field '{display}'");
        }
    }

    private static JsonObject RequireObject(JsonNode? node, string path)
    {
        if (node is JsonObject obj)
            return obj;
        throw new FormatException($"Dependency proof summary '{path}' must be a JSON object");
    }

    private static JsonArray RequireArray(JsonNode? node, string path)
    {
        if (node is JsonArray array)
            return array;
        throw new FormatException($"Dependency proof summary '{path}' must be an array");
    }

    private static string RequireString(JsonNode? node, string path)
    {
        if (node is JsonValue value && value.TryGetValue<string>(out string? result))
            return result;
        throw new FormatException($"Dependency proof summary '{path}' must be a string");
    }

    private static string RequireNonEmptyString(JsonNode? node, string path)
    {
        string value = RequireString(node, path);
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException($"Dependency proof summary '{path}' must be non-empty");
        return value;
    }

    private static string RequireSupportedNeoAbiType(JsonNode? node, string path, bool allowVoid)
    {
        string value = RequireNonEmptyString(node, path);
        return RequireSupportedNeoAbiType(value, path, allowVoid);
    }

    private static string RequireSupportedNeoAbiType(string value, string path, bool allowVoid)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException($"Dependency proof summary '{path}' must be non-empty");

        var supportedTypes = allowVoid ? NeoAbiReturnTypes : NeoAbiParameterTypes;
        if (!supportedTypes.Contains(value))
        {
            throw new FormatException(
                $"Dependency proof summary '{path}' uses unsupported Neo ABI type '{value}'");
        }

        return value;
    }

    private static string? OptionalString(JsonObject obj, string key, string path)
    {
        if (!obj.TryGetPropertyValue(key, out JsonNode? node) || node is null)
            return null;
        string value = RequireString(node, path);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static string RequireSha256(JsonNode? node, string path)
    {
        string value = RequireString(node, path);
        if (value.Length != 64)
            throw new FormatException($"Dependency proof summary '{path}' must be a SHA-256 hex string");
        try
        {
            _ = Convert.FromHexString(value);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"Dependency proof summary '{path}' must be hexadecimal", ex);
        }

        return value.ToLowerInvariant();
    }

    private static string? OptionalUInt160Hex(JsonObject obj, string key, string path)
    {
        string? value = OptionalString(obj, key, path);
        if (value is null)
            return null;
        try
        {
            return ContractIdentity.NormalizeUInt160LittleEndianHex(value);
        }
        catch (ArgumentException ex)
        {
            throw new FormatException($"Dependency proof summary '{path}' must be a 20-byte UInt160 hex string", ex);
        }
    }

    private static string? OptionalNefChecksumHex(JsonObject obj, string key, string path)
    {
        string? value = OptionalString(obj, key, path);
        if (value is null)
            return null;

        string hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value[2..]
            : value;
        if (hex.Length != 8)
            throw new FormatException($"Dependency proof summary '{path}' must be a 4-byte NEF checksum hex string");

        try
        {
            _ = Convert.FromHexString(hex);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"Dependency proof summary '{path}' must be hexadecimal", ex);
        }

        return "0x" + hex.ToLowerInvariant();
    }

    private static bool RequireBool(JsonNode? node, string path)
    {
        if (node is JsonValue value && value.TryGetValue<bool>(out bool result))
            return result;
        throw new FormatException($"Dependency proof summary '{path}' must be a boolean");
    }

    private static int RequireCallFlags(JsonNode? node, string path)
    {
        int flags = OptionalInt(node, path);
        if (flags < NeoCallFlags.None || flags > NeoCallFlags.All)
        {
            throw new FormatException(
                $"Dependency proof summary '{path}' must be between {NeoCallFlags.None} and {NeoCallFlags.All}");
        }

        return flags;
    }

    private static int? OptionalRuntimeTrigger(JsonObject obj, string key, string path)
    {
        if (!obj.TryGetPropertyValue(key, out JsonNode? node) || node is null)
            return null;

        int trigger = OptionalInt(node, path);
        if (trigger is not (NeoTriggerTypes.Verification or NeoTriggerTypes.Application))
        {
            throw new FormatException(
                $"Dependency proof summary '{path}' must be {NeoTriggerTypes.Verification} (Verification) or {NeoTriggerTypes.Application} (Application)");
        }

        return trigger;
    }

    private static bool OptionalBool(JsonObject obj, string key, string path, bool defaultValue)
    {
        if (!obj.TryGetPropertyValue(key, out JsonNode? node) || node is null)
            return defaultValue;
        if (node is JsonValue value && value.TryGetValue<bool>(out bool result))
            return result;
        throw new FormatException($"Dependency proof summary '{path}' must be a boolean");
    }

    private static int? OptionalInt(JsonObject obj, string key, string path)
    {
        if (!obj.TryGetPropertyValue(key, out JsonNode? node) || node is null)
            return null;
        return OptionalInt(node, path);
    }

    private static int OptionalInt(JsonObject obj, string key, string path, int defaultValue) =>
        OptionalInt(obj, key, path) ?? defaultValue;

    private static int OptionalInt(JsonNode? node, string path)
    {
        if (node is JsonValue value && value.TryGetValue<int>(out int result))
            return result;
        throw new FormatException($"Dependency proof summary '{path}' must be an integer");
    }

    private static string NormalizeHash(string value, string path)
    {
        string hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? value[2..]
            : value;
        if (hex.Length != 40)
            throw new FormatException($"Dependency proof summary '{path}' must be a 20-byte UInt160 hex string");
        try
        {
            _ = Convert.FromHexString(hex);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"Dependency proof summary '{path}' must be hexadecimal", ex);
        }

        return "0x" + hex.ToLowerInvariant();
    }

    private static string FormatHash(byte[] hash) =>
        "0x" + Convert.ToHexString(hash).ToLowerInvariant();

    private static string FormatCallFlags(int flags)
    {
        if (flags == NeoCallFlags.None)
            return "None";
        var names = new List<string>();
        if ((flags & NeoCallFlags.ReadStates) != 0) names.Add("ReadStates");
        if ((flags & NeoCallFlags.WriteStates) != 0) names.Add("WriteStates");
        if ((flags & NeoCallFlags.AllowCall) != 0) names.Add("AllowCall");
        if ((flags & NeoCallFlags.AllowNotify) != 0) names.Add("AllowNotify");
        int unknown = flags & ~NeoCallFlags.All;
        if (unknown != 0) names.Add("0x" + unknown.ToString("X"));
        return names.Count == 0 ? flags.ToString(System.Globalization.CultureInfo.InvariantCulture) : string.Join("|", names);
    }

    private static string FormatRuntimeTrigger(int trigger) =>
        trigger switch
        {
            NeoTriggerTypes.Application => "Application",
            NeoTriggerTypes.Verification => "Verification",
            _ => "unknown",
        };
}

public sealed record DependencyContractProofSummary(
    string Hash,
    DependencyProofMetadata Proof,
    ImmutableArray<DependencyMethodProofSummary> Methods);

public sealed record DependencyProofMetadata(
    string Tool,
    string ToolVersion,
    string SourceProfile,
    bool GatePassed,
    bool RequireExternalSmt,
    bool RequireUnqualifiedProofs,
    int AssumptionBackedProofs,
    string ProgramSha256,
    string ManifestSha256,
    string ContractHash,
    string? DeploySenderHash,
    string? NefChecksumHex,
    string? SmtSolverVersion,
    ImmutableArray<DependencyProofSummaryReference> DependencyProofSummaries = default)
{
    public static DependencyProofMetadata FromReport(VerificationReport report, string contractHash)
    {
        if (report.Meta.Inputs is not { } inputs)
            throw new InvalidOperationException("dependency proof summary emission requires verification input provenance");
        if (report.GateEvaluation is not { } gate)
            throw new InvalidOperationException("dependency proof summary emission requires verification gate metadata");
        if (!gate.Passed)
            throw new InvalidOperationException("dependency proof summary emission requires a passed verification gate");
        if (!gate.Policies.FailOnUnproved)
            throw new InvalidOperationException("dependency proof summary emission requires the fail-on-unproved gate policy");
        if (gate.Unproved)
            throw new InvalidOperationException("dependency proof summary emission requires zero unproved verification results");
        if (!gate.Policies.RequireUnqualifiedProofs)
        {
            throw new InvalidOperationException(
                "dependency proof summary emission requires the unqualified-proof gate policy");
        }

        if (gate.AssumptionBackedProofs != 0)
            throw new InvalidOperationException("dependency proof summary emission requires zero assumption-backed proofs");

        if (report.Meta.ContractIdentity?.ContractHash is not { } reportContractHash
            || string.IsNullOrWhiteSpace(reportContractHash))
        {
            throw new InvalidOperationException(
                "dependency proof summary emission requires verification report contract identity with a contract hash");
        }

        string normalizedContractHash = NormalizeContractHashForEmission(contractHash, "contract_hash");
        string normalizedReportContractHash = NormalizeContractHashForEmission(
            reportContractHash,
            "verification report contract identity contract_hash");
        if (!string.Equals(normalizedContractHash, normalizedReportContractHash, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                "dependency proof summary contract hash must match verification report contract identity");
        }

        return new DependencyProofMetadata(
            report.Meta.Tool,
            report.Meta.Version,
            FormalVerifier.NeoN3SecurityProfile,
            gate.Passed,
            gate.Policies.RequireExternalSmt,
            gate.Policies.RequireUnqualifiedProofs,
            gate.AssumptionBackedProofs,
            inputs.ProgramSha256,
            inputs.ManifestSha256,
            normalizedContractHash,
            report.Meta.ContractIdentity?.DeploySenderHash,
            report.Meta.ContractIdentity?.NefChecksumHex,
            report.Meta.SmtSolverVersion,
            DependencyProofSummaryReferencesFromInputs(inputs));
    }

    private static ImmutableArray<DependencyProofSummaryReference> DependencyProofSummaryReferencesFromInputs(
        VerificationInputProvenance inputs)
    {
        if (inputs.DependencyProofSummaries.IsDefaultOrEmpty)
            return ImmutableArray<DependencyProofSummaryReference>.Empty;

        if (inputs.DependencyProofPolicy is not { } policy)
        {
            throw new InvalidOperationException(
                "dependency proof summary emission requires dependency proof policy metadata for transitive dependency summaries");
        }

        if (!policy.TrustedForExternalCalls)
        {
            throw new InvalidOperationException(
                "dependency proof summary emission cannot depend on untrusted transitive dependency proof summaries");
        }

        if (!policy.ArtifactBindingRequired || policy.UnboundSummariesAllowed)
        {
            throw new InvalidOperationException(
                "dependency proof summary emission cannot depend on unbound transitive dependency proof summaries");
        }

        return inputs.DependencyProofSummaries
            .Select(summary => new DependencyProofSummaryReference(NormalizeSha256ForEmission(summary.Sha256)))
            .Distinct()
            .OrderBy(summary => summary.Sha256, StringComparer.Ordinal)
            .ToImmutableArray();
    }

    private static string NormalizeSha256ForEmission(string value)
    {
        if (value.Length != 64)
            throw new InvalidOperationException("dependency proof summary emission requires transitive dependency summary SHA-256 values");

        try
        {
            _ = Convert.FromHexString(value);
        }
        catch (FormatException ex)
        {
            throw new InvalidOperationException(
                "dependency proof summary emission requires transitive dependency summary SHA-256 values",
                ex);
        }

        return value.ToLowerInvariant();
    }

    private static string NormalizeContractHashForEmission(string value, string path)
    {
        try
        {
            return "0x" + ContractIdentity.NormalizeUInt160LittleEndianHex(value);
        }
        catch (ArgumentException ex)
        {
            throw new InvalidOperationException(
                $"dependency proof summary emission requires a valid {path}",
                ex);
        }
    }
}

public sealed record DependencyProofSummaryReference(string Sha256);

public sealed record DependencyProofArtifactBinding(
    string ContractHash,
    string ProgramPath,
    string ManifestPath);

public sealed record DependencyMethodProofSummary(
    string Name,
    int ParameterCount,
    ImmutableArray<DependencyMethodParameterProofSummary> Parameters,
    string ReturnType,
    int InitialCallFlags,
    int? InitialRuntimeTrigger,
    bool FaultFree)
{
    public bool HasReturnValue => !string.Equals(ReturnType, "Void", StringComparison.OrdinalIgnoreCase);
}

public sealed record DependencyMethodParameterProofSummary(
    string Name,
    string Type);

public sealed record DependencyProofCoverage(
    bool IsCovered,
    string? Reason,
    DependencyMethodProofSummary? Method,
    bool UsesUnboundArtifactTrust = false)
{
    public static DependencyProofCoverage Covered(
        DependencyMethodProofSummary method,
        bool usesUnboundArtifactTrust = false) =>
        new(true, null, method, usesUnboundArtifactTrust);

    public static DependencyProofCoverage NotCovered(string reason) => new(false, reason, null);
}
