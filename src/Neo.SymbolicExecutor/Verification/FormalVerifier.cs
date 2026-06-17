using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    internal const string NeoN3SecurityProfile = "neo-n3-security";
    private const int Nep11MaxTokenIdLength = 64;
    private const int ModPowInverseWitnessSearchLimit = 64;
    private const int Hash160ByteLength = 20;
    private const int Hash256ByteLength = 32;
    private const int Ed25519PublicKeyByteLength = 32;
    private const int CompressedPublicKeyByteLength = 33;
    private const int SignatureByteLength = 64;
    private const int NeoVmIntegerMaxBytes = 32;
    private const int FindOptionsKeysOnly = 1 << 0;
    private const int FindOptionsRemovePrefix = 1 << 1;
    private static readonly VerificationAssumption NepTokenStorageIntegerEncodingAssumption = new(
        "nep_token_storage_integer_encoding",
        "Storage.Get values used as NEP token integers are present and encoded as NeoVM integers within the 32-byte StackItem integer bound.",
        NeoN3SecurityProfile);
    private static readonly VerificationAssumption Nep11OwnerStorageHash160EncodingAssumption = new(
        "nep11_owner_storage_hash160_encoding",
        "Storage.Get values used as non-divisible NEP-11 ownerOf(tokenId) owners are either missing/null or encoded as 20-byte UInt160 values.",
        NeoN3SecurityProfile);
    private static readonly VerificationAssumption UnboundDependencyProofSummaryAssumption = new(
        "unbound_dependency_proof_summary",
        "External callee semantics were accepted from a trusted dependency proof summary without local NEF/manifest artifact binding; the callee artifacts were checked outside this verification run.",
        NeoN3SecurityProfile);
    private static readonly System.Text.UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);
    private static readonly HashSet<string> NeoN3SecurityProfileCoveredStandards = new(StringComparer.Ordinal)
    {
        NormalizeProfileStandardTag("NEP-17"),
        NormalizeProfileStandardTag("NEP-11"),
        NormalizeProfileStandardTag("NEP-24"),
        NormalizeProfileStandardTag("NEP-27"),
        NormalizeProfileStandardTag("NEP-26"),
    };

    public static VerificationReport Verify(
        NeoProgram program,
        ContractManifest manifest,
        VerificationSpec spec,
        ExecutionOptions options,
        ISmtBackend? smtBackend,
        int maxProfileEntrypoints = 128,
        byte[]? contractHash = null,
        DependencyProofSummarySet? dependencyProofs = null,
        bool requireExternalSmtDependencyProofs = false)
    {
        dependencyProofs ??= DependencyProofSummarySet.Empty;
        if (contractHash is { Length: Hash160ByteLength })
            options = options with { CurrentScriptHash = contractHash.ToImmutableArray() };

        var results = ImmutableArray.CreateBuilder<VerificationPropertyResult>();
        int totalStates = 0;
        int totalSteps = 0;
        bool budgetExceeded = false;
        string? budgetReason = null;
        bool coverageIncomplete = false;
        var coverageReasons = new List<string>();

        foreach (var property in spec.Properties)
        {
            var result = VerifyProperty(
                program,
                manifest,
                property,
                options,
                smtBackend,
                dependencyProofs,
                requireExternalSmtDependencyProofs);
            results.Add(result.Result);
            totalStates += result.StatesExplored;
            totalSteps += result.StepsExecuted;
            if (result.BudgetExceeded)
            {
                budgetExceeded = true;
                budgetReason ??= result.BudgetReason;
            }
            if (result.CoverageIncomplete)
            {
                coverageIncomplete = true;
                if (!string.IsNullOrWhiteSpace(result.CoverageReason))
                    coverageReasons.Add(result.CoverageReason);
            }
        }

        foreach (var profile in spec.Profiles)
        {
            foreach (var result in VerifyProfile(
                program,
                manifest,
                profile,
                options,
                smtBackend,
                maxProfileEntrypoints,
                contractHash,
                dependencyProofs,
                requireExternalSmtDependencyProofs))
            {
                results.Add(result.Result);
                totalStates += result.StatesExplored;
                totalSteps += result.StepsExecuted;
                if (result.BudgetExceeded)
                {
                    budgetExceeded = true;
                    budgetReason ??= result.BudgetReason;
                }
                if (result.CoverageIncomplete)
                {
                    coverageIncomplete = true;
                    if (!string.IsNullOrWhiteSpace(result.CoverageReason))
                        coverageReasons.Add(result.CoverageReason);
                }
            }
        }

        var immutableResults = results.ToImmutable();
        var summary = VerificationSummary.FromResults(immutableResults);
        var meta = new VerificationMeta(
            StatesExplored: totalStates,
            StepsExecuted: totalSteps,
            BudgetExceeded: budgetExceeded,
            BudgetReason: budgetReason,
            CoverageIncomplete: coverageIncomplete || summary.Incomplete > 0,
            CoverageReason: coverageReasons.Count > 0
                ? string.Join("; ", coverageReasons.Distinct(StringComparer.Ordinal))
                : null,
            SmtAvailable: smtBackend?.IsExternalSolver ?? false,
            SmtEngaged: smtBackend is not null,
            SpecVersion: spec.Version)
        {
            Profiles = spec.Profiles,
            SmtStats = smtBackend?.GetStats(),
        };
        return new VerificationReport(meta, summary, immutableResults);
    }

    private static PropertyRunResult VerifyProperty(
        NeoProgram program,
        ContractManifest manifest,
        VerificationProperty property,
        ExecutionOptions options,
        ISmtBackend? smtBackend,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        var matchingMethods = manifest.Abi.Methods
            .Where(m => string.Equals(m.Name, property.Method, StringComparison.Ordinal))
            .ToArray();
        if (matchingMethods.Length == 0)
        {
            return PropertyRunResult.Incomplete(property, $"manifest has no ABI method named '{property.Method}'");
        }
        if (property.MethodOffset is int methodOffset)
        {
            matchingMethods = matchingMethods
                .Where(m => m.Offset == methodOffset)
                .ToArray();
            if (matchingMethods.Length == 0)
            {
                return PropertyRunResult.Incomplete(
                    property,
                    $"manifest has no ABI method named '{property.Method}' at offset {methodOffset}");
            }
        }
        if (!property.ParameterTypes.IsDefaultOrEmpty)
        {
            matchingMethods = matchingMethods
                .Where(m => MethodParameterTypesMatch(m, property.ParameterTypes))
                .ToArray();
            if (matchingMethods.Length == 0)
            {
                string signature = string.Join(", ", property.ParameterTypes);
                string offsetQualifier = property.MethodOffset is int selectedOffset
                    ? $" at offset {selectedOffset}"
                    : "";
                return PropertyRunResult.Incomplete(
                    property,
                    $"manifest has no ABI method named '{property.Method}'{offsetQualifier} with parameter_types [{signature}]");
            }
        }
        if (matchingMethods.Length > 1)
        {
            string offsets = string.Join(", ", matchingMethods.Select(m => $"{m.Name}@{m.Offset}"));
            string qualifier = property.MethodOffset is int
                ? $"named '{property.Method}' at offset {property.MethodOffset}"
                : $"named '{property.Method}'";
            string guidance = property.MethodOffset is int
                ? "custom specs must target a unique ABI method entrypoint"
                : "custom specs must target a unique ABI method name or specify method_offset/parameter_types";
            return PropertyRunResult.Incomplete(
                property,
                $"manifest has multiple ABI methods {qualifier} ({offsets}); {guidance}");
        }

        var method = matchingMethods[0];
        if (ManifestMethodEntryOffsetCoverageReason(program, method) is { } methodOffsetReason)
            return PropertyRunResult.Incomplete(
                property,
                methodOffsetReason);

        if (CustomSpecMethodEntryCoverageReason(method, property) is { } coverageReason)
            return PropertyRunResult.Incomplete(property, coverageReason);

        if (DuplicateParameterNameReason(method) is { } duplicateParameterReason)
            return PropertyRunResult.Incomplete(property, duplicateParameterReason);

        if (ReturnConditionCompatibilityReason(method, property) is { } returnConditionReason)
            return PropertyRunResult.Incomplete(property, returnConditionReason);

        if (CustomSpecAuthorizationTargetCompatibilityReason(method, property) is { } authTargetReason)
            return PropertyRunResult.Incomplete(property, authTargetReason);

        var methodOptions = OptionsForMethod(manifest, method, options);
        if (InputRequiresFeasibilityReason(program, methodOptions, method, property, smtBackend) is { } requiresReason)
            return PropertyRunResult.Incomplete(property, requiresReason);

        var execution = RunMethodEntry(program, methodOptions, method);
        var currentScriptHash = CurrentScriptHashForProgram(program, methodOptions);
        var result = VerifyPropertyOnExecution(
            manifest,
            method,
            property,
            execution,
            currentScriptHash,
            smtBackend,
            dependencyProofs,
            requireExternalSmtDependencyProofs) with
        {
            MethodOffset = method.Offset,
        };
        return new PropertyRunResult(
            result,
            execution);
    }

    private static bool MethodParameterTypesMatch(
        ContractMethodDescriptor method,
        ImmutableArray<string> parameterTypes)
    {
        if (method.Parameters.Count != parameterTypes.Length)
            return false;

        for (int i = 0; i < parameterTypes.Length; i++)
        {
            string actual = string.IsNullOrWhiteSpace(method.Parameters[i].Type)
                ? "Any"
                : method.Parameters[i].Type!;
            if (!string.Equals(actual, parameterTypes[i], StringComparison.OrdinalIgnoreCase))
                return false;
        }
        return true;
    }

    private static string? DuplicateParameterNameReason(ContractMethodDescriptor method)
    {
        var duplicates = method.Parameters
            .Select((parameter, index) => new
            {
                Name = parameter.Name,
                Index = index,
            })
            .Where(p => !string.IsNullOrWhiteSpace(p.Name))
            .GroupBy(p => p.Name!, StringComparer.Ordinal)
            .Where(group => group.Count() > 1)
            .Select(group => $"'{group.Key}' at indexes {string.Join(", ", group.Select(p => p.Index))}")
            .ToArray();

        return duplicates.Length == 0
            ? null
            : $"manifest method '{method.Name}' has duplicate ABI parameter name(s) {string.Join("; ", duplicates)}; custom specs use parameter names and cannot bind ambiguous arguments soundly";
    }

    private static string? ProfileDuplicateParameterNameReason(ContractMethodDescriptor method)
    {
        if (DuplicateParameterNameReason(method) is not { } reason)
            return null;

        return reason.Replace(
            "custom specs use parameter names",
            "the Neo N3 security profile uses ABI parameter names",
            StringComparison.Ordinal);
    }

    private static string? ReturnConditionCompatibilityReason(
        ContractMethodDescriptor method,
        VerificationProperty property)
    {
        if (!property.Requires.Any(c => c.IsReturn)
            && !property.Ensures.Any(c => c.IsReturn))
        {
            return null;
        }

        string returnType = string.IsNullOrWhiteSpace(method.ReturnType)
            ? "(missing)"
            : method.ReturnType;
        if (string.Equals(returnType, "(missing)", StringComparison.Ordinal)
            || IsAbiType(returnType, "Void"))
        {
            return $"manifest method '{method.Name}' declares return type '{returnType}', so return condition(s) cannot be evaluated soundly";
        }

        var returnConditions = property.Requires.Concat(property.Ensures)
            .Where(c => c.IsReturn)
            .ToArray();
        if (ReturnValueArgReferenceReason(method, returnConditions) is { } valueArgReferenceReason)
            return valueArgReferenceReason;

        if (IsAbiType(returnType, "Boolean"))
        {
            if (returnConditions.Any(c => c.Metric is not null))
                return $"manifest method '{method.Name}' declares return type 'Boolean', but a return condition uses a metric; return metrics require a ByteString-like ABI return";
            if (returnConditions.Any(c => c.HasByteValue))
                return $"manifest method '{method.Name}' declares return type 'Boolean', but a return condition uses a byte-string value; return condition(s) must compare $return to a boolean value";
            if (returnConditions.Any(c => c.IntegerValue.HasValue))
                return $"manifest method '{method.Name}' declares return type 'Boolean', but a return condition uses an integer value; return condition(s) must compare $return to a boolean value";
            foreach (var condition in returnConditions.Where(c => c.ValueArg is not null))
            {
                string valueArgType = MethodParameterType(method, condition.ValueArg!) ?? "Any";
                if (!IsAbiType(valueArgType, "Boolean"))
                    return $"manifest method '{method.Name}' declares return type 'Boolean', but return condition value_arg '{condition.ValueArg}' has type '{valueArgType}'; return condition(s) must compare $return to a boolean value";
            }
            return null;
        }

        if (IsAbiType(returnType, "Integer"))
        {
            if (returnConditions.Any(c => c.Metric is not null))
                return $"manifest method '{method.Name}' declares return type 'Integer', but a return condition uses a metric; return metrics require a ByteString-like ABI return";
            if (returnConditions.Any(c => c.HasByteValue))
                return $"manifest method '{method.Name}' declares return type 'Integer', but a return condition uses a byte-string value; return condition(s) must compare $return to an integer value";
            if (returnConditions.Any(c => c.BooleanValue.HasValue))
                return $"manifest method '{method.Name}' declares return type 'Integer', but a return condition uses a boolean value; return condition(s) must compare $return to an integer value";
            foreach (var condition in returnConditions.Where(c => c.ValueArg is not null))
            {
                string valueArgType = MethodParameterType(method, condition.ValueArg!) ?? "Any";
                if (!IsAbiType(valueArgType, "Integer"))
                    return $"manifest method '{method.Name}' declares return type 'Integer', but return condition value_arg '{condition.ValueArg}' has type '{valueArgType}'; return condition(s) must compare $return to an integer value";
            }
            return null;
        }

        if (IsReturnMetricByteStringLike(returnType))
        {
            if (returnConditions.Any(c => c.BooleanValue.HasValue))
                return $"manifest method '{method.Name}' declares return type '{returnType}', but a return condition uses a boolean value; ByteString-like return conditions must use an integer metric value";
            if (returnConditions.Any(c => c.Metric is not null && c.Metric is not ("size" or "first_byte")))
                return $"manifest method '{method.Name}' declares return type '{returnType}', but ByteString-like return metrics support only 'size' or 'first_byte'";
            foreach (var condition in returnConditions.Where(c => c.ValueArg is not null && c.Metric is null))
            {
                string valueArgType = MethodParameterType(method, condition.ValueArg!) ?? "Any";
                if (!IsVerificationByteStringLikeAbiType(valueArgType))
                    return $"manifest method '{method.Name}' declares return type '{returnType}', but return condition value_arg '{condition.ValueArg}' has type '{valueArgType}'; ByteString-like return condition(s) without a metric must compare $return to a ByteString-like value_arg";
            }
            if (returnConditions.Any(c => c.Metric is null && !c.HasByteValue && c.ValueArg is null))
                return $"manifest method '{method.Name}' declares return type '{returnType}', so integer return condition(s) must use a metric such as 'size' or 'first_byte'";
            return null;
        }

        if (IsReturnCountCompoundLike(returnType))
        {
            if (returnConditions.Any(c => c.BooleanValue.HasValue))
                return $"manifest method '{method.Name}' declares return type '{returnType}', but compound return conditions must use integer metric 'count'";
            if (returnConditions.Any(c => c.HasByteValue))
                return $"manifest method '{method.Name}' declares return type '{returnType}', but compound return conditions cannot compare byte-string values";
            if (returnConditions.Any(c => c.Metric is not "count"))
                return $"manifest method '{method.Name}' declares return type '{returnType}', but compound return conditions currently support only metric 'count'";
            return null;
        }

        return $"manifest method '{method.Name}' declares return type '{returnType}', but return conditions are currently supported only for Boolean, Integer, ByteString-like ABI returns with metrics or byte-string values, and Array/Struct/Map returns with count metrics";
    }

    private static string? ReturnValueArgReferenceReason(
        ContractMethodDescriptor method,
        IEnumerable<VerificationCondition> returnConditions)
    {
        foreach (var condition in returnConditions.Where(c => c.ValueArg is not null))
        {
            string valueArg = condition.ValueArg!;
            string? valueArgType = MethodParameterType(method, valueArg);
            if (valueArgType is null)
                return $"return condition uses value_arg '{valueArg}', but method '{method.Name}' has no ABI parameter named '{valueArg}'";
            if (condition.Metric is not null && !IsAbiType(valueArgType, "Integer"))
                return $"return condition metric '{condition.Metric}' uses value_arg '{valueArg}' with type '{valueArgType}', but metric comparisons require an Integer RHS";
        }

        return null;
    }

    private static string? MethodParameterType(ContractMethodDescriptor method, string parameterName)
    {
        foreach (var parameter in method.Parameters)
        {
            if (string.Equals(parameter.Name, parameterName, StringComparison.Ordinal))
                return parameter.Type ?? "Any";
        }

        return null;
    }

    private static string? CustomSpecAuthorizationTargetCompatibilityReason(
        ContractMethodDescriptor method,
        VerificationProperty property)
    {
        foreach (var condition in property.Requires.Concat(property.Ensures))
        {
            if (condition.WitnessTarget is { } witnessTarget
                && !condition.HasWitnessByteTarget
                && AuthTargetParameterCompatibilityReason(
                    method,
                    witnessTarget,
                    "witness",
                    "CheckWitness hash or public key",
                    IsWitnessTargetAbiType) is { } witnessReason)
            {
                return witnessReason;
            }

            if (condition.CallerHashTarget is { } callerHashTarget
                && !condition.HasCallerHashByteTarget
                && AuthTargetParameterCompatibilityReason(
                    method,
                    callerHashTarget,
                    "caller_hash",
                    "UInt160 caller hash",
                    IsCallerHashTargetAbiType) is { } callerHashReason)
            {
                return callerHashReason;
            }

            if (condition.SignatureCheckTarget is { } signatureCheckTarget
                && !condition.HasSignatureCheckByteTarget
                && AuthTargetParameterCompatibilityReason(
                    method,
                    signatureCheckTarget,
                    "signature_check",
                    "CheckSig/CheckMultisig public-key",
                    IsSignatureCheckTargetAbiType) is { } signatureCheckReason)
            {
                return signatureCheckReason;
            }
        }

        return null;
    }

    private static string? AuthTargetParameterCompatibilityReason(
        ContractMethodDescriptor method,
        string target,
        string conditionName,
        string expectedDescription,
        Func<string, bool> typeAllowed)
    {
        var parameter = method.Parameters.FirstOrDefault(p =>
            string.Equals(p.Name, target, StringComparison.Ordinal));
        if (parameter is null)
            return $"method '{method.Name}' has no ABI parameter named '{target}'";

        string parameterType = parameter.Type ?? "Any";
        return typeAllowed(parameterType)
            ? null
            : $"{conditionName} target ABI parameter '{target}' has type '{parameterType}' and cannot be used as a {expectedDescription} target";
    }

    private static bool IsWitnessTargetAbiType(string type) =>
        IsAbiType(type, "Hash160")
        || IsAbiType(type, "UInt160")
        || IsAbiType(type, "PublicKey")
        || IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray");

    private static bool IsCallerHashTargetAbiType(string type) =>
        IsAbiType(type, "Hash160")
        || IsAbiType(type, "UInt160")
        || IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray");

    private static bool IsSignatureCheckTargetAbiType(string type) =>
        IsAbiType(type, "Array")
        || IsAbiType(type, "PublicKey")
        || IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray");

    private static ExecutionOptions OptionsForMethod(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionOptions options)
    {
        var methodOptions = options with
        {
            SelfCallResolver = ManifestSelfCallResolver.Build(manifest),
        };
        return string.Equals(method.Name, "verify", StringComparison.Ordinal)
            ? methodOptions with { RuntimeTrigger = NeoTriggerTypes.Verification }
            : methodOptions;
    }

    private static ImmutableArray<byte> CurrentScriptHashForProgram(
        NeoProgram program,
        ExecutionOptions options)
    {
        if (!options.CurrentScriptHash.IsDefaultOrEmpty
            && options.CurrentScriptHash.Length == Hash160ByteLength)
        {
            return options.CurrentScriptHash;
        }

        return ComputeScriptHash(program.Bytes.ToArray()).ToImmutableArray();
    }

    private static byte[] ComputeScriptHash(byte[] script)
    {
        byte[] sha256 = System.Security.Cryptography.SHA256.HashData(script);
        var digest = new Org.BouncyCastle.Crypto.Digests.RipeMD160Digest();
        byte[] hash = new byte[digest.GetDigestSize()];
        digest.BlockUpdate(sha256, 0, sha256.Length);
        digest.DoFinal(hash, 0);
        return hash;
    }

    private static ExecutionResult RunMethodEntry(
        NeoProgram program,
        ExecutionOptions options,
        ContractMethodDescriptor method)
    {
        var entryBuilder = new SymbolicEngine(program, options);
        var entries = entryBuilder.CreateMethodEntryStates(method.Offset, method.Parameters);
        if (entries.Count == 1)
            return new SymbolicEngine(program, options).Run(entries[0]);

        var finalStates = ImmutableArray.CreateBuilder<ExecutionState>();
        int statesExplored = 0;
        int stepsExecuted = 0;
        bool budgetExceeded = false;
        bool coverageIncomplete = false;
        var budgetReasons = new List<string>();
        var coverageReasons = new List<string>();
        var skippedEntrypoints = ImmutableArray.CreateBuilder<string>();

        foreach (var entry in entries)
        {
            var execution = new SymbolicEngine(program, options).Run(entry);
            finalStates.AddRange(execution.FinalStates);
            statesExplored += execution.StatesExplored;
            stepsExecuted += execution.StepsExecuted;
            budgetExceeded |= execution.BudgetExceeded;
            coverageIncomplete |= execution.CoverageIncomplete;
            if (!string.IsNullOrWhiteSpace(execution.BudgetReason))
                budgetReasons.Add(execution.BudgetReason!);
            if (!string.IsNullOrWhiteSpace(execution.CoverageReason))
                coverageReasons.Add(execution.CoverageReason!);
            if (!execution.SkippedEntrypoints.IsDefaultOrEmpty)
                skippedEntrypoints.AddRange(execution.SkippedEntrypoints);
        }

        return new ExecutionResult(
            finalStates.ToImmutable(),
            statesExplored,
            stepsExecuted,
            budgetExceeded,
            budgetReasons.Count == 0
                ? null
                : string.Join("; ", budgetReasons.Distinct(StringComparer.Ordinal)),
            coverageIncomplete,
            coverageReasons.Count == 0
                ? null
                : string.Join("; ", coverageReasons.Distinct(StringComparer.Ordinal)),
            skippedEntrypoints.ToImmutable());
    }

    private static string? CustomSpecMethodEntryCoverageReason(
        ContractMethodDescriptor method,
        VerificationProperty? property = null)
    {
        var unsupportedParameters = method.Parameters
            .Select((parameter, index) => new { Parameter = parameter, Index = index })
            .Where(p => IsCustomSpecMethodEntryCoverageIncomplete(p.Parameter.Type))
            .Select(p =>
            {
                string name = string.IsNullOrWhiteSpace(p.Parameter.Name)
                    ? $"arg{p.Index}"
                    : p.Parameter.Name;
                string type = string.IsNullOrWhiteSpace(p.Parameter.Type) ? "Any" : p.Parameter.Type;
                return $"{name}:{type}";
            })
            .ToArray();

        if (unsupportedParameters.Length == 0)
            return null;

        string reason = $"manifest method '{method.Name}' has ABI parameter type(s) requiring non-exhaustive method-entry coverage ({string.Join(", ", unsupportedParameters)}); custom specs are incomplete because the current method-entry model cannot enumerate every NeoVM StackItem shape, collection length, and compound shape for these ABI inputs";

        if (property is not null)
        {
            string[] conditionContexts = CustomSpecConditionEntryCoverageContexts(method, property)
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            if (conditionContexts.Length > 0)
                reason += $"; {string.Join("; ", conditionContexts)}";
        }

        return reason;
    }

    private static string? ManifestMethodEntryOffsetCoverageReason(
        NeoProgram program,
        ContractMethodDescriptor method)
    {
        if (method.Offset < 0 || method.Offset >= program.Bytes.Length)
            return $"manifest method '{method.Name}' offset {method.Offset} is outside script bytes";

        if (!program.IsDecodedInstructionBoundary(method.Offset))
            return $"manifest method '{method.Name}' offset {method.Offset} is not a decoded instruction boundary";

        return null;
    }

    private static IEnumerable<string> CustomSpecConditionEntryCoverageContexts(
        ContractMethodDescriptor method,
        VerificationProperty property)
    {
        foreach (var condition in property.Requires.Concat(property.Ensures))
        {
            if (condition.SignatureCheckTarget is not { Length: > 0 } target)
                continue;

            var parameter = method.Parameters.FirstOrDefault(p =>
                string.Equals(p.Name, target, StringComparison.Ordinal));
            if (parameter is null || !IsAbiType(parameter.Type ?? "", "Array"))
                continue;

            yield return $"signature_check target '{target}' is an open ABI Array used as a CheckMultisig public-key list; dynamic multi-signature authorization remains incomplete unless the public-key array is closed/concrete";
        }
    }

    private static string? ProfileMethodEntryCoverageReason(ContractMethodDescriptor method)
    {
        if (CustomSpecMethodEntryCoverageReason(method) is not { } reason)
            return null;

        return reason.Replace(
            "custom specs are incomplete",
            "the Neo N3 security profile entrypoint coverage is incomplete",
            StringComparison.Ordinal);
    }

    private static bool ProfileStandardObligationsCoverNonExhaustiveParameters(
        ContractManifest manifest,
        ContractMethodDescriptor method)
    {
        if (!IsNep17TransferMethod(manifest, method)
            && !IsNep11NonDivisibleTransferMethod(manifest, method)
            && !IsNep11DivisibleTransferMethod(manifest, method)
            && !IsNep27ReceiverCallbackMethod(manifest, method)
            && !IsNep26ReceiverCallbackMethod(manifest, method))
        {
            return false;
        }

        return method.Parameters
            .Where(p => IsCustomSpecMethodEntryCoverageIncomplete(p.Type))
            .All(static p =>
                string.Equals(p.Name, "data", StringComparison.Ordinal)
                && IsAbiType(p.Type ?? "", "Any"));
    }

    private static bool IsCustomSpecMethodEntryCoverageIncomplete(string? type) =>
        string.IsNullOrWhiteSpace(type)
        || !IsKnownAbiParameterType(type)
        || IsAbiType(type, "Any")
        || IsAbiType(type, "Array")
        || IsAbiType(type, "Struct")
        || IsAbiType(type, "Map")
        || IsAbiType(type, "InteropInterface");

    private static bool IsKnownAbiParameterType(string type) =>
        IsAbiType(type, "Signature")
        || IsAbiType(type, "Boolean")
        || IsAbiType(type, "Integer")
        || IsAbiType(type, "Hash160")
        || IsAbiType(type, "UInt160")
        || IsAbiType(type, "Hash256")
        || IsAbiType(type, "UInt256")
        || IsAbiType(type, "ByteArray")
        || IsAbiType(type, "ByteString")
        || IsAbiType(type, "Buffer")
        || IsAbiType(type, "PublicKey")
        || IsAbiType(type, "String")
        || IsAbiType(type, "Array")
        || IsAbiType(type, "Struct")
        || IsAbiType(type, "Map")
        || IsAbiType(type, "InteropInterface")
        || IsAbiType(type, "Any");

    private static string? InputRequiresFeasibilityReason(
        NeoProgram program,
        ExecutionOptions options,
        ContractMethodDescriptor method,
        VerificationProperty property,
        ISmtBackend? smtBackend)
    {
        if (smtBackend is null)
            return null;

        ImmutableArray<Expression> inputRequires;
        try
        {
            inputRequires = property.Requires
                .Where(c => !c.RequiresExecutionState)
                .Select(c => c.ToExpression(method))
                .ToImmutableArray();
        }
        catch (FormatException fex)
        {
            return fex.Message;
        }

        if (inputRequires.Length == 0)
            return null;

        var entryBuilder = new SymbolicEngine(program, options);
        var entries = entryBuilder.CreateMethodEntryStates(method.Offset, method.Parameters);
        var sawUnknown = false;
        foreach (var entry in entries)
        {
            var query = BuildReachabilityQuery(inputRequires, entry.PathConditions);
            var outcome = smtBackend.IsSatisfiable(query);
            if (outcome == SmtOutcome.Sat)
                return null;
            if (outcome == SmtOutcome.Unknown)
                sawUnknown = true;
        }

        return sawUnknown
            ? $"solver returned unknown while checking input requires feasibility for manifest method '{method.Name}' against ABI method-entry constraints"
            : $"input requires for manifest method '{method.Name}' are infeasible under ABI method-entry constraints; proof would be vacuous";
    }

    private static VerificationPropertyResult VerifyPropertyOnExecution(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        VerificationProperty property,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        int checkedPaths = execution.FinalStates.Count(s => s.Status == TerminalStatus.Halted);
        int ignoredFaulted = property.ForbidFaults
            ? 0
            : execution.FinalStates.Count(s => s.Status == TerminalStatus.Faulted);
        int stopped = execution.FinalStates.Count(s => s.Status == TerminalStatus.Stopped);
        int obligations = 0;
        if (StorageReadCoverageReason(property, method, execution, currentScriptHash, smtBackend) is { } storageReadCoverageReason)
        {
            return new VerificationPropertyResult(
                property.Id,
                property.Method,
                property.Description,
                VerificationStatus.Incomplete,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                storageReadCoverageReason,
                FailedCondition: null,
                Counterexample: null);
        }
        if (StoragePutCoverageReason(property, method, execution, currentScriptHash, smtBackend) is { } storagePutCoverageReason)
        {
            return new VerificationPropertyResult(
                property.Id,
                property.Method,
                property.Description,
                VerificationStatus.Incomplete,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                storagePutCoverageReason,
                FailedCondition: null,
                Counterexample: null);
        }

        var unknownReasons = new List<string>();
        var incompleteReasons = new List<string>();
        bool requireSuccessfulHaltFeasible = property.HasPostconditionObligations;
        bool sawSuccessfulHaltFeasible = !requireSuccessfulHaltFeasible;
        bool successfulHaltReachabilityUnknown = false;

        foreach (var state in execution.FinalStates)
        {
            switch (state.Status)
            {
                case TerminalStatus.Halted:
                    var successfulPathConditions = SuccessfulHaltPathConditions(state);
                    if (HasReturnScopedConditions(property)
                        && ShouldSkipHaltedPathByNonReturnRequires(
                            method,
                            property,
                            state,
                            currentScriptHash,
                            successfulPathConditions,
                            smtBackend,
                            incompleteReasons,
                            unknownReasons))
                    {
                        break;
                    }

                    if (RuntimeReturnCompatibilityReason(method, property, state) is { } runtimeReturnReason)
                    {
                        incompleteReasons.Add(runtimeReturnReason);
                        break;
                    }

                    ImmutableArray<Expression> requires;
                    try
                    {
                        requires = property.Requires.Select(c => c.ToExpression(method, state, currentScriptHash)).ToImmutableArray();
                    }
                    catch (FormatException fex)
                    {
                        incompleteReasons.Add(fex.Message);
                        break;
                    }
                    try
                    {
                        _ = property.Ensures
                            .Where(c => !c.RequiresExecutionState)
                            .Select(c => c.ToExpression(method))
                            .ToImmutableArray();
                    }
                    catch (FormatException fex)
                    {
                        incompleteReasons.Add(fex.Message);
                        break;
                    }
                    if (requireSuccessfulHaltFeasible)
                    {
                        var reachability = BuildReachabilityQuery(
                            requires,
                            successfulPathConditions);
                        var reachabilityOutcome = smtBackend?.IsSatisfiable(reachability) ?? SmtOutcome.Unknown;
                        if (reachabilityOutcome == SmtOutcome.Sat)
                        {
                            sawSuccessfulHaltFeasible = true;
                        }
                        else if (reachabilityOutcome == SmtOutcome.Unsat)
                        {
                            break;
                        }
                        else if (reachabilityOutcome == SmtOutcome.Unknown)
                        {
                            successfulHaltReachabilityUnknown = true;
                        }
                    }

                    ImmutableArray<(VerificationCondition Condition, Expression Expression)> ensures;
                    try
                    {
                        ensures = property.Ensures
                            .Select(c => (Condition: c, Expression: c.ToExpression(method, state, currentScriptHash)))
                            .ToImmutableArray();
                    }
                    catch (FormatException fex)
                    {
                        incompleteReasons.Add(fex.Message);
                        break;
                    }
                    foreach (var ensure in ensures)
                    {
                        obligations++;
                        var query = BuildCounterexampleQuery(requires, successfulPathConditions, ensure.Expression);
                        var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
                        if (outcome == SmtOutcome.Sat)
                        {
                            var witness = smtBackend?.BuildWitness(query);
                            return new VerificationPropertyResult(
                                property.Id,
                                property.Method,
                                property.Description,
                                VerificationStatus.Violated,
                                checkedPaths,
                                ignoredFaulted,
                                stopped,
                                obligations,
                                $"counterexample satisfies path conditions and violates {ensure.Condition.Display(method)}",
                                ensure.Condition.Display(method),
                                witness is null ? null : ImmutableDictionary.CreateRange(witness));
                        }
                        if (outcome == SmtOutcome.Unknown)
                            unknownReasons.Add($"solver returned unknown for {ensure.Condition.Display(method)}");
                    }
                    if (CheckForbiddenSideEffects(
                            property,
                            state,
                            requires,
                            successfulPathConditions,
                            smtBackend,
                            checkedPaths,
                            ignoredFaulted,
                            stopped,
                            ref obligations,
                            unknownReasons) is { } forbiddenSideEffect)
                    {
                        return forbiddenSideEffect;
                    }
                    if (property.ForbidFaults
                        && CheckArithmeticDefinedness(
                            method,
                            property,
                            state,
                            requires,
                            smtBackend,
                            checkedPaths,
                            ignoredFaulted,
                            stopped,
                            ref obligations,
                            unknownReasons) is { } arithmeticFault)
                    {
                        return arithmeticFault;
                    }
                    if (property.ForbidFaults
                        && CheckFaultPreconditions(
                            property,
                            state,
                            requires,
                            smtBackend,
                            checkedPaths,
                            ignoredFaulted,
                            stopped,
                            ref obligations,
                            unknownReasons) is { } syscallFault)
                    {
                        return syscallFault;
                    }
                    if (property.ForbidFaults
                        && CheckRuntimeNotificationManifest(
                            manifest,
                            property,
                            state,
                            currentScriptHash,
                            requires,
                            smtBackend,
                            checkedPaths,
                            ignoredFaulted,
                            stopped,
                            ref obligations,
                            unknownReasons,
                            incompleteReasons) is { } notificationFault)
                    {
                        return notificationFault;
                    }
                    if (property.ForbidFaults
                        && CheckContractCallAbi(
                            manifest,
                            property,
                            state,
                            currentScriptHash,
                            requires,
                            smtBackend,
                            checkedPaths,
                            ignoredFaulted,
                            stopped,
                            ref obligations,
                            unknownReasons,
                            incompleteReasons) is { } contractCallFault)
                    {
                        return contractCallFault;
                    }
                    if (property.RequireExternalCallCompleteness
                        && (property.ForbidFaults || property.HasPostconditionObligations))
                    {
                        var externalCompletenessReasons = CustomExternalCallCompletenessReasons(
                            state,
                            dependencyProofs,
                            requireExternalSmtDependencyProofs).ToArray();
                        if (externalCompletenessReasons.Length > 0
                            && ShouldCheckHaltedPathUnderRequires(
                                "external call completeness checks",
                                state,
                                requires,
                                smtBackend,
                                ref obligations,
                                unknownReasons))
                        {
                            incompleteReasons.AddRange(externalCompletenessReasons);
                        }
                    }
                    break;

                case TerminalStatus.Faulted:
                    if (!property.ForbidFaults)
                        break;

                    if (property.Requires.Any(c => c.IsReturn))
                    {
                        incompleteReasons.Add(
                            "return-scoped requires cannot be evaluated on a faulted path because only successful HALT paths have a method return value");
                        break;
                    }

                    ImmutableArray<Expression> faultRequires;
                    try
                    {
                        faultRequires = property.Requires.Select(c => c.ToExpression(method, state, currentScriptHash)).ToImmutableArray();
                    }
                    catch (FormatException fex)
                    {
                        incompleteReasons.Add(fex.Message);
                        break;
                    }

                    obligations++;
                    var faultQuery = BuildReachabilityQuery(faultRequires, state.PathConditions);
                    var faultOutcome = smtBackend?.IsSatisfiable(faultQuery) ?? SmtOutcome.Unknown;
                    if (faultOutcome == SmtOutcome.Sat)
                    {
                        var witness = smtBackend?.BuildWitness(faultQuery);
                        return new VerificationPropertyResult(
                            property.Id,
                            property.Method,
                            property.Description,
                            VerificationStatus.Violated,
                            checkedPaths,
                            ignoredFaulted,
                            stopped,
                            obligations,
                            $"faulted path is reachable under requires: {state.TerminationReason ?? "VM fault"}",
                            "no fault under requires",
                            witness is null ? null : ImmutableDictionary.CreateRange(witness));
                    }
                    if (faultOutcome == SmtOutcome.Unknown)
                    {
                        unknownReasons.Add(
                            $"solver returned unknown for fault reachability: {state.TerminationReason ?? "VM fault"}");
                    }
                    break;

                case TerminalStatus.Stopped:
                    incompleteReasons.Add(state.TerminationReason ?? "stopped before verification reached a terminal verdict");
                    break;
            }
        }

        incompleteReasons.AddRange(IncompleteReasons(execution));
        if (property.HasPostconditionObligations && checkedPaths == 0)
            incompleteReasons.Add("postconditions require at least one successful HALT path; method reached no successful HALT paths");
        if (requireSuccessfulHaltFeasible && !sawSuccessfulHaltFeasible)
        {
            if (successfulHaltReachabilityUnknown)
            {
                unknownReasons.Add(
                    "solver returned unknown while checking whether any successful HALT path satisfies requires");
            }
            else
            {
                incompleteReasons.Add(
                    "postconditions require at least one successful HALT path satisfying requires; no successful HALT path is feasible under requires");
            }
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                property.Id,
                property.Method,
                property.Description,
                VerificationStatus.Incomplete,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }

        if (unknownReasons.Count > 0 || smtBackend is null)
        {
            return new VerificationPropertyResult(
                property.Id,
                property.Method,
                property.Description,
                VerificationStatus.Unknown,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                smtBackend is null
                    ? "no SMT backend was provided"
                    : string.Join("; ", unknownReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }

        return new VerificationPropertyResult(
            property.Id,
            property.Method,
            property.Description,
            VerificationStatus.Proved,
            checkedPaths,
            ignoredFaulted,
            stopped,
            obligations,
            ProvedReason(property, checkedPaths),
            FailedCondition: null,
            Counterexample: null);
    }

    private static bool HasReturnScopedConditions(VerificationProperty property) =>
        property.Requires.Concat(property.Ensures).Any(c => c.IsReturn);

    private static bool ShouldSkipHaltedPathByNonReturnRequires(
        ContractMethodDescriptor method,
        VerificationProperty property,
        ExecutionState state,
        ImmutableArray<byte> currentScriptHash,
        IReadOnlyList<Expression> successfulPathConditions,
        ISmtBackend? smtBackend,
        List<string> incompleteReasons,
        List<string> unknownReasons)
    {
        ImmutableArray<Expression> nonReturnRequires;
        try
        {
            nonReturnRequires = property.Requires
                .Where(c => !c.IsReturn)
                .Select(c => c.ToExpression(method, state, currentScriptHash))
                .ToImmutableArray();
        }
        catch (FormatException fex)
        {
            incompleteReasons.Add(fex.Message);
            return false;
        }

        if (nonReturnRequires.Length == 0)
            return false;

        var reachability = BuildReachabilityQuery(nonReturnRequires, successfulPathConditions);
        var outcome = smtBackend?.IsSatisfiable(reachability) ?? SmtOutcome.Unknown;
        if (outcome == SmtOutcome.Unsat)
            return true;

        if (outcome == SmtOutcome.Unknown)
        {
            unknownReasons.Add(
                "solver returned unknown while checking whether non-return requires exclude a successful HALT path before return condition evaluation");
        }

        return false;
    }

    private static string? RuntimeReturnCompatibilityReason(
        ContractMethodDescriptor method,
        VerificationProperty property,
        ExecutionState state)
    {
        if (!HasReturnScopedConditions(property))
            return null;
        if (state.EvaluationStack.Count == 0)
            return null;

        var returned = state.Peek();
        if (IsAbiType(method.ReturnType, "Boolean"))
        {
            return returned.Sort == Sort.Bool
                ? null
                : $"manifest method '{method.Name}' declares return type 'Boolean', but a successful HALT path returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem; return condition(s) cannot be evaluated soundly";
        }

        if (IsAbiType(method.ReturnType, "Integer"))
        {
            return returned.Sort == Sort.Int
                ? null
                : $"manifest method '{method.Name}' declares return type 'Integer', but a successful HALT path returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem; return condition(s) cannot be evaluated soundly";
        }

        if (property.Requires.Concat(property.Ensures).Any(c => c.IsReturn && (c.Metric is not null || c.HasByteValue))
            && IsReturnMetricByteStringLike(method.ReturnType))
        {
            return IsRuntimeByteStringLike(returned)
                ? null
                : $"manifest method '{method.Name}' declares return type '{method.ReturnType}', but a successful HALT path returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem; return metric or byte-string condition(s) cannot be evaluated soundly";
        }

        if (property.Requires.Concat(property.Ensures).Any(c => c.IsReturn && c.Metric == "count")
            && TryGetCompoundReturnSort(method.ReturnType, out var expectedSort))
        {
            if (returned.Expression is not HeapRef { RefSort: var actualSort } href
                || actualSort != expectedSort)
            {
                return $"manifest method '{method.Name}' declares return type '{method.ReturnType}', but a successful HALT path returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem; return count condition(s) cannot be evaluated soundly";
            }

            _ = state.Heap.Get(href.ObjectId);
        }

        return null;
    }

    private static VerificationPropertyResult? CheckForbiddenSideEffects(
        VerificationProperty property,
        ExecutionState state,
        ImmutableArray<Expression> requires,
        IReadOnlyList<Expression> successfulPathConditions,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        ref int obligations,
        List<string> unknownReasons)
    {
        if (!property.HasForbiddenSideEffectObligations)
            return null;

        var effects = ImmutableArray.CreateBuilder<ForbiddenSideEffect>();
        if (property.ForbidStorageMutation)
        {
            foreach (var op in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                string opName = op.Kind == StorageOpKind.Put ? "Storage.Put" : "Storage.Delete";
                effects.Add(new ForbiddenSideEffect(
                    op.Offset,
                    $"{opName} at {FormatOffset(op.Offset)}",
                    "no Storage.Put or Storage.Delete under requires"));
            }

            foreach (var call in state.Telemetry.ExternalCalls
                         .Where(call => !call.ModeledSelfCall && NativeCallMayMutateStorage(call))
                         .OrderBy(call => call.Offset))
            {
                effects.Add(new ForbiddenSideEffect(
                    call.Offset,
                    NativeSideEffectDisplay(call),
                    "no Storage.Put, Storage.Delete, or native storage mutation under requires"));
            }
        }

        if (property.ForbidExternalCalls)
        {
            foreach (var call in state.Telemetry.ExternalCalls
                         .Where(call => !call.ModeledSelfCall)
                         .OrderBy(call => call.Offset))
            {
                effects.Add(new ForbiddenSideEffect(
                    call.Offset,
                    ForbiddenExternalCallDisplay(call),
                    "no external calls under requires"));
            }
        }

        if (property.ForbidNotifications)
        {
            foreach (var notification in state.Telemetry.Notifications.OrderBy(notification => notification.Offset))
            {
                effects.Add(new ForbiddenSideEffect(
                    notification.Offset,
                    ForbiddenRuntimeNotificationDisplay(notification),
                    "no Runtime.Notify under requires"));
            }

            foreach (var call in state.Telemetry.ExternalCalls
                         .Where(call => !call.ModeledSelfCall && NativeCallMayEmitNotification(call))
                         .OrderBy(call => call.Offset))
            {
                effects.Add(new ForbiddenSideEffect(
                    call.Offset,
                    NativeSideEffectDisplay(call),
                    "no Runtime.Notify or native notifications under requires"));
            }
        }

        if (effects.Count == 0)
            return null;

        var reachabilityQuery = BuildReachabilityQuery(requires, successfulPathConditions);
        SmtOutcome? reachabilityOutcome = null;
        foreach (var effect in effects.OrderBy(effect => effect.Offset))
        {
            obligations++;
            reachabilityOutcome ??= smtBackend?.IsSatisfiable(reachabilityQuery) ?? SmtOutcome.Unknown;
            if (reachabilityOutcome == SmtOutcome.Sat)
            {
                return new VerificationPropertyResult(
                    property.Id,
                    property.Method,
                    property.Description,
                    VerificationStatus.Violated,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    $"{effect.Display} is reachable on a successful HALT path under requires",
                    effect.FailedCondition,
                    BuildWitness(smtBackend, reachabilityQuery));
            }

            if (reachabilityOutcome == SmtOutcome.Unknown)
            {
                unknownReasons.Add(
                    $"solver returned unknown while checking whether {effect.Display} is reachable under requires");
            }
        }

        return null;
    }

    private static string ForbiddenExternalCallDisplay(ExternalCall call)
    {
        if (IsRuntimeLoadScriptCall(call))
            return $"Runtime.LoadScript at {FormatOffset(call.Offset)}";

        string callKind = call.ReturnValueDeclaredByMethodToken
            ? "CALLT"
            : "external Contract.Call";
        if (call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>")
            return $"{callKind} at {FormatOffset(call.Offset)} with a dynamic or unknown method selector";

        return $"{callKind} at {FormatOffset(call.Offset)} method '{call.Method}'";
    }

    private static string ForbiddenRuntimeNotificationDisplay(RuntimeNotification notification)
    {
        if (string.IsNullOrWhiteSpace(notification.ConcreteName))
            return $"Runtime.Notify at {FormatOffset(notification.Offset)} with a dynamic or unknown event name";

        return $"Runtime.Notify '{notification.ConcreteName}' at {FormatOffset(notification.Offset)}";
    }

    private static string NativeSideEffectDisplay(ExternalCall call) =>
        $"{ExternalCallDisplay(call)} at {FormatOffset(call.Offset)}";

    private static bool NativeCallMayMutateStorage(ExternalCall call) =>
        IsContractManagementLifecycleCall(call)
        || IsOracleRequestCall(call)
        || IsNativeTokenTransferCall(call);

    private static bool NativeCallMayEmitNotification(ExternalCall call) =>
        IsContractManagementLifecycleCall(call)
        || IsOracleRequestCall(call);

    private static bool IsContractManagementLifecycleCall(ExternalCall call)
    {
        if (call.MethodDynamic
            || call.TargetHash?.AsConcreteBytes() is not { } targetHash
            || !BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.ContractManagement)))
        {
            return false;
        }

        return string.Equals(call.Method, "deploy", StringComparison.Ordinal)
            || string.Equals(call.Method, "update", StringComparison.Ordinal)
            || string.Equals(call.Method, "destroy", StringComparison.Ordinal);
    }

    private static bool IsOracleRequestCall(ExternalCall call)
    {
        return !call.MethodDynamic
            && string.Equals(call.Method, "request", StringComparison.Ordinal)
            && call.TargetHash?.AsConcreteBytes() is { } targetHash
            && BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.OracleContract));
    }

    private static IEnumerable<ForbiddenSideEffect> FalseReturnSideEffects(
        ExecutionState state,
        string failedCondition)
    {
        foreach (var op in state.Telemetry.StorageOps
                     .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                     .OrderBy(op => op.Offset))
        {
            string opName = op.Kind == StorageOpKind.Put ? "Storage.Put" : "Storage.Delete";
            yield return new ForbiddenSideEffect(
                op.Offset,
                $"{opName} at {FormatOffset(op.Offset)}",
                failedCondition);
        }

        foreach (var notification in state.Telemetry.Notifications.OrderBy(notification => notification.Offset))
        {
            yield return new ForbiddenSideEffect(
                notification.Offset,
                ForbiddenRuntimeNotificationDisplay(notification),
                failedCondition);
        }

        foreach (var call in state.Telemetry.ExternalCalls
                     .Where(call => !call.ModeledSelfCall && !IsModeledKnownNativeCall(call))
                     .OrderBy(call => call.Offset))
        {
            yield return new ForbiddenSideEffect(
                call.Offset,
                ForbiddenExternalCallDisplay(call),
                failedCondition);
        }
    }

    private static string? StorageReadCoverageReason(
        VerificationProperty property,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        var referencedOffsets = property.Requires
            .Concat(property.Ensures)
            .Select(c => c.StorageReadOffset)
            .Where(offset => offset.HasValue)
            .Select(offset => offset!.Value)
            .Distinct()
            .OrderBy(offset => offset)
            .ToArray();
        if (referencedOffsets.Length == 0)
            return null;

        var referencedOffsetSet = referencedOffsets.ToHashSet();
        var repeatedByPath = execution.FinalStates
            .Select(state =>
            {
                var repeated = state.Telemetry.StorageOps
                    .Where(op => op.Kind == StorageOpKind.Get && referencedOffsetSet.Contains(op.Offset))
                    .GroupBy(op => op.Offset)
                    .Where(group => group.Count() > 1)
                    .Select(group => group.Key)
                    .ToArray();
                return (State: state, Repeated: repeated);
            })
            .Where(item => item.Repeated.Length > 0
                && RequiresMayBeFeasibleForStorageReadCoverage(property, method, item.State, currentScriptHash, smtBackend))
            .ToArray();
        if (repeatedByPath.Length > 0)
        {
            string repeatedOffsets = string.Join(
                ", ",
                repeatedByPath
                    .SelectMany(item => item.Repeated)
                    .Distinct()
                    .OrderBy(offset => offset)
                    .Select(FormatOffset));
            return $"storage_read verification condition(s) reference Storage.Get offset(s) executed more than once on one terminal path: {repeatedOffsets}; offset-only storage_read conditions are ambiguous because repeated reads at one opcode produce distinct values";
        }

        var missingByPath = execution.FinalStates
            .Select(state =>
            {
                var observed = state.Telemetry.StorageOps
                    .Where(op => op.Kind == StorageOpKind.Get)
                    .Select(op => op.Offset)
                    .ToHashSet();
                var missing = referencedOffsets
                    .Where(offset => !observed.Contains(offset))
                    .ToArray();
                return (State: state, Missing: missing);
            })
            .Where(item => item.Missing.Length > 0
                && RequiresMayBeFeasibleForStorageReadCoverage(property, method, item.State, currentScriptHash, smtBackend))
            .ToArray();
        if (missingByPath.Length == 0)
            return null;

        string missingOffsets = string.Join(
            ", ",
            missingByPath
                .SelectMany(item => item.Missing)
                .Distinct()
                .OrderBy(offset => offset)
                .Select(FormatOffset));
        return $"storage_read verification condition(s) reference unobserved Storage.Get offset(s): {missingOffsets}; every terminal path must execute the referenced Storage.Get before the condition can be evaluated soundly";
    }

    private static string? StoragePutCoverageReason(
        VerificationProperty property,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        var referencedOffsets = property.Ensures
            .Select(c => c.StoragePutOffset)
            .Where(offset => offset.HasValue)
            .Select(offset => offset!.Value)
            .Distinct()
            .OrderBy(offset => offset)
            .ToArray();
        if (referencedOffsets.Length == 0)
            return null;

        var missingByPath = execution.FinalStates
            .Where(state => state.Status == TerminalStatus.Halted)
            .Select(state =>
            {
                var observed = state.Telemetry.StorageOps
                    .Where(op => op.Kind == StorageOpKind.Put)
                    .Select(op => op.Offset)
                    .ToHashSet();
                var missing = referencedOffsets
                    .Where(offset => !observed.Contains(offset))
                    .ToArray();
                return (State: state, Missing: missing);
            })
            .Where(item => item.Missing.Length > 0
                && RequiresMayBeFeasibleForStorageReadCoverage(property, method, item.State, currentScriptHash, smtBackend))
            .ToArray();
        if (missingByPath.Length == 0)
            return null;

        string missingOffsets = string.Join(
            ", ",
            missingByPath
                .SelectMany(item => item.Missing)
                .Distinct()
                .OrderBy(offset => offset)
                .Select(FormatOffset));
        return $"storage_put verification condition(s) reference unobserved Storage.Put offset(s): {missingOffsets}; every successful HALT path satisfying requires must execute the referenced Storage.Put before the condition can be evaluated soundly";
    }

    private static bool RequiresMayBeFeasibleForStorageReadCoverage(
        VerificationProperty property,
        ContractMethodDescriptor method,
        ExecutionState state,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        if (property.Requires.Length == 0 || smtBackend is null)
            return true;

        ImmutableArray<Expression> requires;
        try
        {
            requires = property.Requires.Select(c => c.ToExpression(method, state, currentScriptHash)).ToImmutableArray();
        }
        catch (FormatException)
        {
            return true;
        }

        if (requires.Length == 0)
            return true;

        IReadOnlyList<Expression> pathConditions = state.Status == TerminalStatus.Halted
            ? SuccessfulHaltPathConditions(state)
            : state.PathConditions;
        var outcome = smtBackend.IsSatisfiable(BuildReachabilityQuery(requires, pathConditions));
        return outcome != SmtOutcome.Unsat;
    }

    private static ImmutableArray<Expression> SuccessfulHaltPathConditions(ExecutionState state)
    {
        var builder = ImmutableArray.CreateBuilder<Expression>(
            state.PathConditions.Count
            + state.Telemetry.FaultConditions.Count
            + state.Telemetry.ArithmeticOps.Count * 3);
        builder.AddRange(state.PathConditions);

        foreach (var fault in state.Telemetry.FaultConditions)
            builder.Add(Expr.Not(fault.FaultCondition));

        foreach (var guard in ArithmeticSuccessGuards(state.Telemetry.ArithmeticOps))
            builder.Add(guard);

        return builder.ToImmutable();
    }

    private static IReadOnlyList<Expression> OperationPrefixPathConditions(
        ExecutionState state,
        ImmutableArray<Expression> pathConditions) =>
        pathConditions.IsDefault ? state.PathConditions : pathConditions;

    private static IEnumerable<Expression> ArithmeticSuccessGuards(IEnumerable<ArithmeticOp> operations)
    {
        foreach (var op in operations)
        {
            if (!op.Checked
                && op.Result is not null
                && HasTransparentArithmeticResult(op)
                && (op.OverflowPossible || ConcreteIntegerOverflow(op.Result.Expression)))
            {
                yield return Expr.Ge(op.Result.Expression, Expr.Int(Expr.NeoVmIntegerMin));
                yield return Expr.Le(op.Result.Expression, Expr.Int(Expr.NeoVmIntegerMax));
            }

            if (op.DivisorMaybeZero && op.Right is not null)
                yield return Expr.Not(Expr.Eq(op.Right.Expression, Expr.Int(0)));

            if (op.Operation == "SQRT" && op.Left is not null && !op.Left.IsConcrete)
                yield return Expr.Ge(op.Left.Expression, Expr.Int(0));

            if ((op.Operation == "MODMUL" || op.Operation == "MODPOW")
                && op.Third is not null
                && !op.Third.IsConcrete)
            {
                yield return Expr.Not(Expr.Eq(op.Third.Expression, Expr.Int(0)));
            }

            if ((op.Operation == "POW" || op.Operation == "SHL" || op.Operation == "SHR")
                && op.Right is not null
                && !op.Right.IsConcrete)
            {
                yield return Expr.Ge(op.Right.Expression, Expr.Int(0));
                if (op.MaxRight is { } maxRight)
                    yield return Expr.Le(op.Right.Expression, Expr.Int(maxRight));
            }

            if (op.Operation == "MODPOW" && op.Right is not null && !op.Right.IsConcrete)
            {
                yield return Expr.Ge(op.Right.Expression, Expr.Int(-1));
                if (op.MaxRight is { } maxRight)
                    yield return Expr.Le(op.Right.Expression, Expr.Int(maxRight));
            }

            if (op.Operation == "MODPOW"
                && op.Right is not null
                && (Expr.ConcreteInt(op.Right.Expression) is not { } concreteExponent || concreteExponent == -1))
            {
                var notInverseBranch = Expr.Not(Expr.NumEq(op.Right.Expression, Expr.Int(-1)));
                if (op.Left is not null && !op.Left.IsConcrete)
                    yield return Expr.BoolOr(notInverseBranch, Expr.Gt(op.Left.Expression, Expr.Int(0)));
                if (op.Third is not null && !op.Third.IsConcrete)
                    yield return Expr.BoolOr(notInverseBranch, Expr.Ge(op.Third.Expression, Expr.Int(2)));
            }
        }
    }

    private static VerificationPropertyResult? CheckArithmeticDefinedness(
        ContractMethodDescriptor method,
        VerificationProperty property,
        ExecutionState state,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        ref int obligations,
        List<string> unknownReasons)
    {
        foreach (var op in state.Telemetry.ArithmeticOps)
        {
            if (!op.Checked
                && op.Result is not null
                && HasTransparentArithmeticResult(op)
                && (op.OverflowPossible || ConcreteIntegerOverflow(op.Result.Expression)))
            {
                var result = CheckArithmeticFaultCondition(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    Expr.Lt(op.Result.Expression, Expr.Int(Expr.NeoVmIntegerMin)),
                    $"{op.Operation} at 0x{op.Offset:X4} can fault with integer overflow below NeoVM's 32-byte signed range under requires.",
                    $"solver returned unknown for integer-underflow reachability at 0x{op.Offset:X4}");
                if (result is not null)
                    return result;

                result = CheckArithmeticFaultCondition(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    Expr.Gt(op.Result.Expression, Expr.Int(Expr.NeoVmIntegerMax)),
                    $"{op.Operation} at 0x{op.Offset:X4} can fault with integer overflow above NeoVM's 32-byte signed range under requires.",
                    $"solver returned unknown for integer-overflow reachability at 0x{op.Offset:X4}");
                if (result is not null)
                    return result;
            }

            if (op.DivisorMaybeZero && op.Right is not null)
            {
                var zeroDivisor = Expr.Eq(op.Right.Expression, Expr.Int(0));
                var result = CheckArithmeticFaultCondition(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    zeroDivisor,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault with a zero divisor under requires.",
                    $"solver returned unknown for zero-divisor reachability at 0x{op.Offset:X4}");
                if (result is not null)
                    return result;
            }

            if (op.Operation == "SQRT" && op.Left is not null && !op.Left.IsConcrete)
            {
                var negativeInput = Expr.Lt(op.Left.Expression, Expr.Int(0));
                var result = CheckArithmeticFaultCondition(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    negativeInput,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault with a negative input under requires.",
                    $"solver returned unknown for SQRT negative-input reachability at 0x{op.Offset:X4}");
                if (result is not null)
                    return result;
            }

            if ((op.Operation == "MODMUL" || op.Operation == "MODPOW")
                && op.Third is not null
                && !op.Third.IsConcrete)
            {
                var zeroModulus = Expr.Eq(op.Third.Expression, Expr.Int(0));
                var result = CheckArithmeticFaultCondition(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    zeroModulus,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault with a zero modulus under requires.",
                    $"solver returned unknown for {op.Operation} zero-modulus reachability at 0x{op.Offset:X4}");
                if (result is not null)
                    return result;
            }

            if ((op.Operation == "POW" || op.Operation == "SHL" || op.Operation == "SHR")
                && op.Right is not null
                && !op.Right.IsConcrete)
            {
                string operandName = op.Operation == "POW" ? "exponent" : "shift count";
                var negativeRight = Expr.Lt(op.Right.Expression, Expr.Int(0));
                var result = CheckArithmeticFaultCondition(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    negativeRight,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault with a negative {operandName} under requires.",
                    $"solver returned unknown for {op.Operation} negative-{operandName.Replace(' ', '-')} reachability at 0x{op.Offset:X4}");
                if (result is not null)
                    return result;

                if (op.MaxRight is { } maxRight)
                {
                    var tooLargeRight = Expr.Gt(op.Right.Expression, Expr.Int(maxRight));
                    result = CheckArithmeticFaultCondition(
                        property,
                        state,
                        op,
                        requires,
                        smtBackend,
                        checkedPaths,
                        ignoredFaulted,
                        stopped,
                        ref obligations,
                        unknownReasons,
                        tooLargeRight,
                        $"{op.Operation} at 0x{op.Offset:X4} can fault with a {operandName} larger than {maxRight} under requires.",
                        $"solver returned unknown for {op.Operation} oversized-{operandName.Replace(' ', '-')} reachability at 0x{op.Offset:X4}");
                    if (result is not null)
                        return result;
                }
            }

            if (op.Operation == "POW")
            {
                var result = CheckFiniteRightResultOverflow(
                    property,
                    state,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    op,
                    "exponent",
                    static (left, right) => BigInteger.Pow(left, right));
                if (result is not null)
                    return result;
            }

            if (op.Operation == "SHL")
            {
                var result = CheckFiniteRightResultOverflow(
                    property,
                    state,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    op,
                    "shift count",
                    static (left, right) => left << right);
                if (result is not null)
                    return result;
            }

            if (op.Operation == "MODPOW" && op.Right is not null && !op.Right.IsConcrete)
            {
                var exponentTooNegative = Expr.Lt(op.Right.Expression, Expr.Int(-1));
                var result = CheckArithmeticFaultCondition(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    ref obligations,
                    unknownReasons,
                    exponentTooNegative,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault with an exponent less than -1 under requires.",
                    $"solver returned unknown for {op.Operation} exponent-below-minus-one reachability at 0x{op.Offset:X4}");
                if (result is not null)
                    return result;

                if (op.MaxRight is { } maxRight)
                {
                    var exponentTooLarge = Expr.Gt(op.Right.Expression, Expr.Int(maxRight));
                    result = CheckArithmeticFaultCondition(
                        property,
                        state,
                        op,
                        requires,
                        smtBackend,
                        checkedPaths,
                        ignoredFaulted,
                        stopped,
                        ref obligations,
                        unknownReasons,
                        exponentTooLarge,
                        $"{op.Operation} at 0x{op.Offset:X4} can fault with an exponent larger than {maxRight} under requires.",
                        $"solver returned unknown for {op.Operation} oversized-exponent reachability at 0x{op.Offset:X4}");
                    if (result is not null)
                        return result;
                }
            }

            if (op.Operation == "MODPOW"
                && op.Right is not null
                && (Expr.ConcreteInt(op.Right.Expression) is not { } concreteExponent || concreteExponent == -1))
            {
                var inverseBranch = Expr.NumEq(op.Right.Expression, Expr.Int(-1));
                if (op.Left is not null && !op.Left.IsConcrete)
                {
                    var nonPositiveBase = Expr.BoolAnd(
                        inverseBranch,
                        Expr.Le(op.Left.Expression, Expr.Int(0)));
                    var result = CheckArithmeticFaultCondition(
                        property,
                        state,
                        op,
                        requires,
                        smtBackend,
                        checkedPaths,
                        ignoredFaulted,
                        stopped,
                        ref obligations,
                        unknownReasons,
                        nonPositiveBase,
                        $"{op.Operation} at 0x{op.Offset:X4} can fault because the modular inverse base is not positive under requires.",
                        $"solver returned unknown for {op.Operation} inverse-base reachability at 0x{op.Offset:X4}");
                    if (result is not null)
                        return result;
                }

                if (op.Third is not null && !op.Third.IsConcrete)
                {
                    var modulusTooSmall = Expr.BoolAnd(
                        inverseBranch,
                        Expr.Lt(op.Third.Expression, Expr.Int(2)));
                    var result = CheckArithmeticFaultCondition(
                        property,
                        state,
                        op,
                        requires,
                        smtBackend,
                        checkedPaths,
                        ignoredFaulted,
                        stopped,
                        ref obligations,
                        unknownReasons,
                        modulusTooSmall,
                        $"{op.Operation} at 0x{op.Offset:X4} can fault because the modular inverse modulus is not at least 2 under requires.",
                        $"solver returned unknown for {op.Operation} inverse-modulus reachability at 0x{op.Offset:X4}");
                    if (result is not null)
                        return result;
                }

                if (op.Left is not null && op.Third is not null)
                {
                    var result = CheckModPowInverseExists(
                        property,
                        state,
                        requires,
                        smtBackend,
                        checkedPaths,
                        ignoredFaulted,
                        stopped,
                        ref obligations,
                        unknownReasons,
                        op,
                        inverseBranch);
                    if (result is not null)
                        return result;
                }
            }
        }

        return null;
    }

    private static bool ConcreteIntegerOverflow(Expression expression) =>
        Expr.ConcreteInt(expression) is { } value
        && !Expr.IsWithinNeoVmIntegerRange(value);

    private static bool HasTransparentArithmeticResult(ArithmeticOp op) =>
        op.Operation is "ADD" or "SUB" or "MUL" or "INC" or "DEC" or "NEGATE" or "ABS";

    private static VerificationPropertyResult? CheckFiniteRightResultOverflow(
        VerificationProperty property,
        ExecutionState state,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        ref int obligations,
        List<string> unknownReasons,
        ArithmeticOp op,
        string rightOperandName,
        Func<BigInteger, int, BigInteger> evaluateResult)
    {
        if (op.Left is null
            || op.Right is null
            || op.Right.IsConcrete
            || op.MaxRight is not { } maxRight
            || maxRight < 0
            || Expr.ConcreteInt(op.Left.Expression) is not { } leftValue)
            return null;

        for (int rightValue = 0; rightValue <= maxRight; rightValue++)
        {
            var resultValue = evaluateResult(leftValue, rightValue);
            if (Expr.IsWithinNeoVmIntegerRange(resultValue))
                continue;

            var overflowRight = Expr.NumEq(op.Right.Expression, Expr.Int(rightValue));
            var result = CheckArithmeticFaultCondition(
                property,
                state,
                op,
                requires,
                smtBackend,
                checkedPaths,
                ignoredFaulted,
                stopped,
                ref obligations,
                unknownReasons,
                overflowRight,
                $"{op.Operation} at 0x{op.Offset:X4} can fault with integer overflow for {rightOperandName} {rightValue} under requires.",
                $"solver returned unknown for {op.Operation} integer-overflow reachability at 0x{op.Offset:X4} with {rightOperandName.Replace(' ', '-')} {rightValue}");
            if (result is not null)
                return result;
        }

        return null;
    }

    private static VerificationPropertyResult? CheckModPowInverseExists(
        VerificationProperty property,
        ExecutionState state,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        ref int obligations,
        List<string> unknownReasons,
        ArithmeticOp op,
        Expression inverseBranch)
    {
        obligations++;
        var prefixPathConditions = OperationPrefixPathConditions(state, op.PathConditions);

        var baseConcrete = Expr.ConcreteInt(op.Left!.Expression);
        var modulusConcrete = Expr.ConcreteInt(op.Third!.Expression);
        if (baseConcrete is { } knownBase && modulusConcrete is { } knownModulus)
        {
            if (knownBase > 0
                && knownModulus >= 2
                && BigInteger.GreatestCommonDivisor(BigInteger.Abs(knownBase), BigInteger.Abs(knownModulus)).IsOne)
                return null;

            var concreteInverseReachability = BuildReachabilityQuery(requires, prefixPathConditions, inverseBranch);
            var inverseOutcome = smtBackend?.IsSatisfiable(concreteInverseReachability) ?? SmtOutcome.Unknown;
            if (inverseOutcome == SmtOutcome.Sat)
            {
                return BuildArithmeticViolation(
                    property,
                    state,
                    op,
                    requires,
                    smtBackend,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    inverseBranch,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault because the modular inverse does not exist under requires.");
            }

            if (inverseOutcome == SmtOutcome.Unknown)
                unknownReasons.Add(
                    $"solver returned unknown for {op.Operation} modular-inverse branch reachability at 0x{op.Offset:X4}");
            return null;
        }

        if (baseConcrete == BigInteger.One)
            return null;

        var inverseReachability = BuildReachabilityQuery(requires, prefixPathConditions, inverseBranch);
        if (TryProveUniqueInt(op.Left.Expression, inverseReachability, smtBackend, out var uniqueBase)
            && TryProveUniqueInt(op.Third.Expression, inverseReachability, smtBackend, out var uniqueModulus))
        {
            if (uniqueBase > 0
                && uniqueModulus >= 2
                && BigInteger.GreatestCommonDivisor(BigInteger.Abs(uniqueBase), BigInteger.Abs(uniqueModulus)).IsOne)
                return null;

            var noInverse = Expr.BoolAnd(
                inverseBranch,
                Expr.BoolAnd(
                    Expr.NumEq(op.Left.Expression, Expr.Int(uniqueBase)),
                    Expr.NumEq(op.Third.Expression, Expr.Int(uniqueModulus))));
            return BuildArithmeticViolation(
                property,
                state,
                op,
                requires,
                smtBackend,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                noInverse,
                $"{op.Operation} at 0x{op.Offset:X4} can fault because the modular inverse does not exist under requires.");
        }

        foreach (var (candidateBase, candidateModulus) in EnumerateModPowInverseFaultCandidates(baseConcrete, modulusConcrete))
        {
            var noInverse = Expr.BoolAnd(
                inverseBranch,
                Expr.BoolAnd(
                    Expr.NumEq(op.Left.Expression, Expr.Int(candidateBase)),
                    Expr.NumEq(op.Third.Expression, Expr.Int(candidateModulus))));
            var query = BuildReachabilityQuery(requires, prefixPathConditions, noInverse);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Sat)
            {
                var witness = smtBackend?.BuildWitness(query);
                return new VerificationPropertyResult(
                    property.Id,
                    property.Method,
                    property.Description,
                    VerificationStatus.Violated,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault because the modular inverse does not exist under requires.",
                    "arithmetic operation defined under requires",
                    witness is null ? null : ImmutableDictionary.CreateRange(witness));
            }
        }

        unknownReasons.Add(
            $"{op.Operation} at 0x{op.Offset:X4} has a symbolic modular-inverse existence obligation that the current solver/model cannot prove");
        return null;
    }

    private static VerificationPropertyResult BuildArithmeticViolation(
        VerificationProperty property,
        ExecutionState state,
        ArithmeticOp op,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        int obligations,
        Expression faultCondition,
        string violationReason)
    {
        var query = BuildReachabilityQuery(
            requires,
            OperationPrefixPathConditions(state, op.PathConditions),
            faultCondition);
        var witness = smtBackend?.BuildWitness(query);
        return new VerificationPropertyResult(
            property.Id,
            property.Method,
            property.Description,
            VerificationStatus.Violated,
            checkedPaths,
            ignoredFaulted,
            stopped,
            obligations,
            violationReason,
            "arithmetic operation defined under requires",
            witness is null ? null : ImmutableDictionary.CreateRange(witness));
    }

    private static bool TryProveUniqueInt(
        Expression expression,
        ImmutableArray<Expression> conditions,
        ISmtBackend? smtBackend,
        out BigInteger value)
    {
        value = BigInteger.Zero;
        if (smtBackend is null)
            return false;

        var candidate = smtBackend.ConcretizeInt(conditions, expression);
        if (candidate is null)
            return false;

        var uniqueness = conditions.Add(Expr.NumNe(expression, Expr.Int(candidate.Value)));
        if (smtBackend.IsSatisfiable(uniqueness) != SmtOutcome.Unsat)
            return false;

        value = candidate.Value;
        return true;
    }

    private static IEnumerable<(BigInteger Base, BigInteger Modulus)> EnumerateModPowInverseFaultCandidates(
        BigInteger? baseConcrete,
        BigInteger? modulusConcrete)
    {
        if (baseConcrete is { } knownBase)
        {
            if (knownBase <= 0)
                yield break;

            for (int modulus = 2; modulus <= ModPowInverseWitnessSearchLimit; modulus++)
            {
                if (!BigInteger.GreatestCommonDivisor(BigInteger.Abs(knownBase), modulus).IsOne)
                    yield return (knownBase, new BigInteger(modulus));
            }

            yield break;
        }

        if (modulusConcrete is { } knownModulus)
        {
            if (knownModulus < 2)
                yield break;

            for (int baseValue = 1; baseValue <= ModPowInverseWitnessSearchLimit; baseValue++)
            {
                if (!BigInteger.GreatestCommonDivisor(baseValue, BigInteger.Abs(knownModulus)).IsOne)
                    yield return (new BigInteger(baseValue), knownModulus);
            }

            yield break;
        }

        for (int baseValue = 1; baseValue <= ModPowInverseWitnessSearchLimit; baseValue++)
        {
            for (int modulus = 2; modulus <= ModPowInverseWitnessSearchLimit; modulus++)
            {
                if (!BigInteger.GreatestCommonDivisor(baseValue, modulus).IsOne)
                    yield return (new BigInteger(baseValue), new BigInteger(modulus));
            }
        }
    }

    private static VerificationPropertyResult? CheckArithmeticFaultCondition(
        VerificationProperty property,
        ExecutionState state,
        ArithmeticOp op,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        ref int obligations,
        List<string> unknownReasons,
        Expression faultCondition,
        string violationReason,
        string unknownReason)
    {
        obligations++;
        var query = BuildReachabilityQuery(
            requires,
            OperationPrefixPathConditions(state, op.PathConditions),
            faultCondition);
        var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
        if (outcome == SmtOutcome.Sat)
        {
            var witness = smtBackend?.BuildWitness(query);
            return new VerificationPropertyResult(
                property.Id,
                property.Method,
                property.Description,
                VerificationStatus.Violated,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                violationReason,
                "arithmetic operation defined under requires",
                witness is null ? null : ImmutableDictionary.CreateRange(witness));
        }
        if (outcome == SmtOutcome.Unknown)
            unknownReasons.Add(unknownReason);

        return null;
    }

    private static VerificationPropertyResult? CheckFaultPreconditions(
        VerificationProperty property,
        ExecutionState state,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        ref int obligations,
        List<string> unknownReasons,
        Func<FaultConditionOp, bool>? skipFaultCondition = null,
        ImmutableArray<VerificationAssumption> assumptions = default)
    {
        foreach (var op in state.Telemetry.FaultConditions)
        {
            if (skipFaultCondition?.Invoke(op) == true)
                continue;

            obligations++;
            var query = BuildReachabilityQuery(
                requires,
                OperationPrefixPathConditions(state, op.PathConditions),
                op.FaultCondition);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Sat)
            {
                var witness = smtBackend?.BuildWitness(query);
                return new VerificationPropertyResult(
                    property.Id,
                    property.Method,
                    property.Description,
                    VerificationStatus.Violated,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    $"{op.Operation} at 0x{op.Offset:X4} can fault under requires: {op.Reason}.",
                    op.FailedCondition,
                    witness is null ? null : ImmutableDictionary.CreateRange(witness),
                    Assumptions: assumptions);
            }
            if (outcome == SmtOutcome.Unknown)
                unknownReasons.Add($"solver returned unknown for {op.Operation} fault reachability at 0x{op.Offset:X4}");
        }

        return null;
    }

    private static VerificationPropertyResult? CheckContractCallAbi(
        ContractManifest manifest,
        VerificationProperty property,
        ExecutionState state,
        ImmutableArray<byte> currentScriptHash,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        int checkedPaths,
        int ignoredFaulted,
        int stopped,
        ref int obligations,
        List<string> unknownReasons,
        List<string> incompleteReasons)
    {
        var selfCalls = state.Telemetry.ExternalCalls
            .Where(call => call.ModeledSelfCall || IsCurrentExecutingScriptHash(call.TargetHash, currentScriptHash))
            .OrderBy(call => call.Offset)
            .ToArray();
        if (selfCalls.Length == 0)
            return null;
        if (!ShouldCheckHaltedPathUnderRequires(
                "Contract.Call self-call ABI checks",
                state,
                requires,
                smtBackend,
                ref obligations,
                unknownReasons))
        {
            return null;
        }

        foreach (var call in selfCalls)
        {
            obligations++;
            if (call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>")
            {
                incompleteReasons.Add(
                    $"Contract.Call self-call at 0x{call.Offset:X4} has dynamic or unknown method selector; ABI target cannot be proven");
                continue;
            }

            var sameName = manifest.Abi.Methods
                .Where(m => string.Equals(m.Name, call.Method, StringComparison.Ordinal))
                .ToArray();
            if (sameName.Length == 0)
            {
                return new VerificationPropertyResult(
                    property.Id,
                    property.Method,
                    property.Description,
                    VerificationStatus.Violated,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    $"Contract.Call self-call method '{call.Method}' is not declared in the manifest.",
                    "Contract.Call self-call target is declared in manifest",
                    Counterexample: null);
            }

            var arityMatches = sameName
                .Where(m => m.Parameters.Count == call.Args.Count)
                .ToArray();
            if (arityMatches.Length == 0)
            {
                return new VerificationPropertyResult(
                    property.Id,
                    property.Method,
                    property.Description,
                    VerificationStatus.Violated,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    $"Contract.Call self-call method '{call.Method}' {FormatExpectedArgumentCounts(sameName)}, got {call.Args.Count}.",
                    "Contract.Call self-call argument count matches manifest",
                    Counterexample: null);
            }

            if (arityMatches.Length > 1)
            {
                incompleteReasons.Add(
                    $"Contract.Call self-call method '{call.Method}' at 0x{call.Offset:X4} resolves to multiple manifest ABI methods with {call.Args.Count} argument(s)");
                continue;
            }

            var method = arityMatches[0];
            for (int i = 0; i < call.Args.Count; i++)
            {
                var parameter = method.Parameters[i];
                var check = CheckRuntimeNotificationArgumentType(state, call.Args[i], parameter);
                if (check.Kind == NotificationArgumentTypeCheckKind.Match)
                    continue;

                string argumentName = string.IsNullOrWhiteSpace(parameter.Name)
                    ? $"#{i}"
                    : parameter.Name;
                if (check.Kind == NotificationArgumentTypeCheckKind.Incomplete)
                {
                    incompleteReasons.Add(
                        $"Contract.Call self-call method '{call.Method}' argument '{argumentName}' at 0x{call.Offset:X4}: {check.Reason}");
                    continue;
                }

                return new VerificationPropertyResult(
                    property.Id,
                    property.Method,
                    property.Description,
                    VerificationStatus.Violated,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    $"Contract.Call self-call method '{call.Method}' argument '{argumentName}' {check.Reason}.",
                    "Contract.Call self-call argument types match manifest",
                    Counterexample: null);
            }
        }

        return null;
    }

    private static bool ShouldCheckHaltedPathUnderRequires(
        string operation,
        ExecutionState state,
        ImmutableArray<Expression> requires,
        ISmtBackend? smtBackend,
        ref int obligations,
        List<string> unknownReasons)
    {
        if (requires.Length == 0)
            return true;

        obligations++;
        var query = BuildReachabilityQuery(requires, state.PathConditions);
        var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
        if (outcome == SmtOutcome.Sat)
            return true;
        if (outcome == SmtOutcome.Unknown)
        {
            unknownReasons.Add(
                $"solver returned unknown while checking whether {operation} path satisfies requires");
        }

        return false;
    }

    private static bool IsCurrentExecutingScriptHash(SymbolicValue? value) =>
        value?.Expression is Symbol { Sort: Sort.Bytes, Name: "executing_script_hash" };

    private static bool IsCurrentExecutingScriptHash(
        SymbolicValue? value,
        ImmutableArray<byte> currentScriptHash)
    {
        if (IsCurrentExecutingScriptHash(value))
            return true;
        if (currentScriptHash.IsDefaultOrEmpty
            || value?.AsConcreteBytes() is not { Length: Hash160ByteLength } concrete)
        {
            return false;
        }

        return BytesEqual(concrete, currentScriptHash.ToArray());
    }

    private static IEnumerable<string> CustomExternalCallCompletenessReasons(ExecutionState state)
    {
        return CustomExternalCallCompletenessReasons(
            state,
            DependencyProofSummarySet.Empty,
            requireExternalSmtDependencyProofs: false);
    }

    private static IEnumerable<string> CustomExternalCallCompletenessReasons(
        ExecutionState state,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        foreach (var call in state.Telemetry.ExternalCalls.OrderBy(c => c.Offset))
        {
            if (IsRuntimeLoadScriptCall(call))
            {
                yield return RuntimeLoadScriptCompletenessReason(call);
                continue;
            }

            if (call.ModeledSelfCall)
                continue;

            if (IsCurrentExecutingScriptHash(call.TargetHash))
            {
                string selfCallMethod = call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>"
                    ? "with a dynamic or unknown method selector"
                    : $"to method '{call.Method}'";
                yield return $"Contract.Call self-call at 0x{call.Offset:X4} {selfCallMethod}; callee execution is not modeled by this verifier";
                continue;
            }

            if (IsModeledKnownNativeCall(call))
                continue;

            if (SensitiveModeledNativeCallCompletenessReason(call) is { } sensitiveNativeReason)
            {
                yield return sensitiveNativeReason;
                continue;
            }

            if (TryResolveExternalCallTargetHash(state, call, out byte[] knownNativeTarget)
                && NeoNativeContractHashes.IsKnownNativeContractHash(knownNativeTarget))
            {
                continue;
            }

            string callKind = call.ReturnValueDeclaredByMethodToken
                ? "CALLT"
                : "external Contract.Call";
            if (!TryResolveExternalCallTargetHash(state, call, out byte[] targetHash))
            {
                string methodContext = call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>"
                    ? string.Empty
                    : $" for method '{call.Method}'";
                yield return $"{callKind} at 0x{call.Offset:X4} has dynamic or unknown target contract{methodContext}; target contract existence and ABI are not modeled by this verifier";
                continue;
            }

            if (call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>")
            {
                yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} with a dynamic or unknown method selector; target contract existence and ABI are not modeled by this verifier";
                continue;
            }

            if (call.ArgumentsDynamic)
            {
                yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}' with a dynamic or open argument array; target method arity and ABI arguments are not modeled by this verifier";
                continue;
            }

            if (!dependencyProofs.IsEmpty)
            {
                var coverage = dependencyProofs.CheckExternalCall(
                    targetHash,
                    call.Method,
                    call.Args.Count,
                    call.HasReturnValue,
                    ExpectedDependencyReturnType(state, call),
                    call.CallFlags,
                    call.CallFlagsDynamic,
                    state.RuntimeTrigger,
                    requireExternalSmtDependencyProofs,
                    returnValueDeclaredByMethodToken: call.ReturnValueDeclaredByMethodToken);
                if (coverage.IsCovered)
                {
                    string? compatibilityReason = coverage.Method is { } coveredMethod
                        ? DependencyProofArgumentCompatibilityReason(state, call, coveredMethod)
                        : "dependency proof summary coverage did not identify the covered ABI method";
                    if (compatibilityReason is null)
                        continue;
                    yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}'; {compatibilityReason}";
                    continue;
                }
                yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}'; {coverage.Reason}";
                continue;
            }

            yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}'; target contract existence and ABI are not modeled by this verifier";
        }
    }

    private static IEnumerable<string> ProfileExternalCallCompletenessReasons(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state)
    {
        return ProfileExternalCallCompletenessReasons(
            manifest,
            method,
            state,
            DependencyProofSummarySet.Empty,
            requireExternalSmtDependencyProofs: false);
    }

    private static IEnumerable<string> ProfileExternalCallCompletenessReasons(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        foreach (var call in state.Telemetry.ExternalCalls.OrderBy(c => c.Offset))
        {
            foreach (var reason in ExternalCallCompletenessReasons(
                         state,
                         call,
                         dependencyProofs,
                         requireExternalSmtDependencyProofs))
                yield return reason;
        }
    }

    private static IEnumerable<string> ExternalCallCompletenessReasons(
        ExecutionState state,
        ExternalCall call,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        if (IsRuntimeLoadScriptCall(call))
        {
            yield return RuntimeLoadScriptCompletenessReason(call);
            yield break;
        }
        if (call.ModeledSelfCall)
            yield break;

        if (IsCurrentExecutingScriptHash(call.TargetHash))
        {
            string selfCallMethod = call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>"
                ? "with a dynamic or unknown method selector"
                : $"to method '{call.Method}'";
            yield return $"Contract.Call self-call at 0x{call.Offset:X4} {selfCallMethod}; callee execution is not modeled by this verifier";
            yield break;
        }

        if (IsModeledKnownNativeCall(call))
            yield break;

        if (SensitiveModeledNativeCallCompletenessReason(call) is { } sensitiveNativeReason)
        {
            yield return sensitiveNativeReason;
            yield break;
        }

        if (TryResolveExternalCallTargetHash(state, call, out byte[] knownNativeTarget)
            && NeoNativeContractHashes.IsKnownNativeContractHash(knownNativeTarget))
            yield break;

        string callKind = call.ReturnValueDeclaredByMethodToken
            ? "CALLT"
            : "external Contract.Call";
        if (!TryResolveExternalCallTargetHash(state, call, out byte[] targetHash))
        {
            string methodContext = call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>"
                ? string.Empty
                : $" for method '{call.Method}'";
            yield return $"{callKind} at 0x{call.Offset:X4} has dynamic or unknown target contract{methodContext}; target contract existence and ABI are not modeled by this verifier";
            yield break;
        }

        if (call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>")
        {
            yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} with a dynamic or unknown method selector; target contract existence and ABI are not modeled by this verifier";
            yield break;
        }

        if (call.ArgumentsDynamic)
        {
            yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}' with a dynamic or open argument array; target method arity and ABI arguments are not modeled by this verifier";
            yield break;
        }

        if (!dependencyProofs.IsEmpty)
        {
            var coverage = dependencyProofs.CheckExternalCall(
                targetHash,
                call.Method,
                call.Args.Count,
                call.HasReturnValue,
                ExpectedDependencyReturnType(state, call),
                call.CallFlags,
                call.CallFlagsDynamic,
                state.RuntimeTrigger,
                requireExternalSmtDependencyProofs,
                returnValueDeclaredByMethodToken: call.ReturnValueDeclaredByMethodToken);
            if (coverage.IsCovered)
            {
                string? compatibilityReason = coverage.Method is { } coveredMethod
                    ? DependencyProofArgumentCompatibilityReason(state, call, coveredMethod)
                    : "dependency proof summary coverage did not identify the covered ABI method";
                if (compatibilityReason is null)
                    yield break;
                yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}'; {compatibilityReason}";
                yield break;
            }
            yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}'; {coverage.Reason}";
            yield break;
        }

        yield return $"{callKind} at 0x{call.Offset:X4} targets contract {FormatHash(targetHash)} method '{call.Method}'; target contract existence and ABI are not modeled by this verifier";
    }

    private static ImmutableArray<VerificationAssumption> ProfileExternalCallCompletenessAssumptions(
        ExecutionState state,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        if (!dependencyProofs.RequiresUnboundArtifactTrust)
            return ImmutableArray<VerificationAssumption>.Empty;

        var assumptions = ImmutableArray.CreateBuilder<VerificationAssumption>();
        foreach (var call in state.Telemetry.ExternalCalls.OrderBy(c => c.Offset))
        {
            if (ExternalCallUsesUnboundDependencyProofAssumption(
                    state,
                    call,
                    dependencyProofs,
                    requireExternalSmtDependencyProofs))
            {
                assumptions.Add(UnboundDependencyProofSummaryAssumption);
            }
        }

        return assumptions
            .Distinct()
            .ToImmutableArray();
    }

    private static bool ExternalCallUsesUnboundDependencyProofAssumption(
        ExecutionState state,
        ExternalCall call,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        if (IsRuntimeLoadScriptCall(call)
            || call.ModeledSelfCall
            || IsCurrentExecutingScriptHash(call.TargetHash)
            || IsModeledKnownNativeCall(call)
            || SensitiveModeledNativeCallCompletenessReason(call) is not null)
        {
            return false;
        }

        if (TryResolveExternalCallTargetHash(state, call, out byte[] knownNativeTarget)
            && NeoNativeContractHashes.IsKnownNativeContractHash(knownNativeTarget))
        {
            return false;
        }

        if (!TryResolveExternalCallTargetHash(state, call, out byte[] targetHash)
            || call.MethodDynamic
            || string.IsNullOrWhiteSpace(call.Method)
            || call.Method == "<dynamic>"
            || call.ArgumentsDynamic
            || dependencyProofs.IsEmpty)
        {
            return false;
        }

        var coverage = dependencyProofs.CheckExternalCall(
            targetHash,
            call.Method,
            call.Args.Count,
            call.HasReturnValue,
            ExpectedDependencyReturnType(state, call),
            call.CallFlags,
            call.CallFlagsDynamic,
            state.RuntimeTrigger,
            requireExternalSmtDependencyProofs,
            returnValueDeclaredByMethodToken: call.ReturnValueDeclaredByMethodToken);
        return coverage is { IsCovered: true, UsesUnboundArtifactTrust: true, Method: { } coveredMethod }
            && DependencyProofArgumentCompatibilityReason(state, call, coveredMethod) is null;
    }

    private static string? DependencyProofArgumentCompatibilityReason(
        ExecutionState state,
        ExternalCall call,
        DependencyMethodProofSummary method)
    {
        if (method.Parameters.Length != call.Args.Count)
        {
            return $"dependency proof summary for {method.Name} has {method.Parameters.Length} typed parameter(s), got {call.Args.Count} runtime argument(s)";
        }

        for (int i = 0; i < method.Parameters.Length; i++)
        {
            var parameter = method.Parameters[i];
            var parameterDefinition = new ContractParameterDefinition(parameter.Name, parameter.Type);
            var check = CheckRuntimeNotificationArgumentType(
                state,
                call.Args[i],
                parameterDefinition,
                allowStructForArray: false);
            if (check.Kind == NotificationArgumentTypeCheckKind.Match)
                continue;

            string argumentName = string.IsNullOrWhiteSpace(parameter.Name)
                ? $"#{i}"
                : parameter.Name;
            return check.Kind == NotificationArgumentTypeCheckKind.Incomplete
                ? $"dependency proof summary argument '{argumentName}' expects {parameter.Type}, but the caller argument cannot be proven compatible: {check.Reason}"
                : $"dependency proof summary argument '{argumentName}' expects {parameter.Type}, but caller passed an incompatible argument: {check.Reason}";
        }

        return null;
    }

    private static bool TryResolveExternalCallTargetHash(
        ExecutionState state,
        ExternalCall call,
        out byte[] targetHash)
    {
        if (call.TargetHash?.AsConcreteBytes() is { Length: Hash160ByteLength } concrete)
        {
            targetHash = concrete;
            return true;
        }

        if (call.TargetHash is not null
            && TryResolveBytesFromPathConditions(
                state.PathConditions,
                call.TargetHash.Expression,
                Hash160ByteLength,
                out targetHash))
        {
            return true;
        }

        targetHash = Array.Empty<byte>();
        return false;
    }

    private static bool TryResolveBytesFromPathConditions(
        IReadOnlyList<Expression> pathConditions,
        Expression expression,
        int expectedLength,
        out byte[] bytes)
    {
        foreach (var condition in pathConditions)
        {
            if (TryExtractConcreteBytesEquality(condition, expression, expectedLength, out bytes))
                return true;
        }

        bytes = Array.Empty<byte>();
        return false;
    }

    private static bool TryExtractConcreteBytesEquality(
        Expression condition,
        Expression expression,
        int expectedLength,
        out byte[] bytes)
    {
        switch (condition)
        {
            case BinaryExpr { Op: "and" } binary:
                return TryExtractConcreteBytesEquality(binary.Left, expression, expectedLength, out bytes)
                    || TryExtractConcreteBytesEquality(binary.Right, expression, expectedLength, out bytes);
            case BinaryExpr { Op: "==" } equality:
                return TryExtractConcreteBytesEquality(
                    equality.Left,
                    equality.Right,
                    expression,
                    expectedLength,
                    out bytes);
            case UnaryExpr { Op: "not", Operand: BinaryExpr { Op: "!=" } inequality }:
                return TryExtractConcreteBytesEquality(
                    inequality.Left,
                    inequality.Right,
                    expression,
                    expectedLength,
                    out bytes);
            default:
                bytes = Array.Empty<byte>();
                return false;
        }
    }

    private static bool TryExtractConcreteBytesEquality(
        Expression left,
        Expression right,
        Expression expression,
        int expectedLength,
        out byte[] bytes)
    {
        if (left.Equals(expression)
            && right is BytesConst { Value.Length: var rightLength } rightBytes
            && rightLength == expectedLength)
        {
            bytes = rightBytes.Value;
            return true;
        }

        if (right.Equals(expression)
            && left is BytesConst { Value.Length: var leftLength } leftBytes
            && leftLength == expectedLength)
        {
            bytes = leftBytes.Value;
            return true;
        }

        bytes = Array.Empty<byte>();
        return false;
    }

    private static string? ExpectedDependencyReturnType(ExecutionState state, ExternalCall call)
    {
        if (!call.HasReturnValue)
            return "Void";

        string symbolName = ExternalReturnSymbolName(call);
        if (state.PathConditions.Any(condition => ExpressionRequiresExternalReturnNull(condition, symbolName)))
            return "Null";

        foreach (var condition in state.PathConditions)
        {
            if (ExpressionRequiresExternalReturnStackItemType(condition, symbolName) is { } stackItemReturnType)
                return stackItemReturnType;
        }

        foreach (var condition in state.PathConditions)
        {
            if (ExpressionRequiresExternalReturnTypeSensitiveEquality(condition, symbolName) is { } equalityReturnType)
                return equalityReturnType;
        }

        if (state.PathConditions.Any(condition => ExpressionRequiresExternalReturnInteger(condition, symbolName)))
            return "Integer";

        return state.PathConditions.Any(condition =>
            ExpressionRequiresExternalReturnTrue(condition, symbolName)
            || ExpressionRequiresExternalReturnFalse(condition, symbolName))
            ? "Boolean"
            : null;
    }

    private static bool ExpressionRequiresExternalReturnNull(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and", Left: var left, Right: var right } =>
                ExpressionRequiresExternalReturnNull(left, symbolName)
                || ExpressionRequiresExternalReturnNull(right, symbolName),
            UnaryExpr { Op: "tobool", Operand: var operand } =>
                ExpressionRequiresExternalReturnNull(operand, symbolName),
            UnaryExpr { Op: "isnull", Operand: var operand } =>
                ExpressionIsDirectExternalReturnSymbol(operand, symbolName),
            BinaryExpr { Op: "==" or "num==", Left: var left, Right: var right } =>
                ExternalReturnNullPredicate(left, symbolName)
                && ExpressionIsBoolLiteral(right, expected: true, allowNumeric: true)
                || ExternalReturnNullPredicate(right, symbolName)
                && ExpressionIsBoolLiteral(left, expected: true, allowNumeric: true),
            BinaryExpr { Op: "!=" or "num!=", Left: var left, Right: var right } =>
                ExternalReturnNullPredicate(left, symbolName)
                && ExpressionIsBoolLiteral(right, expected: false, allowNumeric: true)
                || ExternalReturnNullPredicate(right, symbolName)
                && ExpressionIsBoolLiteral(left, expected: false, allowNumeric: true),
            _ => false,
        };

    private static bool ExternalReturnNullPredicate(Expression expression, string symbolName) =>
        expression is UnaryExpr { Op: "isnull", Operand: var operand }
        && ExpressionIsDirectExternalReturnSymbol(operand, symbolName);

    private static string? ExpressionRequiresExternalReturnStackItemType(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and", Left: var left, Right: var right } =>
                ExpressionRequiresExternalReturnStackItemType(left, symbolName)
                ?? ExpressionRequiresExternalReturnStackItemType(right, symbolName),
            UnaryExpr { Op: "tobool", Operand: var operand } =>
                ExpressionRequiresExternalReturnStackItemType(operand, symbolName),
            BinaryExpr { Op: "==" or "num==", Left: var left, Right: var right } =>
                ExternalReturnStackItemTypePredicate(left, symbolName) is { } leftType
                    && ExpressionIsBoolLiteral(right, expected: true, allowNumeric: true)
                    ? leftType
                    : ExternalReturnStackItemTypePredicate(right, symbolName) is { } rightType
                        && ExpressionIsBoolLiteral(left, expected: true, allowNumeric: true)
                        ? rightType
                        : null,
            BinaryExpr { Op: "!=" or "num!=", Left: var left, Right: var right } =>
                ExternalReturnStackItemTypePredicate(left, symbolName) is { } leftType
                    && ExpressionIsBoolLiteral(right, expected: false, allowNumeric: true)
                    ? leftType
                    : ExternalReturnStackItemTypePredicate(right, symbolName) is { } rightType
                        && ExpressionIsBoolLiteral(left, expected: false, allowNumeric: true)
                        ? rightType
                        : null,
            _ => ExternalReturnStackItemTypePredicate(condition, symbolName),
        };

    private static string? ExpressionRequiresExternalReturnTypeSensitiveEquality(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and", Left: var left, Right: var right } =>
                ExpressionRequiresExternalReturnTypeSensitiveEquality(left, symbolName)
                ?? ExpressionRequiresExternalReturnTypeSensitiveEquality(right, symbolName),
            UnaryExpr { Op: "tobool", Operand: var operand } =>
                ExpressionRequiresExternalReturnTypeSensitiveEquality(operand, symbolName),
            UnaryExpr { Op: "not", Operand: UnaryExpr { Op: "not", Operand: var operand } } =>
                ExpressionRequiresExternalReturnTypeSensitiveEquality(operand, symbolName),
            UnaryExpr { Op: "not", Operand: BinaryExpr { Op: "!=", Left: var left, Right: var right } } =>
                ExternalReturnTypeSensitiveEqualityType(left, right, symbolName),
            BinaryExpr { Op: "==", Left: var left, Right: var right } =>
                ExternalReturnTypeSensitiveEqualityType(left, right, symbolName),
            _ => null,
        };

    private static string? ExternalReturnTypeSensitiveEqualityType(
        Expression left,
        Expression right,
        string symbolName)
    {
        if (ExpressionIsDirectExternalReturnSymbol(left, symbolName))
            return DependencyReturnTypeForTypeSensitiveEqualityOperand(right);
        if (ExpressionIsDirectExternalReturnSymbol(right, symbolName))
            return DependencyReturnTypeForTypeSensitiveEqualityOperand(left);
        return null;
    }

    private static string? DependencyReturnTypeForTypeSensitiveEqualityOperand(Expression expression) =>
        expression.Sort switch
        {
            Sort.Int or Sort.Bytes => DependencyProofSummarySet.PrimitiveEqualityReturnConstraint,
            Sort.Bool => "Boolean",
            Sort.Null => "Null",
            Sort.Buffer => "Buffer",
            Sort.Array => "Array",
            Sort.Struct => "Struct",
            Sort.Map => "Map",
            Sort.Pointer => "Pointer",
            Sort.InteropInterface => "InteropInterface",
            _ => null,
        };

    private static string? ExternalReturnStackItemTypePredicate(Expression expression, string symbolName) =>
        expression switch
        {
            UnaryExpr { Op: var op, Operand: var operand }
                when TryParseIsTypeOperation(op, out byte typeByte)
                    && ExpressionIsDirectExternalReturnSymbol(operand, symbolName) =>
                DependencyReturnTypeForStackItemType(typeByte),
            _ => null,
        };

    private static bool TryParseIsTypeOperation(string op, out byte typeByte)
    {
        const string Prefix = "istype:";
        typeByte = default;
        return op.StartsWith(Prefix, StringComparison.Ordinal)
            && byte.TryParse(
                op.AsSpan(Prefix.Length),
                System.Globalization.NumberStyles.HexNumber,
                provider: null,
                out typeByte);
    }

    private static string? DependencyReturnTypeForStackItemType(byte typeByte) =>
        typeByte switch
        {
            SymbolicEngine.StackItemTypeCodes.Pointer => "Pointer",
            SymbolicEngine.StackItemTypeCodes.Boolean => "Boolean",
            SymbolicEngine.StackItemTypeCodes.Integer => "Integer",
            SymbolicEngine.StackItemTypeCodes.ByteString => "ByteString",
            SymbolicEngine.StackItemTypeCodes.Buffer => "Buffer",
            SymbolicEngine.StackItemTypeCodes.Array => "Array",
            SymbolicEngine.StackItemTypeCodes.Struct => "Struct",
            SymbolicEngine.StackItemTypeCodes.Map => "Map",
            SymbolicEngine.StackItemTypeCodes.InteropInterface => "InteropInterface",
            _ => null,
        };

    private static bool ExpressionIsDirectExternalReturnSymbol(Expression expression, string symbolName) =>
        expression is Symbol { Name: var name }
        && string.Equals(name, symbolName, StringComparison.Ordinal);

    private static bool IsRuntimeLoadScriptCall(ExternalCall call) =>
        string.Equals(call.Method, "Runtime.LoadScript", StringComparison.Ordinal);

    private static string RuntimeLoadScriptCompletenessReason(ExternalCall call) =>
        $"Runtime.LoadScript at 0x{call.Offset:X4} uses a dynamic payload, open argument list, or excessive nesting; nested script execution is not fully modeled by this verifier";

    private static string FormatExpectedArgumentCounts(IReadOnlyCollection<ContractMethodDescriptor> methods)
    {
        var counts = methods
            .Select(m => m.Parameters.Count)
            .Distinct()
            .OrderBy(count => count)
            .ToArray();

        return counts.Length == 1
            ? $"expects {counts[0]} argument(s)"
            : $"expects one of [{string.Join(", ", counts)}] argument counts";
    }

    private static bool IsRuntimeByteStringLike(SymbolicValue argument) =>
        argument.Sort is Sort.Bytes or Sort.Buffer;

    private static bool IsAbiType(string actual, string expected) =>
        string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);

    private static bool IsManifestByteStringLike(string type) =>
        IsAbiType(type, "ByteString")
        || IsAbiType(type, "ByteArray");

    private static bool IsReturnMetricByteStringLike(string type) =>
        IsManifestByteStringLike(type)
        || IsAbiType(type, "String")
        || TryGetManifestFixedByteLength(type, out _);

    private static bool IsVerificationByteStringLikeAbiType(string type) =>
        IsReturnMetricByteStringLike(type)
        || IsAbiType(type, "Hash160")
        || IsAbiType(type, "UInt160")
        || IsAbiType(type, "Hash256")
        || IsAbiType(type, "UInt256")
        || IsAbiType(type, "PublicKey")
        || IsAbiType(type, "Signature");

    private static bool IsReturnCountCompoundLike(string type) =>
        TryGetCompoundReturnSort(type, out _);

    private static bool TryGetCompoundReturnSort(string? type, out Sort sort)
    {
        if (type is not null && IsAbiType(type, "Array"))
        {
            sort = Sort.Array;
            return true;
        }

        if (type is not null && IsAbiType(type, "Struct"))
        {
            sort = Sort.Struct;
            return true;
        }

        if (type is not null && IsAbiType(type, "Map"))
        {
            sort = Sort.Map;
            return true;
        }

        sort = Sort.Unknown;
        return false;
    }

    private static bool TryGetManifestFixedByteLength(string type, out int length)
    {
        if (IsAbiType(type, "Hash160") || IsAbiType(type, "UInt160"))
        {
            length = Hash160ByteLength;
            return true;
        }

        if (IsAbiType(type, "Hash256") || IsAbiType(type, "UInt256"))
        {
            length = Hash256ByteLength;
            return true;
        }

        if (IsAbiType(type, "PublicKey"))
        {
            length = CompressedPublicKeyByteLength;
            return true;
        }

        if (IsAbiType(type, "Signature"))
        {
            length = SignatureByteLength;
            return true;
        }

        length = 0;
        return false;
    }

    private static bool TryGetKnownByteLength(ExecutionState state, SymbolicValue argument, out int length)
    {
        if (!IsRuntimeByteStringLike(argument))
        {
            length = 0;
            return false;
        }

        if (TryGetConcreteRuntimeBytes(state, argument, out byte[] bytes))
        {
            length = bytes.Length;
            return true;
        }

        if (TryGetRuntimeByteStringExpression(state, argument, out var byteExpression)
            && Expr.TryKnownByteLength(byteExpression, out length))
        {
            return true;
        }

        if (argument.Expression is HeapRef { RefSort: Sort.Buffer } href
            && state.Heap.Get(href.ObjectId) is BufferObject buffer)
        {
            if (buffer.SymbolicLength is not null
                && Expr.ConcreteInt(buffer.SymbolicLength) is { } symbolicLength
                && symbolicLength >= 0
                && symbolicLength <= int.MaxValue)
            {
                length = (int)symbolicLength;
                return true;
            }

            if (!buffer.IsSymbolicOpen)
            {
                length = buffer.Length;
                return true;
            }

            length = 0;
            return false;
        }

        if (Expr.TryKnownByteLength(argument.Expression, out length))
            return true;

        length = 0;
        return false;
    }

    private static bool TryGetConcreteRuntimeBytes(
        ExecutionState state,
        SymbolicValue argument,
        out byte[] bytes)
    {
        if (argument.Expression is BytesConst bytesConst)
        {
            bytes = bytesConst.Value;
            return true;
        }

        if (argument.Expression is HeapRef { RefSort: Sort.Buffer } href
            && state.Heap.Get(href.ObjectId) is BufferObject buffer)
        {
            if (buffer.SourceBytes is { } sourceBytes
                && Expr.CanonicalBytes(sourceBytes) is { } concreteSourceBytes)
            {
                bytes = concreteSourceBytes;
                return true;
            }

            if (!buffer.IsSymbolicOpen
                && buffer.Cells.All(cell => cell is IntConst))
            {
                bytes = buffer.Cells.Select(cell => (byte)((IntConst)cell).Value).ToArray();
                return true;
            }
        }

        bytes = Array.Empty<byte>();
        return false;
    }

    private static bool TryGetRuntimeByteStringExpression(
        ExecutionState state,
        SymbolicValue argument,
        out Expression expression)
    {
        if (argument.Sort == Sort.Bytes)
        {
            expression = argument.Expression;
            return true;
        }

        if (argument.Expression is HeapRef { RefSort: Sort.Buffer } href
            && state.Heap.Get(href.ObjectId) is BufferObject buffer)
        {
            if (buffer.SourceBytes is { } sourceBytes)
            {
                expression = sourceBytes;
                return true;
            }

            if (!buffer.IsSymbolicOpen && buffer.Cells.All(cell => cell is IntConst))
            {
                expression = Expr.Bytes(buffer.Cells.Select(cell => (byte)((IntConst)cell).Value).ToArray());
                return true;
            }

            expression = new UnaryExpr(Sort.Bytes, "buf2bytes", argument.Expression);
            return true;
        }

        expression = Expr.Bytes(Array.Empty<byte>());
        return false;
    }

    private static bool IsStrictUtf8(byte[] bytes)
    {
        try
        {
            _ = StrictUtf8.GetString(bytes);
            return true;
        }
        catch (System.Text.DecoderFallbackException)
        {
            return false;
        }
    }

    private static bool HasByteLengthConstraint(ExecutionState state, Expression expression, int expectedLength)
    {
        var size = new UnaryExpr(Sort.Int, "size", expression);
        var expected = Expr.Int(expectedLength);
        return state.PathConditions.Any(condition => IsEquality(condition, size, expected));
    }

    private static bool HasStrictUtf8Constraint(ExecutionState state, Expression expression)
    {
        var expected = Expr.IsStrictUtf8(expression);
        return state.PathConditions.Any(condition => condition.Equals(expected));
    }

    private static bool HasValidEcPointConstraint(ExecutionState state, Expression expression)
    {
        var expected = Expr.IsValidEcPoint(expression);
        return state.PathConditions.Any(condition => condition.Equals(expected));
    }

    private static bool IsEquality(Expression expression, Expression left, Expression right) =>
        expression is BinaryExpr { Op: "==", Left: var actualLeft, Right: var actualRight }
        && ((actualLeft.Equals(left) && actualRight.Equals(right))
            || (actualLeft.Equals(right) && actualRight.Equals(left)));

    private static string DescribeRuntimeArgumentType(ExecutionState state, SymbolicValue argument)
    {
        if (TryGetKnownByteLength(state, argument, out int length))
            return $"ByteString({length} bytes)";
        return DescribeRuntimeArgumentType(argument);
    }

    private static string DescribeRuntimeArgumentType(SymbolicValue argument) =>
        argument.Sort switch
        {
            Sort.Int => "Integer",
            Sort.Bool => "Boolean",
            Sort.Bytes => "ByteString",
            Sort.Null => "Null",
            Sort.Buffer => "Buffer",
            Sort.Array => "Array",
            Sort.Struct => "Struct",
            Sort.Map => "Map",
            Sort.Pointer => "Pointer",
            Sort.InteropInterface => "InteropInterface",
            _ => "Unknown",
        };

    private enum AbiReturnTypeCheckKind
    {
        Match,
        Mismatch,
        Incomplete,
    }

    private sealed record AbiReturnTypeCheck(
        AbiReturnTypeCheckKind Kind,
        string Reason,
        ImmutableArray<VerificationAssumption> Assumptions = default)
    {
        public static AbiReturnTypeCheck Match() =>
            new(AbiReturnTypeCheckKind.Match, "");

        public static AbiReturnTypeCheck Match(ImmutableArray<VerificationAssumption> assumptions) =>
            new(AbiReturnTypeCheckKind.Match, "", assumptions);

        public static AbiReturnTypeCheck Mismatch(string reason) =>
            new(AbiReturnTypeCheckKind.Mismatch, reason);

        public static AbiReturnTypeCheck Incomplete(string reason) =>
            new(AbiReturnTypeCheckKind.Incomplete, reason);
    }

    private enum NotificationArgumentTypeCheckKind
    {
        Match,
        Mismatch,
        Incomplete,
    }

    private enum RoyaltySequenceStatus
    {
        Match,
        Mismatch,
        Incomplete,
    }

    private sealed record RoyaltySequenceCheck(
        RoyaltySequenceStatus Status,
        string Reason,
        IReadOnlyList<SymbolicValue> Items)
    {
        public static RoyaltySequenceCheck Match(IReadOnlyList<SymbolicValue> items) =>
            new(RoyaltySequenceStatus.Match, "", items);

        public static RoyaltySequenceCheck Mismatch(string reason) =>
            new(RoyaltySequenceStatus.Mismatch, reason, Array.Empty<SymbolicValue>());

        public static RoyaltySequenceCheck Incomplete(string reason) =>
            new(RoyaltySequenceStatus.Incomplete, reason, Array.Empty<SymbolicValue>());
    }

    private sealed record NotificationArgumentTypeCheck(
        NotificationArgumentTypeCheckKind Kind,
        string Reason)
    {
        public static NotificationArgumentTypeCheck Match() =>
            new(NotificationArgumentTypeCheckKind.Match, "");

        public static NotificationArgumentTypeCheck Mismatch(string reason) =>
            new(NotificationArgumentTypeCheckKind.Mismatch, reason);

        public static NotificationArgumentTypeCheck Incomplete(string reason) =>
            new(NotificationArgumentTypeCheckKind.Incomplete, reason);
    }

    private sealed record Nep24RoyaltyEventParameterSymbols(
        string TokenId,
        string RoyaltyToken,
        string RoyaltyRecipient,
        string Buyer,
        string Amount);

    private static IEnumerable<PropertyRunResult> VerifyProfile(
        NeoProgram program,
        ContractManifest manifest,
        string profile,
        ExecutionOptions options,
        ISmtBackend? smtBackend,
        int maxEntrypoints,
        byte[]? contractHash,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        if (!string.Equals(profile, NeoN3SecurityProfile, StringComparison.OrdinalIgnoreCase))
        {
            yield return PropertyRunResult.Incomplete(
                id: $"profile.{profile}",
                method: "*",
                description: "Unknown verification profile.",
                reason: $"unknown verification profile '{profile}'");
            yield break;
        }

        foreach (var result in VerifyNeoN3SecurityProfile(
            program,
            manifest,
            options,
            smtBackend,
            maxEntrypoints,
            contractHash,
            dependencyProofs,
            requireExternalSmtDependencyProofs))
            yield return result with
            {
                Result = result.Result with { SourceProfile = NeoN3SecurityProfile },
            };
    }

    private static IEnumerable<PropertyRunResult> VerifyNeoN3SecurityProfile(
        NeoProgram program,
        ContractManifest manifest,
        ExecutionOptions options,
        ISmtBackend? smtBackend,
        int maxEntrypoints,
        byte[]? contractHash,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        options = options with
        {
            SelfCallResolver = ManifestSelfCallResolver.Build(manifest),
        };

        yield return PropertyRunResult.Static(BuildManifestPermissionsResult(manifest, contractHash));
        foreach (string standard in UnsupportedProfileStandards(manifest))
        {
            yield return PropertyRunResult.Incomplete(
                id: $"security.standard_coverage.{ProfileStandardResultIdSuffix(standard)}",
                method: "*",
                description: "Neo N3 profile declared-standard coverage.",
                reason: $"manifest declares supported standard '{standard}', but neo-n3-security has no dedicated proof obligations for that standard; standard-specific semantics are not proof-grade covered");
        }

        if (manifest.DeclaresStandard("NEP-17"))
        {
            yield return PropertyRunResult.Static(BuildNep17AbiResult(manifest));
            yield return PropertyRunResult.Static(BuildNep17SymbolValueResult(
                manifest,
                program,
                options));
            yield return PropertyRunResult.Static(BuildNep17DecimalsValueResult(
                manifest,
                program,
                options));
            yield return PropertyRunResult.Static(BuildNep17TotalSupplyNonNegativeResult(
                manifest,
                program,
                options,
                smtBackend));
            yield return PropertyRunResult.Static(BuildNep17BalanceOfNonNegativeResult(
                manifest,
                program,
                options,
                smtBackend));
            yield return PropertyRunResult.Static(BuildNep17TotalSupplyReturnConsistencyResult(
                manifest,
                program,
                options));
        }
        if (manifest.DeclaresStandard("NEP-11"))
        {
            yield return PropertyRunResult.Static(BuildNep11AbiResult(manifest));
            yield return PropertyRunResult.Static(BuildNep11SymbolValueResult(
                manifest,
                program,
                options));
            yield return PropertyRunResult.Static(BuildNep11IteratorReturnResult(
                manifest,
                program,
                options));
            yield return PropertyRunResult.Static(BuildNep11TokenIdParameterLengthResult(
                manifest,
                program,
                options,
                smtBackend));
            yield return PropertyRunResult.Static(BuildNep11DecimalsConsistencyResult(
                manifest,
                program,
                options,
                smtBackend));
            yield return PropertyRunResult.Static(BuildNep11TotalSupplyNonNegativeResult(
                manifest,
                program,
                options,
                smtBackend));
            yield return PropertyRunResult.Static(BuildNep11BalanceOfNonNegativeResult(
                manifest,
                program,
                options,
                smtBackend));
            yield return PropertyRunResult.Static(BuildNep11TotalSupplyReturnConsistencyResult(
                manifest,
                program,
                options));
        }
        if (manifest.DeclaresStandard("NEP-24"))
        {
            yield return PropertyRunResult.Static(BuildNep24AbiResult(manifest));
        }
        if (manifest.DeclaresStandard("NEP-27"))
        {
            yield return PropertyRunResult.Static(BuildNep27AbiResult(manifest));
        }
        if (manifest.DeclaresStandard("NEP-26"))
        {
            yield return PropertyRunResult.Static(BuildNep26AbiResult(manifest));
        }

        if (manifest.Abi.Methods.Count == 0)
        {
            yield return PropertyRunResult.Incomplete(
                id: "security.profile.neo-n3-security",
                method: "*",
                description: "Neo N3 built-in security profile.",
                reason: "manifest declares no ABI methods to verify");
            yield break;
        }

        int methodIndex = 0;
        foreach (var method in manifest.Abi.Methods)
        {
            if (methodIndex >= maxEntrypoints)
            {
                var skipped = manifest.Abi.Methods.Skip(maxEntrypoints)
                    .Select(m => $"{m.Name}@{m.Offset}")
                    .ToArray();
                yield return PropertyRunResult.Incomplete(
                    id: "security.coverage.profile_entrypoint_cap",
                    method: "*",
                    description: "Neo N3 profile entrypoint coverage budget.",
                    reason: $"manifest declares {manifest.Abi.Methods.Count} ABI method(s), exceeding --max-entrypoints {maxEntrypoints}; skipped {string.Join(", ", skipped)}");
                yield break;
            }
            methodIndex++;

            if (ManifestMethodEntryOffsetCoverageReason(program, method) is { } methodOffsetReason)
            {
                yield return PropertyRunResult.Incomplete(
                    id: ProfileMethodResultId(manifest, method, $"security.coverage.{method.Name}"),
                    method: method.Name,
                    description: "Neo N3 profile entrypoint coverage.",
                    reason: methodOffsetReason,
                    methodOffset: method.Offset);
                continue;
            }

            if (ProfileDuplicateParameterNameReason(method) is { } duplicateParameterReason)
            {
                yield return PropertyRunResult.Incomplete(
                    id: ProfileMethodResultId(manifest, method, $"security.coverage.{method.Name}"),
                    method: method.Name,
                    description: "Neo N3 profile entrypoint coverage.",
                    reason: duplicateParameterReason,
                    methodOffset: method.Offset);
                continue;
            }

            string? profileCoverageReason = ProfileMethodEntryCoverageReason(method);
            bool standardObligationsCoverNonExhaustiveParameters =
                profileCoverageReason is not null
                && ProfileStandardObligationsCoverNonExhaustiveParameters(manifest, method);
            if (profileCoverageReason is not null
                && !standardObligationsCoverNonExhaustiveParameters)
            {
                yield return PropertyRunResult.Incomplete(
                    id: ProfileMethodResultId(manifest, method, $"security.coverage.{method.Name}"),
                    method: method.Name,
                    description: "Neo N3 profile entrypoint coverage.",
                    reason: profileCoverageReason,
                    methodOffset: method.Offset);
                continue;
            }

            var methodOptions = OptionsForMethod(manifest, method, options);
            var execution = RunMethodEntry(program, methodOptions, method);
            var currentScriptHash = CurrentScriptHashForProgram(program, methodOptions);

            if (profileCoverageReason is not null
                && standardObligationsCoverNonExhaustiveParameters)
            {
                yield return PropertyRunResult.Incomplete(
                    id: ProfileMethodResultId(manifest, method, $"security.coverage.{method.Name}"),
                    method: method.Name,
                    description: "Neo N3 profile entrypoint coverage.",
                    reason: profileCoverageReason,
                    methodOffset: method.Offset);
            }

            bool includeMethodExecutionStats = true;
            PropertyRunResult WithMethodExecution(VerificationPropertyResult result)
            {
                var qualifiedResult = QualifyProfileMethodResult(manifest, method, result);
                var run = new PropertyRunResult(
                    qualifiedResult with { MethodOffset = method.Offset },
                    execution,
                    includeMethodExecutionStats);
                includeMethodExecutionStats = false;
                return run;
            }

            yield return WithMethodExecution(BuildEntrypointReachabilityResult(method, execution));
            yield return WithMethodExecution(BuildAbiReturnTypeResult(manifest, method, execution, smtBackend));
            if (method.Safe)
                yield return WithMethodExecution(BuildManifestSafeResult(method, execution, smtBackend));
            yield return WithMethodExecution(BuildAccessControlResult(manifest, method, execution, smtBackend));
            yield return WithMethodExecution(BuildExternalReturnResult(
                manifest,
                method,
                execution,
                smtBackend,
                dependencyProofs,
                requireExternalSmtDependencyProofs));
            yield return WithMethodExecution(BuildManifestCallPermissionsResult(manifest, method, execution, smtBackend));
            yield return WithMethodExecution(BuildArithmeticSafetyResult(manifest, method, execution, smtBackend));
            yield return WithMethodExecution(BuildVmFaultFreedomResult(
                manifest,
                method,
                execution,
                smtBackend,
                dependencyProofs,
                requireExternalSmtDependencyProofs,
                currentScriptHash));
            yield return WithMethodExecution(BuildVmSurfaceResult(
                manifest,
                method,
                execution,
                dependencyProofs,
                requireExternalSmtDependencyProofs));
            if (IsNep24RoyaltyInfoMethod(manifest, method))
            {
                yield return WithMethodExecution(BuildNep24RoyaltyInfoBehaviorResult(
                    method,
                    execution,
                    smtBackend));
                yield return WithMethodExecution(BuildNep24SalePriceDependenceResult(
                    method,
                    execution));
            }
            if (manifest.DeclaresStandard("NEP-24")
                && HasConcreteRuntimeNotification(execution, "RoyaltiesTransferred"))
            {
                yield return WithMethodExecution(BuildNep24RoyaltiesTransferredConsistencyResult(
                    method,
                    execution));
            }
            if (IsNep27ReceiverCallbackMethod(manifest, method))
            {
                yield return WithMethodExecution(BuildNep27ReceiverBehaviorResult(
                    manifest,
                    method,
                    execution,
                    smtBackend,
                    dependencyProofs,
                    requireExternalSmtDependencyProofs));
            }
            if (IsNep26ReceiverCallbackMethod(manifest, method))
            {
                yield return WithMethodExecution(BuildNep26ReceiverBehaviorResult(
                    manifest,
                    method,
                    execution,
                    smtBackend,
                    dependencyProofs,
                    requireExternalSmtDependencyProofs));
            }
            if (IsNep17TransferMethod(manifest, method))
            {
                yield return WithMethodExecution(BuildNep17TransferSuccessFeasibilityResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep17SelfTransferSuccessResult(method, execution, currentScriptHash, smtBackend));
                yield return WithMethodExecution(BuildNep17InsufficientBalanceFalseResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep17SenderAuthorizationResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep17ZeroAddressResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep17FailureNoStateChangeResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep17TotalSupplyConservationResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep17BalanceDeltaResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep17BalanceOfStorageConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep17BalanceOfReturnConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep17TransferEventResult(method, execution, currentScriptHash, smtBackend));
                yield return WithMethodExecution(BuildNep17CallbackOrderPayloadResult(method, execution, currentScriptHash, smtBackend));
            }
            if (IsNep17LifecycleMethod(manifest, method))
            {
                yield return WithMethodExecution(BuildLifecycleFailureNoStateChangeResult(
                    "nep17",
                    method,
                    execution,
                    smtBackend));
                yield return WithMethodExecution(BuildNep17LifecycleEventResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    currentScriptHash,
                    smtBackend));
                yield return WithMethodExecution(BuildNep17LifecycleAmountNonNegativeResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep17LifecycleBalanceResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep17LifecycleZeroAddressResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
            }
            if (IsNep11LifecycleMethod(manifest, method))
            {
                bool hasDivisibleOwnerOf = FindAbiMethod(manifest, "ownerOf", IsNep11DivisibleOwnerOfMethod) is not null;
                yield return WithMethodExecution(BuildLifecycleFailureNoStateChangeResult(
                    "nep11",
                    method,
                    execution,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11LifecycleEventResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    currentScriptHash,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11LifecycleZeroAddressResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11LifecycleBalanceResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                if (hasDivisibleOwnerOf && FindAmountParameter(method) >= 0)
                {
                    yield return WithMethodExecution(BuildNep11LifecycleAmountNonNegativeResult(
                        manifest,
                        method,
                        execution,
                        program,
                        options,
                        smtBackend));
                }
                yield return WithMethodExecution(BuildNep11LifecycleIndexResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                if (FindAbiMethod(manifest, "ownerOf", IsNep11NonDivisibleOwnerOfMethod) is not null)
                {
                    yield return WithMethodExecution(BuildNep11LifecycleOwnerStorageResult(
                        manifest,
                        method,
                        execution,
                        program,
                        options,
                        smtBackend));
                }
                if (hasDivisibleOwnerOf)
                {
                    yield return WithMethodExecution(BuildNep11DivisibleLifecycleOwnerOfIndexResult(
                        manifest,
                        method,
                        execution,
                        program,
                        options,
                        smtBackend));
                }
            }
            if (IsNep11NonDivisibleTransferMethod(manifest, method))
            {
                yield return WithMethodExecution(BuildNep11TransferSuccessFeasibilityResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11TokenIdLengthResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11OwnerAuthorizationResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11InvalidTokenFalseResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11OwnerUpdateResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11OwnerBalanceDeltaResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11TokensOfIndexResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11TotalSupplyConservationResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11OwnerOfStorageConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11OwnerOfReturnConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11BalanceOfStorageConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11BalanceOfReturnConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11FailureNoStateChangeResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11TransferEventResult(method, execution, currentScriptHash, smtBackend));
                yield return WithMethodExecution(BuildNep11CallbackOrderPayloadResult(method, execution, currentScriptHash, smtBackend));
            }
            if (IsNep11DivisibleTransferMethod(manifest, method))
            {
                yield return WithMethodExecution(BuildNep11TransferSuccessFeasibilityResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11TokenIdLengthResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleAmountDecimalsBoundResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleSenderAuthorizationResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleInsufficientBalanceFalseResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11FailureNoStateChangeResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11TotalSupplyConservationResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleBalanceDeltaResult(method, execution, smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleOwnerOfIndexResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleBalanceOfStorageConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleBalanceOfReturnConsistencyResult(
                    manifest,
                    method,
                    execution,
                    program,
                    options,
                    smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleTransferEventResult(method, execution, currentScriptHash, smtBackend));
                yield return WithMethodExecution(BuildNep11DivisibleCallbackOrderPayloadResult(method, execution, currentScriptHash, smtBackend));
            }

            foreach (var generated in GenerateNeoN3ProfileProperties(manifest, method))
            {
                yield return WithMethodExecution(VerifyPropertyOnExecution(
                    manifest,
                    method,
                    generated,
                    execution,
                    currentScriptHash,
                    smtBackend,
                    dependencyProofs,
                    requireExternalSmtDependencyProofs));
            }
        }
    }

    private static VerificationPropertyResult QualifyProfileMethodResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        VerificationPropertyResult result) =>
        string.Equals(result.Method, method.Name, StringComparison.Ordinal)
            ? result with { Id = ProfileMethodResultId(manifest, method, result.Id) }
            : result;

    private static string ProfileMethodResultId(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        string id) =>
        HasSameNameAbiOverload(manifest, method)
            ? $"{id}@{method.Offset}"
            : id;

    private static bool HasSameNameAbiOverload(
        ContractManifest manifest,
        ContractMethodDescriptor method) =>
        manifest.Abi.Methods.Count(m => string.Equals(m.Name, method.Name, StringComparison.Ordinal)) > 1;

    private static IEnumerable<string> UnsupportedProfileStandards(ContractManifest manifest) =>
        manifest.SupportedStandards
            .Where(standard => !string.IsNullOrWhiteSpace(standard))
            .GroupBy(NormalizeProfileStandardTag)
            .Select(group => group.First())
            .Where(standard => !NeoN3SecurityProfileCoveredStandards.Contains(NormalizeProfileStandardTag(standard)))
            .OrderBy(standard => standard, StringComparer.Ordinal);

    private static string NormalizeProfileStandardTag(string standard) =>
        new(standard.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    private static string ProfileStandardResultIdSuffix(string standard)
    {
        string normalized = NormalizeProfileStandardTag(standard);
        return normalized.Length == 0 ? "UNKNOWN" : normalized;
    }

    private static VerificationPropertyResult BuildTokenSymbolValueResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        string standardId,
        string standardName)
    {
        string id = $"security.{standardId}.symbol_value.symbol";
        const string methodName = "symbol";
        string description = $"{standardName} symbol() must return one stable ASCII token symbol.";
        const string failedCondition = "symbol() is a unique concrete value and symbol() is non-empty ASCII without whitespace or control characters";

        if (FindAbiMethod(manifest, methodName, IsStringSafeNoParameterMethod) is not { } symbol)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: $"{standardName} manifest has no proof-grade symbol(): String safe=true method to prove a stable token symbol",
                FailedCondition: null,
                Counterexample: null);
        }

        if (symbol.Offset < 0 || symbol.Offset >= program.Bytes.Length)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: $"symbol() offset {symbol.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: symbol.Offset);
        }

        var execution = RunMethodEntry(program, options, symbol);
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = IncompleteReasons(execution)
            .Select(reason => "symbol(): " + reason)
            .ToList();
        var values = new HashSet<string>(StringComparer.Ordinal);

        foreach (var state in execution.Halted)
        {
            obligations++;
            if (state.EvaluationStack.Count == 0)
            {
                return Violated(
                    counts,
                    obligations,
                    $"{standardName} symbol() halts without returning a String value.",
                    BuildStateWitness(null, state),
                    symbol.Offset);
            }

            var returned = state.Peek();
            if (!IsRuntimeByteStringLike(returned))
            {
                return Violated(
                    counts,
                    obligations,
                    $"{standardName} symbol() returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem instead of String-compatible ByteString or Buffer.",
                    BuildStateWitness(null, state),
                    symbol.Offset);
            }

            if (!TryGetConcreteRuntimeBytes(state, returned, out byte[] bytes))
            {
                incompleteReasons.Add($"symbol() return value is symbolic; {standardName} requires a unique concrete symbol() value");
                continue;
            }

            if (!IsStrictUtf8(bytes))
            {
                return Violated(
                    counts,
                    obligations,
                    $"{standardName} symbol() returns bytes that are not valid strict UTF-8.",
                    BuildStateWitness(null, state),
                    symbol.Offset);
            }

            if (bytes.Length == 0)
            {
                return Violated(
                    counts,
                    obligations,
                    $"{standardName} symbol() returns an empty token symbol.",
                    BuildStateWitness(null, state),
                    symbol.Offset);
            }

            if (bytes.Any(b => b > 0x7F))
            {
                return Violated(
                    counts,
                    obligations,
                    $"{standardName} symbol() returns non-ASCII characters.",
                    BuildStateWitness(null, state),
                    symbol.Offset);
            }

            if (bytes.Any(b => b < 0x20 || b == 0x7F))
            {
                return Violated(
                    counts,
                    obligations,
                    $"{standardName} symbol() returns control characters.",
                    BuildStateWitness(null, state),
                    symbol.Offset);
            }

            if (bytes.Any(b => char.IsWhiteSpace((char)b)))
            {
                return Violated(
                    counts,
                    obligations,
                    $"{standardName} symbol() returns whitespace characters.",
                    BuildStateWitness(null, state),
                    symbol.Offset);
            }

            values.Add(System.Text.Encoding.ASCII.GetString(bytes));
        }

        if (values.Count == 0)
            incompleteReasons.Add("symbol() produced no successful HALT path");
        if (values.Count > 1)
        {
            return Violated(
                counts,
                obligations,
                $"{standardName} symbol() can return multiple concrete values ({string.Join(", ", values.OrderBy(value => value))}); token symbol must be stable.",
                null,
                symbol.Offset);
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: symbol.Offset);
        }

        return new VerificationPropertyResult(
            id,
            methodName,
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            $"{standardName} symbol() returns stable ASCII symbol {values.Single()} on every successful path",
            FailedCondition: null,
            Counterexample: null,
            MethodOffset: symbol.Offset);

        VerificationPropertyResult Violated(
            (int CheckedPaths, int IgnoredFaultedPaths, int StoppedPaths) Counts,
            int ObligationsChecked,
            string Reason,
            ImmutableDictionary<string, object>? Counterexample,
            int MethodOffset) =>
            new(
                id,
                methodName,
                description,
                VerificationStatus.Violated,
                Counts.CheckedPaths,
                Counts.IgnoredFaultedPaths,
                Counts.StoppedPaths,
                ObligationsChecked,
                Reason,
                failedCondition,
                Counterexample,
                MethodOffset: MethodOffset);
    }

    private static bool UsesManifestByteArrayTokenIdAbi(ContractManifest manifest) =>
        manifest.Abi.Methods.Any(method =>
            method.Parameters.Any(parameter =>
                string.Equals(parameter.Name, "tokenId", StringComparison.Ordinal)
                && IsType(parameter.Type, "ByteArray")))
        || manifest.Abi.Events.Any(@event =>
            string.Equals(@event.Name, "Transfer", StringComparison.Ordinal)
            && @event.Parameters.Any(parameter =>
                string.Equals(parameter.Name, "tokenId", StringComparison.Ordinal)
                && IsType(parameter.Type, "ByteArray")));

    private static bool ExpressionOrTaintDependsOn(SymbolicValue value, string symbolName) =>
        value.Taints.Contains(symbolName, StringComparer.Ordinal)
        || ExpressionDependsOn(value.Expression, symbolName);

    private static bool ExpressionDependsOn(Expression expression, string symbolName) =>
        expression.FreeSymbols().Contains(symbolName, StringComparer.Ordinal);

    private static bool TryValidateNep11TokensOfIteratorShape(
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue iterator,
        out string? violationReason,
        out string? failedCondition,
        out string? incompleteReason)
    {
        violationReason = null;
        failedCondition = null;
        incompleteReason = null;

        if (method.Parameters.Count == 0)
        {
            incompleteReason = "tokensOf(owner) has no owner parameter";
            return false;
        }

        string ownerSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[0].Name, 0);
        if (!TryGetNep11IteratorFindProvenance(
            "tokensOf(owner)",
            state,
            iterator,
            out var prefix,
            out var concreteOptions,
            out incompleteReason))
            return false;

        if (!prefix.Expression.FreeSymbols().Contains(ownerSymbol, StringComparer.Ordinal))
        {
            violationReason = "tokensOf(owner) returns a Storage.Find iterator whose prefix does not depend on owner.";
            failedCondition = "tokensOf(owner): owner-scoped Storage.Find prefix";
            return false;
        }

        if (!HasConcreteNamespaceBeforeSymbol(prefix.Expression, ownerSymbol))
        {
            violationReason = "tokensOf(owner) returns a Storage.Find iterator whose prefix is not rooted in a concrete owner-token namespace before owner.";
            failedCondition = "tokensOf(owner): concrete namespace before owner in Storage.Find prefix";
            return false;
        }

        return TryValidateNep11IteratorFindOptions(
            "tokensOf(owner)",
            concreteOptions,
            "tokensOf(owner): tokenId iterator uses KeysOnly",
            "tokensOf(owner): tokenId iterator removes owner prefix",
            "tokensOf(owner) returns owner-scoped storage keys without removing the owner prefix.",
            out violationReason,
            out failedCondition);
    }

    private static bool TryValidateNep11TokensIteratorShape(
        ExecutionState state,
        SymbolicValue iterator,
        out string? violationReason,
        out string? failedCondition,
        out string? incompleteReason)
    {
        violationReason = null;
        failedCondition = null;
        incompleteReason = null;

        if (!TryGetNep11IteratorFindProvenance(
            "tokens()",
            state,
            iterator,
            out var prefix,
            out var concreteOptions,
            out incompleteReason))
            return false;

        if (Expr.CanonicalBytes(prefix.Expression) is not { } concretePrefix)
        {
            incompleteReason = "tokens() uses symbolic Storage.Find prefix; the verifier cannot prove it enumerates token IDs";
            return false;
        }

        if (concretePrefix.Length == 0)
        {
            violationReason = "tokens() returns a Storage.Find iterator with an empty prefix, which can enumerate unrelated storage keys.";
            failedCondition = "tokens(): concrete tokenId Storage.Find prefix";
            return false;
        }

        return TryValidateNep11IteratorFindOptions(
            "tokens()",
            concreteOptions,
            "tokens(): tokenId iterator uses KeysOnly",
            "tokens(): tokenId iterator removes token namespace prefix",
            "tokens() returns token storage keys without removing the token namespace prefix.",
            out violationReason,
            out failedCondition);
    }

    private static bool TryValidateNep11DivisibleOwnerOfIteratorShape(
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue iterator,
        out string? violationReason,
        out string? failedCondition,
        out string? incompleteReason)
    {
        violationReason = null;
        failedCondition = null;
        incompleteReason = null;

        int tokenIdIndex = FindNamedNep11TokenIdParameter(method);
        if (tokenIdIndex < 0)
        {
            incompleteReason = "ownerOf(tokenId) has no named tokenId ByteString parameter";
            return false;
        }

        if (!TryGetNep11IteratorFindProvenance(
            "ownerOf(tokenId)",
            state,
            iterator,
            out var prefix,
            out var concreteOptions,
            out incompleteReason))
            return false;

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        if (!prefix.Expression.FreeSymbols().Contains(tokenIdSymbol, StringComparer.Ordinal))
        {
            violationReason = "divisible ownerOf(tokenId) returns a Storage.Find iterator whose prefix does not depend on tokenId.";
            failedCondition = "ownerOf(tokenId): tokenId-scoped Storage.Find prefix";
            return false;
        }

        if (!HasConcreteNamespaceBeforeSymbol(prefix.Expression, tokenIdSymbol))
        {
            violationReason = "divisible ownerOf(tokenId) returns a Storage.Find iterator whose prefix is not rooted in a concrete owner namespace before tokenId.";
            failedCondition = "ownerOf(tokenId): concrete namespace before tokenId in Storage.Find prefix";
            return false;
        }

        return TryValidateNep11IteratorFindOptions(
            "ownerOf(tokenId)",
            concreteOptions,
            "ownerOf(tokenId): owner iterator uses KeysOnly",
            "ownerOf(tokenId): owner iterator removes tokenId prefix",
            "divisible ownerOf(tokenId) returns token-scoped storage keys without removing the tokenId prefix.",
            out violationReason,
            out failedCondition);
    }

    private static bool TryGetNep11IteratorFindProvenance(
        string displayName,
        ExecutionState state,
        SymbolicValue iterator,
        out SymbolicValue prefix,
        out BigInteger concreteOptions,
        out string? incompleteReason)
    {
        prefix = SymbolicValue.Null();
        concreteOptions = BigInteger.Zero;
        incompleteReason = null;

        if (!TryGetIteratorSymbolName(iterator, out string iteratorName))
        {
            incompleteReason = $"{displayName} returns a Neo iterator whose Storage.Find provenance is unknown";
            return false;
        }

        if (!state.InteropContext.TryGetValue($"iterator_prefix:{iteratorName}", out var foundPrefix))
        {
            incompleteReason = $"{displayName} returns a Neo iterator without recorded Storage.Find prefix provenance";
            return false;
        }

        prefix = foundPrefix;

        if (!state.InteropContext.TryGetValue($"iterator_options:{iteratorName}", out var options))
        {
            incompleteReason = $"{displayName} returns a Neo iterator without recorded Storage.Find options provenance";
            return false;
        }

        if (options.Expression is not IntConst { Value: var optionsValue })
        {
            incompleteReason = $"{displayName} uses symbolic Storage.Find options; the verifier cannot prove it returns key-only values";
            return false;
        }

        concreteOptions = optionsValue;
        return true;
    }

    private static bool TryValidateNep11IteratorFindOptions(
        string displayName,
        BigInteger concreteOptions,
        string keysOnlyFailedCondition,
        string removePrefixFailedCondition,
        string removePrefixViolationReason,
        out string? violationReason,
        out string? failedCondition)
    {
        violationReason = null;
        failedCondition = null;

        if ((concreteOptions & FindOptionsKeysOnly) == 0)
        {
            violationReason = $"{displayName} returns a Storage.Find iterator that is not configured with FindOptions.KeysOnly.";
            failedCondition = keysOnlyFailedCondition;
            return false;
        }

        if ((concreteOptions & FindOptionsRemovePrefix) == 0)
        {
            violationReason = removePrefixViolationReason;
            failedCondition = removePrefixFailedCondition;
            return false;
        }

        return true;
    }

    private static bool HasConcreteNamespaceBeforeSymbol(Expression expression, string symbolName)
    {
        bool sawConcreteNamespace = false;
        foreach (var segment in FlattenByteConcat(expression))
        {
            if (segment.FreeSymbols().Contains(symbolName, StringComparer.Ordinal))
                return sawConcreteNamespace;

            if (Expr.CanonicalBytes(segment) is { Length: > 0 })
                sawConcreteNamespace = true;
        }

        return false;
    }

    private static IEnumerable<Expression> FlattenByteConcat(Expression expression)
    {
        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } binary)
        {
            foreach (var segment in FlattenByteConcat(binary.Left))
                yield return segment;
            foreach (var segment in FlattenByteConcat(binary.Right))
                yield return segment;
            yield break;
        }

        yield return expression;
    }

    private static bool TryGetIteratorSymbolName(SymbolicValue value, out string name)
    {
        if (value.Expression is Symbol { Name: var symbolName }
            && symbolName.StartsWith("iterator_", StringComparison.Ordinal))
        {
            name = symbolName;
            return true;
        }

        name = string.Empty;
        return false;
    }

    private static IteratorReturnClassification ClassifyIteratorReturn(
        ExecutionState state,
        SymbolicValue value,
        out string description)
    {
        if (value.Expression is Symbol { Name: var name })
        {
            if (name.StartsWith("iterator_", StringComparison.Ordinal))
            {
                description = "Neo iterator InteropInterface";
                return IteratorReturnClassification.Iterator;
            }

            if (name.StartsWith("storage_ctx_", StringComparison.Ordinal))
            {
                description = "StorageContext InteropInterface";
                return IteratorReturnClassification.KnownNonIterator;
            }

            description = $"InteropInterface symbol '{name}'";
            return IteratorReturnClassification.Unknown;
        }

        if (value.Expression is HeapRef { RefSort: Sort.InteropInterface } href
            && state.Heap.Get(href.ObjectId) is InteropObject interop)
        {
            description = $"{interop.Kind} InteropInterface";
            return IteratorReturnClassification.KnownNonIterator;
        }

        description = "InteropInterface value of unknown kind";
        return IteratorReturnClassification.Unknown;
    }

    private enum IteratorReturnClassification
    {
        Iterator,
        KnownNonIterator,
        Unknown,
    }

    private static VerificationPropertyResult BuildTokenTransferSuccessFeasibilityResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        string standardId,
        string standardName)
    {
        string id = $"security.{standardId}.transfer_success_feasible.{method.Name}";
        string description = $"{standardName} transfer must have at least one feasible true-return success path.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            obligations++;
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Proved,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"at least one {standardName} transfer path can return true",
                FailedCondition: null,
                Counterexample: null);
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }
        if (BuildIncompleteResult(id, method.Name, description, execution, obligations) is { } incomplete)
            return incomplete;
        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, execution, obligations) is { } noHalt)
            return noHalt;

        return new VerificationPropertyResult(
            id,
            method.Name,
            description,
            VerificationStatus.Violated,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            $"{standardName} transfer has no feasible true-return transfer path.",
            "transfer exposes at least one successful true-return path",
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildLifecycleFailureNoStateChangeResult(
        string standardId,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string lifecycle = string.Equals(method.Name, "mint", StringComparison.OrdinalIgnoreCase) ? "mint" : "burn";
        string id = $"security.{standardId}.lifecycle_failure_no_state_change.{method.Name}";
        string description = $"{standardId.ToUpperInvariant()} {lifecycle} false-return paths must not perform observable side effects.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeFalse(method, state, smtBackend, out bool returnMayBeFalse, out var outcome, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeFalse)
                continue;

            obligations++;
            string failedCondition = $"false-return {lifecycle} path has no Storage.Put, Storage.Delete, Runtime.Notify, or external side-effect call";
            var sideEffect = FalseReturnSideEffects(state, failedCondition)
                .OrderBy(effect => effect.Offset)
                .FirstOrDefault();
            if (sideEffect is null)
                continue;

            if (outcome == SmtOutcome.Sat)
            {
                var query = BuildFalseReturnReachabilityQuery(method, state);
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{lifecycle} can return false after {sideEffect.Display}.",
                    sideEffect.FailedCondition,
                    BuildWitness(smtBackend, query));
            }

            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Unknown,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"solver could not prove a side-effecting {lifecycle} path at 0x{sideEffect.Offset:X4} cannot return false",
                sideEffect.FailedCondition,
                BuildStateWitness(smtBackend, state));
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }
        if (BuildIncompleteResult(id, method.Name, description, execution, obligations) is { } incomplete)
            return incomplete;
        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, execution, obligations) is { } noHalt)
            return noHalt;

        return new VerificationPropertyResult(
            id,
            method.Name,
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            obligations == 0
                ? $"property holds vacuously: no successful {lifecycle} path can return false"
                : $"every false-return {standardId.ToUpperInvariant()} {lifecycle} path avoids Storage.Put, Storage.Delete, Runtime.Notify, and external side-effect calls",
            FailedCondition: null,
            Counterexample: null);
    }

    private static bool TryGetConcreteNep11Decimals(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        out BigInteger decimals,
        out string reason,
        out int? methodOffset)
    {
        decimals = BigInteger.Zero;
        methodOffset = null;
        if (FindAbiMethod(manifest, "decimals", IsIntegerSafeNoParameterMethod) is not { } decimalsMethod)
        {
            reason = "NEP-11 manifest has no decimals(): Integer safe=true method to compute divisible max transfer amount";
            return false;
        }

        methodOffset = decimalsMethod.Offset;
        if (decimalsMethod.Offset < 0 || decimalsMethod.Offset >= program.Bytes.Length)
        {
            reason = $"decimals() offset {decimalsMethod.Offset} is outside script bytes";
            return false;
        }

        var execution = RunMethodEntry(program, options, decimalsMethod);
        var incompleteReasons = IncompleteReasons(execution)
            .Select(r => "decimals(): " + r)
            .ToList();
        var values = new HashSet<BigInteger>();
        foreach (var state in execution.Halted)
        {
            if (state.EvaluationStack.Count == 0)
            {
                reason = "decimals() halts without returning an Integer value";
                return false;
            }

            var returnValue = state.Peek().Expression;
            if (returnValue.Sort != Sort.Int)
            {
                reason = $"decimals() returns a {returnValue.Sort} StackItem instead of Integer";
                return false;
            }

            if (Expr.ConcreteInt(returnValue) is not { } concrete)
            {
                reason = "decimals() return value is symbolic; divisible max transfer amount requires a unique concrete decimals() value";
                return false;
            }

            values.Add(concrete);
        }

        if (values.Count == 0)
            incompleteReasons.Add("decimals() produced no successful HALT path");
        if (incompleteReasons.Count > 0)
        {
            reason = string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal));
            return false;
        }

        if (values.Count != 1)
        {
            reason = "decimals() can return multiple concrete values; divisible max transfer amount requires a unique decimals() value";
            return false;
        }

        decimals = values.Single();
        reason = "";
        return true;
    }

    private static VerificationPropertyResult BuildMissingBalanceOfNonNegativeResult(
        string standardId,
        string standardName,
        string methodSignature) =>
        new(
            $"security.{standardId}.balanceof_non_negative.balanceOf",
            "balanceOf",
            $"{standardName} {methodSignature} must return a non-negative integer.",
            VerificationStatus.Incomplete,
            CheckedPaths: 0,
            IgnoredFaultedPaths: 0,
            StoppedPaths: 0,
            ObligationsChecked: 0,
            Reason: $"{standardName} manifest has no {methodSignature} method to check non-negativity",
            FailedCondition: null,
            Counterexample: null);

    private static VerificationPropertyResult BuildTokenTotalSupplyNonNegativeResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend,
        string standardId,
        string standardName)
    {
        string id = $"security.{standardId}.totalsupply_non_negative.totalSupply";
        const string methodName = "totalSupply";
        string description = $"{standardName} totalSupply() must return a non-negative integer.";
        const string failedCondition = "totalSupply() >= 0";
        if (FindAbiMethod(manifest, methodName, IsIntegerSafeNoParameterMethod) is not { } totalSupply)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: $"{standardName} manifest has no totalSupply() method to check non-negativity",
                FailedCondition: null,
                Counterexample: null);
        }

        if (totalSupply.Offset < 0 || totalSupply.Offset >= program.Bytes.Length)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: $"totalSupply() offset {totalSupply.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: totalSupply.Offset);
        }

        var supplyExecution = RunMethodEntry(program, options, totalSupply);
        var counts = CountPaths(supplyExecution);
        int obligations = 0;
        var incompleteReasons = IncompleteReasons(supplyExecution)
            .Select(reason => "totalSupply(): " + reason)
            .ToList();
        var halted = supplyExecution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("totalSupply() produced no successful HALT path");

        foreach (var state in halted)
        {
            obligations++;
            if (state.EvaluationStack.Count == 0)
            {
                return new VerificationPropertyResult(
                    id,
                    methodName,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "totalSupply() halts without returning an Integer value.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    MethodOffset: totalSupply.Offset);
            }

            var returnValue = state.Peek().Expression;
            if (returnValue.Sort != Sort.Int)
            {
                return new VerificationPropertyResult(
                    id,
                    methodName,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{standardName} totalSupply() returns a {returnValue.Sort} StackItem instead of Integer.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    MethodOffset: totalSupply.Offset);
            }

            var negativeCondition = Expr.Lt(returnValue, Expr.Int(0));
            if (negativeCondition is BoolConst { Value: false })
                continue;

            if (negativeCondition is BoolConst { Value: true })
            {
                string display = Expr.ConcreteInt(returnValue) is { } concrete
                    ? concrete.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    : "a negative value";
                return new VerificationPropertyResult(
                    id,
                    methodName,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{standardName} totalSupply() returns negative value {display}.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    MethodOffset: totalSupply.Offset);
            }

            var query = BuildReachabilityQuery(
                ImmutableArray<Expression>.Empty,
                state.PathConditions,
                negativeCondition);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Sat)
            {
                return new VerificationPropertyResult(
                    id,
                    methodName,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{standardName} totalSupply() can return a negative value.",
                    failedCondition,
                    BuildWitness(smtBackend, query),
                    MethodOffset: totalSupply.Offset);
            }

            if (outcome == SmtOutcome.Unknown)
                incompleteReasons.Add($"solver returned unknown while proving {standardName} totalSupply() >= 0");
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: totalSupply.Offset);
        }

        return new VerificationPropertyResult(
            id,
            methodName,
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            $"{standardName} totalSupply() returns a non-negative integer on every successful path",
            FailedCondition: null,
            Counterexample: null,
            MethodOffset: totalSupply.Offset);
    }

    private static VerificationPropertyResult BuildTokenBalanceOfNonNegativeResult(
        ContractMethodDescriptor balanceOf,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend,
        string standardId,
        string standardName,
        string methodSignature)
    {
        string id = $"security.{standardId}.balanceof_non_negative.balanceOf";
        string description = $"{standardName} {methodSignature} must return a non-negative integer.";
        string failedCondition = $"{methodSignature} >= 0";
        if (balanceOf.Offset < 0 || balanceOf.Offset >= program.Bytes.Length)
        {
            return new VerificationPropertyResult(
                id,
                "balanceOf",
                description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: $"{methodSignature} offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: balanceOf.Offset);
        }

        var balanceExecution = RunMethodEntry(program, options, balanceOf);
        var counts = CountPaths(balanceExecution);
        int obligations = 0;
        var incompleteReasons = IncompleteReasons(balanceExecution)
            .Select(reason => $"{methodSignature}: " + reason)
            .ToList();
        var halted = balanceExecution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add($"{methodSignature} produced no successful HALT path");

        foreach (var state in halted)
        {
            obligations++;
            if (state.EvaluationStack.Count == 0)
            {
                return new VerificationPropertyResult(
                    id,
                    "balanceOf",
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{methodSignature} halts without returning an Integer value.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    MethodOffset: balanceOf.Offset);
            }

            var returnValue = state.Peek().Expression;
            if (returnValue.Sort != Sort.Int)
            {
                return new VerificationPropertyResult(
                    id,
                    "balanceOf",
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{standardName} {methodSignature} returns a {returnValue.Sort} StackItem instead of Integer.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    MethodOffset: balanceOf.Offset);
            }

            var negativeCondition = Expr.Lt(returnValue, Expr.Int(0));
            if (negativeCondition is BoolConst { Value: false })
                continue;

            if (negativeCondition is BoolConst { Value: true })
            {
                string display = Expr.ConcreteInt(returnValue) is { } concrete
                    ? concrete.ToString(System.Globalization.CultureInfo.InvariantCulture)
                    : "a negative value";
                return new VerificationPropertyResult(
                    id,
                    "balanceOf",
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{standardName} {methodSignature} returns negative value {display}.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    MethodOffset: balanceOf.Offset);
            }

            var query = BuildReachabilityQuery(
                ImmutableArray<Expression>.Empty,
                state.PathConditions,
                negativeCondition);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Sat)
            {
                return new VerificationPropertyResult(
                    id,
                    "balanceOf",
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"{standardName} {methodSignature} can return a negative value.",
                    failedCondition,
                    BuildWitness(smtBackend, query),
                    MethodOffset: balanceOf.Offset);
            }

            if (outcome == SmtOutcome.Unknown)
                incompleteReasons.Add($"solver returned unknown while proving {standardName} {methodSignature} >= 0");
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                "balanceOf",
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: balanceOf.Offset);
        }

        return new VerificationPropertyResult(
            id,
            "balanceOf",
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            $"{standardName} {methodSignature} returns a non-negative integer on every successful path",
            FailedCondition: null,
            Counterexample: null,
            MethodOffset: balanceOf.Offset);
    }

    private static VerificationPropertyResult BuildTokenTotalSupplyReturnConsistencyResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        string standardId,
        string standardName)
    {
        string id = $"security.{standardId}.totalsupply_return_consistency.totalSupply";
        const string methodName = "totalSupply";
        string description = $"{standardName} totalSupply() must return the supply storage value it reads.";
        if (FindAbiMethod(manifest, methodName, IsIntegerSafeNoParameterMethod) is not { } totalSupply)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: $"{standardName} manifest has no totalSupply() method to check return consistency",
                FailedCondition: null,
                Counterexample: null);
        }

        if (totalSupply.Offset < 0 || totalSupply.Offset >= program.Bytes.Length)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: $"totalSupply() offset {totalSupply.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: totalSupply.Offset);
        }

        var supplyExecution = RunMethodEntry(program, options, totalSupply);
        var counts = CountPaths(supplyExecution);
        int obligations = 0;
        var incompleteReasons = IncompleteReasons(supplyExecution)
            .Select(reason => "totalSupply(): " + reason)
            .ToList();
        var halted = supplyExecution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("totalSupply() produced no successful HALT path");

        foreach (var state in halted)
        {
            var reads = state.Telemetry.StorageOps
                .Where(op => op.Kind == StorageOpKind.Get)
                .OrderBy(op => op.Offset)
                .ToList();
            if (reads.Count == 0)
                continue;

            obligations++;
            if (state.EvaluationStack.Count == 0)
            {
                return new VerificationPropertyResult(
                    id,
                    methodName,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "totalSupply() reads supply storage but halts without returning a value.",
                    "totalSupply returns the supply storage value",
                    BuildStateWitness(null, state),
                    MethodOffset: totalSupply.Offset);
            }

            var returnValue = state.Peek().Expression;
            if (reads.Any(read => ReturnMatchesStorageReadOrMissingZero(state, returnValue, read.Offset)))
                continue;

            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                "totalSupply() does not return the storage value it reads.",
                "totalSupply returns the supply storage value",
                BuildStateWitness(null, state),
                MethodOffset: totalSupply.Offset);
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: totalSupply.Offset);
        }

        return new VerificationPropertyResult(
            id,
            methodName,
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            obligations == 0
                ? "property holds vacuously: totalSupply() does not read storage"
                : "totalSupply() returns the same supply storage value it reads",
            FailedCondition: null,
            Counterexample: null,
            MethodOffset: totalSupply.Offset);
    }

    private static VerificationPropertyResult BuildTokenTotalSupplyConservationResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend,
        string standardId,
        string standardName)
    {
        string id = $"security.{standardId}.total_supply_unchanged.{method.Name}";
        string description = $"{standardName} transfer true-return paths must not mutate storage keys backing totalSupply().";
        var counts = CountPaths(transferExecution);
        int obligations = 0;

        if (FindAbiMethod(manifest, "totalSupply", IsIntegerSafeNoParameterMethod) is not { } totalSupply)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"{standardName} manifest has no totalSupply() method to infer supply storage keys from",
                FailedCondition: null,
                Counterexample: null);
        }

        if (totalSupply.Offset < 0 || totalSupply.Offset >= program.Bytes.Length)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"totalSupply() offset {totalSupply.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var supplyExecution = RunMethodEntry(program, options, totalSupply);
        var supplyKeys = InferTotalSupplyStorageKeys(supplyExecution, out var supplyReasons);
        if (supplyReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", supplyReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }

        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, transferExecution, obligations) is { } noHalt)
            return noHalt;

        if (supplyKeys.Length == 0)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Proved,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                "property holds vacuously: totalSupply() does not read storage",
                FailedCondition: null,
                Counterexample: null);
        }

        var incompleteReasons = new List<string>();
        foreach (var state in transferExecution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                obligations++;
                if (TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                        continue;

                    string opName = mutation.Kind == StorageOpKind.Put ? "Storage.Put" : "Storage.Delete";
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"transfer can return true after {opName} mutates totalSupply() storage key {FormatStorageKey(mutationKey)} at 0x{mutation.Offset:X4}.",
                        "true-return transfer does not mutate totalSupply() storage",
                        BuildStateWitness(smtBackend, state));
                }

                if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                {
                    incompleteReasons.Add("true-return transfer mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }
            }
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }
        if (BuildIncompleteResult(id, method.Name, description, transferExecution, obligations) is { } incomplete)
            return incomplete;
        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, transferExecution, obligations) is { } noHaltAfterIncomplete)
            return noHaltAfterIncomplete;

        return new VerificationPropertyResult(
            id,
            method.Name,
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            $"every true-return {standardName} transfer path leaves totalSupply() storage keys untouched",
            FailedCondition: null,
            Counterexample: null);
    }

    private static ImmutableArray<VerificationAssumption> NepTokenStorageIntegerEncodingAssumptions(bool include) =>
        include
            ? ImmutableArray.Create(NepTokenStorageIntegerEncodingAssumption)
            : ImmutableArray<VerificationAssumption>.Empty;

    private static ImmutableArray<VerificationAssumption> CombineAssumptions(
        params ImmutableArray<VerificationAssumption>[] groups) =>
        groups
            .SelectMany(group => group.IsDefaultOrEmpty
                ? Enumerable.Empty<VerificationAssumption>()
                : group)
            .Distinct()
            .ToImmutableArray();

    private static ImmutableArray<Expression> ProfileStorageIntegerEncodingRequires(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state)
    {
        if (!UsesNepTokenStorageIntegerInvariant(manifest, method))
            return ImmutableArray<Expression>.Empty;

        var requires = ImmutableArray.CreateBuilder<Expression>();
        var seen = new HashSet<Expression>();
        foreach (var require in ProfileMissingStorageIntegerRequires(manifest, method, state))
        {
            if (seen.Add(require))
                requires.Add(require);
        }
        foreach (var op in state.Telemetry.FaultConditions)
        {
            if (!TryGetStorageValueIntegerEncodingSize(op, out var sizeExpression, out int storageGetOffset)
                || !IsProfileTokenStorageIntegerRead(manifest, method, state, storageGetOffset))
            {
                continue;
            }

            var require = Expr.Le(sizeExpression, Expr.Int(NeoVmIntegerMaxBytes));
            if (seen.Add(require))
                requires.Add(require);
        }
        return requires.ToImmutable();
    }

    private static IEnumerable<Expression> ProfileMissingStorageIntegerRequires(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state)
    {
        if (state.Status != TerminalStatus.Faulted
            || !IsStorageBackedIntegerNullFault(state.TerminationReason))
        {
            yield break;
        }

        foreach (var condition in state.PathConditions)
        {
            foreach (var symbol in MissingStorageReadExistenceSymbols(condition))
            {
                if (TryParseStorageReadSymbolOffset(symbol, "storage_exists_", out int storageGetOffset)
                    && IsProfileTokenStorageIntegerRead(manifest, method, state, storageGetOffset))
                {
                    yield return Expr.Sym(Sort.Bool, symbol);
                }
            }
        }
    }

    private static bool IsStorageBackedIntegerNullFault(string? terminationReason) =>
        terminationReason is not null
        && terminationReason.EndsWith(" with null operand", StringComparison.Ordinal);

    private static IEnumerable<string> MissingStorageReadExistenceSymbols(Expression condition)
    {
        switch (condition)
        {
            case BinaryExpr { Op: "and" } binary:
                foreach (var left in MissingStorageReadExistenceSymbols(binary.Left))
                    yield return left;
                foreach (var right in MissingStorageReadExistenceSymbols(binary.Right))
                    yield return right;
                yield break;
            case UnaryExpr
            {
                Op: "not",
                Operand: Symbol { Sort: Sort.Bool, Name: var name }
            } when name.StartsWith("storage_exists_", StringComparison.Ordinal):
                yield return name;
                yield break;
        }
    }

    private static bool IsProfileTokenStorageIntegerRead(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        int storageGetOffset)
    {
        if (IsTotalSupplyMethod(method))
            return ReturnMatchesTokenSupplyStorageRead(state, storageGetOffset);

        if (manifest.DeclaresStandard("NEP-17") && HasCompleteNep17AbiShape(manifest))
            return IsNep17StorageIntegerRead(manifest, method, state, storageGetOffset);

        if (manifest.DeclaresStandard("NEP-11") && HasCompleteNep11AbiShape(manifest))
            return IsNep11StorageIntegerRead(manifest, method, state, storageGetOffset);

        return false;
    }

    private static bool IsNep17StorageIntegerRead(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        int storageGetOffset)
    {
        if (IsNep17BalanceOfMethod(method))
        {
            string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[0].Name, 0);
            return StorageReadMatchesAccountKeyAtOffset(state, accountSymbol, storageGetOffset);
        }

        if (!IsNep17TransferMethod(manifest, method))
            return false;

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        if (fromIndex < 0 || toIndex < 0)
            return false;

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        return StorageReadMatchesAccountKeyAtOffset(state, fromSymbol, storageGetOffset)
            || StorageReadMatchesAccountKeyAtOffset(state, toSymbol, storageGetOffset);
    }

    private static bool IsNep11StorageIntegerRead(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        int storageGetOffset)
    {
        if (IsNep11NonDivisibleBalanceOfMethod(method))
        {
            string ownerSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[0].Name, 0);
            return StorageReadMatchesAccountKeyAtOffset(state, ownerSymbol, storageGetOffset);
        }

        if (IsNep11DivisibleBalanceOfMethod(method))
        {
            string ownerSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[0].Name, 0);
            string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[1].Name, 1);
            return StorageReadMatchesAccountTokenKeyAtOffset(state, ownerSymbol, tokenIdSymbol, storageGetOffset);
        }

        if (IsNep11DivisibleTransferMethod(manifest, method))
        {
            int fromIndex = FindFromParameter(method);
            int toIndex = FindToParameter(method);
            int tokenIdIndex = FindNep11TokenIdParameter(method);
            if (fromIndex < 0 || toIndex < 0 || tokenIdIndex < 0)
                return false;

            string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
            string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
            string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
            return StorageReadMatchesAccountTokenKeyAtOffset(state, fromSymbol, tokenIdSymbol, storageGetOffset)
                || StorageReadMatchesAccountTokenKeyAtOffset(state, toSymbol, tokenIdSymbol, storageGetOffset);
        }

        if (IsNep11NonDivisibleTransferMethod(manifest, method))
        {
            int toIndex = FindToParameter(method);
            int tokenIdIndex = FindNep11TokenIdParameter(method);
            if (toIndex < 0 || tokenIdIndex < 0)
                return false;

            string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
            string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
            var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
            string? ownerSymbol = ownerRead is null ? null : StorageReadSymbolName(ownerRead.Op.Offset);
            return StorageReadMatchesAccountKeyAtOffset(state, toSymbol, storageGetOffset)
                || ownerSymbol is not null
                && StorageReadMatchesAccountKeyAtOffset(state, ownerSymbol, storageGetOffset);
        }

        return false;
    }

    private static bool ReturnMatchesTokenSupplyStorageRead(ExecutionState state, int storageGetOffset) =>
        state.Status == TerminalStatus.Halted
        && state.EvaluationStack.Count > 0
        && ReturnMatchesStorageReadOrMissingZero(state, state.Peek().Expression, storageGetOffset);

    private static bool StorageReadMatchesAccountKeyAtOffset(
        ExecutionState state,
        string accountSymbol,
        int storageGetOffset) =>
        state.Telemetry.StorageOps.Any(op =>
            op.Kind == StorageOpKind.Get
            && op.Offset == storageGetOffset
            && TryAccountStorageKeyPattern(state, op.Key, accountSymbol, out _));

    private static bool StorageReadMatchesAccountTokenKeyAtOffset(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        int storageGetOffset) =>
        state.Telemetry.StorageOps.Any(op =>
            op.Kind == StorageOpKind.Get
            && op.Offset == storageGetOffset
            && TryAccountTokenStorageKeyPattern(state, op.Key, accountSymbol, tokenIdSymbol, out _));

    private static bool UsesNepTokenStorageIntegerInvariant(
        ContractManifest manifest,
        ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-17")
            && HasCompleteNep17AbiShape(manifest)
            && (IsNep17TransferMethod(manifest, method)
                || IsNep17BalanceOfMethod(method)
                || IsTotalSupplyMethod(method))
        || manifest.DeclaresStandard("NEP-11")
            && HasCompleteNep11AbiShape(manifest)
            && (IsNep11NonDivisibleTransferMethod(manifest, method)
                || IsNep11DivisibleTransferMethod(manifest, method)
                || IsNep11NonDivisibleBalanceOfMethod(method)
                || IsNep11DivisibleBalanceOfMethod(method)
                || IsTotalSupplyMethod(method));

    private static bool HasCompleteNep17AbiShape(ContractManifest manifest) =>
        FindAbiMethod(manifest, "symbol", IsStringSafeNoParameterMethod) is not null
        && FindAbiMethod(manifest, "decimals", IsIntegerSafeNoParameterMethod) is not null
        && FindAbiMethod(manifest, "totalSupply", IsIntegerSafeNoParameterMethod) is not null
        && FindAbiMethod(manifest, "balanceOf", IsNep17BalanceOfMethod) is not null
        && FindAbiMethod(manifest, "transfer", IsNep17TransferMethodShape) is not null
        && HasNep17TransferEventShape(manifest);

    private static bool HasCompleteNep11AbiShape(ContractManifest manifest) =>
        FindAbiMethod(manifest, "symbol", IsStringSafeNoParameterMethod) is not null
        && FindAbiMethod(manifest, "decimals", IsIntegerSafeNoParameterMethod) is not null
        && FindAbiMethod(manifest, "totalSupply", IsIntegerSafeNoParameterMethod) is not null
        && FindAbiMethod(manifest, "tokensOf", IsNep11TokensOfMethod) is not null
        && OptionalNep11MethodValidWhenDeclared(manifest, "properties", IsNep11PropertiesMethod)
        && OptionalNep11MethodValidWhenDeclared(manifest, "tokens", IsNep11TokensMethod)
        && HasNep11TransferEventShape(manifest)
        && (HasCompleteNonDivisibleNep11Shape(manifest) || HasCompleteDivisibleNep11Shape(manifest));

    private static bool OptionalNep11MethodValidWhenDeclared(
        ContractManifest manifest,
        string name,
        Func<ContractMethodDescriptor, bool> predicate) =>
        FindAbiMethod(manifest, name) is null
        || FindAbiMethod(manifest, name, predicate) is not null;

    private static bool HasCompleteNonDivisibleNep11Shape(ContractManifest manifest) =>
        FindAbiMethod(manifest, "balanceOf", IsNep11NonDivisibleBalanceOfMethod) is not null
        && FindAbiMethod(manifest, "ownerOf", IsNep11NonDivisibleOwnerOfMethod) is not null
        && FindAbiMethod(manifest, "transfer", IsNep11NonDivisibleTransferMethodShape) is not null;

    private static bool HasCompleteDivisibleNep11Shape(ContractManifest manifest) =>
        FindAbiMethod(manifest, "balanceOf", IsNep11DivisibleBalanceOfMethod) is not null
        && FindAbiMethod(manifest, "ownerOf", IsNep11DivisibleOwnerOfMethod) is not null
        && FindAbiMethod(manifest, "transfer", IsNep11DivisibleTransferMethodShape) is not null;

    private static bool HasNep17TransferEventShape(ContractManifest manifest) =>
        manifest.Abi.Events.FirstOrDefault(e => string.Equals(e.Name, "Transfer", StringComparison.Ordinal)) is
        {
            Parameters.Count: 3,
        } transferEvent
        && HasStandardParameter(transferEvent.Parameters, 0, "from", IsStrictHash160)
        && HasStandardParameter(transferEvent.Parameters, 1, "to", IsStrictHash160)
        && HasStandardParameter(transferEvent.Parameters, 2, "amount", type => IsType(type, "Integer"));

    private static bool HasNep11TransferEventShape(ContractManifest manifest) =>
        manifest.Abi.Events.FirstOrDefault(e => string.Equals(e.Name, "Transfer", StringComparison.Ordinal)) is
        {
            Parameters.Count: 4,
        } transferEvent
        && HasStandardParameter(transferEvent.Parameters, 0, "from", IsStrictHash160)
        && HasStandardParameter(transferEvent.Parameters, 1, "to", IsStrictHash160)
        && HasStandardParameter(transferEvent.Parameters, 2, "amount", type => IsType(type, "Integer"))
        && HasStandardParameter(transferEvent.Parameters, 3, "tokenId", IsByteStringLike);

    private static bool TryGetStorageValueIntegerEncodingSize(
        FaultConditionOp op,
        out Expression sizeExpression,
        out int storageGetOffset)
    {
        sizeExpression = default!;
        storageGetOffset = 0;
        if (!string.Equals(op.Operation, "CONVERT Integer", StringComparison.Ordinal))
            return false;
        if (op.FaultCondition is not BinaryExpr
            {
                Op: ">",
                Left: UnaryExpr
                {
                    Sort: Sort.Int,
                    Op: "size",
                    Operand: Symbol { Sort: Sort.Bytes, Name: var storageValueName }
                } size,
                Right: IntConst { Value: var maxBytes }
            })
        {
            return false;
        }
        if (maxBytes != NeoVmIntegerMaxBytes
            || !storageValueName.StartsWith("storage_value_", StringComparison.Ordinal))
        {
            return false;
        }
        if (!TryParseStorageReadSymbolOffset(storageValueName, "storage_value_", out storageGetOffset))
            return false;

        sizeExpression = size;
        return true;
    }

    private static bool TryParseStorageReadSymbolOffset(
        string symbolName,
        string prefix,
        out int offset)
    {
        offset = 0;
        if (!symbolName.StartsWith(prefix, StringComparison.Ordinal))
            return false;

        int start = prefix.Length;
        int end = start;
        while (end < symbolName.Length && char.IsDigit(symbolName[end]))
            end++;

        return end > start
            && int.TryParse(symbolName.AsSpan(start, end - start), out offset);
    }

    private static bool IsExplicitProfileRejectionFault(ExecutionState state)
    {
        string? reason = state.TerminationReason;
        return reason is not null
            && (reason.StartsWith("ASSERT failed", StringComparison.Ordinal)
                || reason.StartsWith("ABORT", StringComparison.Ordinal));
    }

    private static IEnumerable<VerificationProperty> GenerateNeoN3ProfileProperties(
        ContractManifest manifest,
        ContractMethodDescriptor method)
    {
        bool isNep17 = IsNep17TransferMethod(manifest, method);
        bool isDivisibleNep11 = IsNep11DivisibleTransferMethod(manifest, method);
        if (!isNep17 && !isDivisibleNep11)
            yield break;

        int amountIndex = FindAmountParameter(method);
        if (amountIndex < 0)
            yield break;

        string arg = string.IsNullOrWhiteSpace(method.Parameters[amountIndex].Name)
            ? $"arg{amountIndex}"
            : method.Parameters[amountIndex].Name;
        yield return new VerificationProperty(
            Id: isNep17
                ? $"security.nep17.amount_non_negative.{method.Name}"
                : $"security.nep11.amount_non_negative.{method.Name}",
            Method: method.Name,
            Description: isNep17
                ? "NEP-17 transfer success paths must prove the transfer amount is non-negative."
                : "Divisible NEP-11 transfer success paths must prove the transfer amount is non-negative.",
            ForbidFaults: false,
            Requires: TrueReturnRequires(),
            Ensures: ImmutableArray.Create(new VerificationCondition(arg, ">=", BigInteger.Zero, null)),
            RequireExternalCallCompleteness: false);
    }

    private static ImmutableArray<VerificationCondition> TrueReturnRequires() =>
        ImmutableArray.Create(new VerificationCondition("$return", "==", null, true, IsReturn: true));

    private static ManifestCallPermissionEvaluation EvaluateManifestCallPermission(
        ContractManifest manifest,
        ExecutionState state,
        ExternalCall call)
    {
        if (call.MethodDynamic || string.IsNullOrWhiteSpace(call.Method) || call.Method == "<dynamic>")
        {
            return ManifestCallPermissionEvaluation.Incomplete(
                $"external call at 0x{call.Offset:X4} has dynamic or unknown method selector");
        }

        if (call.TargetHash?.AsConcreteBytes() is { } concreteTargetHash
            && concreteTargetHash.Length != Hash160ByteLength)
        {
            return ManifestCallPermissionEvaluation.Denied(
                $"external call at 0x{call.Offset:X4} target hash has {concreteTargetHash.Length} bytes, expected UInt160");
        }

        if (!TryResolveExternalCallTargetHash(state, call, out byte[] targetHash))
        {
            if (HasAllowedStandardCallbackWildcardPermission(manifest, call.Method))
                return ManifestCallPermissionEvaluation.Allowed();

            return ManifestCallPermissionEvaluation.Incomplete(
                $"external call at 0x{call.Offset:X4} has dynamic or unknown target hash");
        }

        bool sawGroupPermission = false;
        foreach (var permission in manifest.Permissions)
        {
            if (!PermissionMethodAllows(permission, call.Method))
                continue;

            var contractMatch = PermissionContractMatches(permission.Contract, targetHash);
            if (contractMatch == ManifestContractMatch.Allowed)
                return ManifestCallPermissionEvaluation.Allowed();
            if (contractMatch == ManifestContractMatch.GroupMembershipUnknown)
                sawGroupPermission = true;
        }

        string target = NativeContractDisplay(targetHash) ?? FormatHash(targetHash);
        if (sawGroupPermission)
        {
            return ManifestCallPermissionEvaluation.Incomplete(
                $"external call {target}.{call.Method} at 0x{call.Offset:X4} is allowed only through a group permission; target group membership is not modeled");
        }

        return ManifestCallPermissionEvaluation.Denied(
            $"external call {target}.{call.Method} at 0x{call.Offset:X4} is not covered by manifest.permissions");
    }

    private static bool PermissionMethodAllows(ContractPermission permission, string method) =>
        permission.Methods.IsWildcard
        || permission.Methods.Items.Any(m => string.Equals(m, method, StringComparison.Ordinal));

    private static bool IsModeledKnownNativeCall(ExternalCall call) =>
        call.ReturnModeledNative
        && NeoNativeContractHashes.IsKnownNativeContractHash(call.TargetHash?.AsConcreteBytes())
        && !IsSensitiveModeledNativeCall(call);

    private static bool IsSensitiveModeledNativeCall(ExternalCall call) =>
        IsNativeTokenTransferCall(call);

    private static string? SensitiveModeledNativeCallCompletenessReason(ExternalCall call)
    {
        if (IsNativeTokenTransferCall(call))
        {
            return $"{ExternalCallDisplay(call)} at 0x{call.Offset:X4} models flags, argument preconditions, Boolean return shape, and success-path Transfer notification payload, but native token balance changes and receiver callback side effects are not yet proof-grade modeled";
        }

        return null;
    }

    private static bool IsNativeTokenTransferCall(ExternalCall call)
    {
        if (!string.Equals(call.Method, "transfer", StringComparison.Ordinal))
            return false;

        return call.TargetHash?.AsConcreteBytes() is { } targetHash
            && (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.NeoToken))
                || BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.GasToken)));
    }

    private static string ExternalCallDisplay(ExternalCall call)
    {
        string method = string.IsNullOrWhiteSpace(call.Method) ? "<dynamic>" : call.Method;
        if (call.TargetHash?.AsConcreteBytes() is { } targetHash
            && NativeContractDisplay(targetHash) is { } native)
        {
            return $"{native}.{method}";
        }

        return method;
    }

    private static string? NativeContractDisplay(byte[] targetHash)
    {
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.NeoToken)))
            return "NEO";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.GasToken)))
            return "GAS";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.ContractManagement)))
            return "ContractManagement";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.OracleContract)))
            return "Oracle";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.LedgerContract)))
            return "Ledger";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.PolicyContract)))
            return "Policy";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.RoleManagement)))
            return "RoleManagement";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.StdLib)))
            return "StdLib";
        if (BytesEqual(targetHash, NeoNativeContractHashes.FromHex(NeoNativeContractHashes.CryptoLib)))
            return "CryptoLib";

        return null;
    }

    private static bool HasAllowedStandardCallbackWildcardPermission(ContractManifest manifest, string method) =>
        manifest.Permissions.Any(p =>
            IsAllowedStandardCallbackWildcardPermission(manifest, p)
            && PermissionMethodAllows(p, method));

    private static bool IsAllowedStandardCallbackWildcardPermission(
        ContractManifest manifest,
        ContractPermission permission)
    {
        if (permission.Contract != "*" || permission.Methods.IsWildcard || permission.Methods.Items.Count == 0)
            return false;

        var allowedMethods = new HashSet<string>(StringComparer.Ordinal);
        if (ManifestHasCompleteNep17CallbackStandard(manifest))
            allowedMethods.Add("onNEP17Payment");
        if (ManifestHasCompleteNep11CallbackStandard(manifest))
            allowedMethods.Add("onNEP11Payment");

        return allowedMethods.Count > 0
            && permission.Methods.Items.All(allowedMethods.Contains);
    }

    private static bool ManifestHasCompleteNep17CallbackStandard(ContractManifest manifest) =>
        manifest.DeclaresStandard("NEP-17")
        && HasCompleteNep17AbiShape(manifest);

    private static bool ManifestHasCompleteNep11CallbackStandard(ContractManifest manifest) =>
        manifest.DeclaresStandard("NEP-11")
        && HasCompleteNep11AbiShape(manifest);

    private static ManifestContractMatch PermissionContractMatches(string descriptor, byte[] targetHash)
    {
        if (descriptor == "*")
            return ManifestContractMatch.Allowed;

        if (TryParseHexDescriptor(descriptor, out var bytes))
        {
            if (bytes.Length == 20)
            {
                return BytesEqual(bytes, targetHash)
                    ? ManifestContractMatch.Allowed
                    : ManifestContractMatch.Denied;
            }

            if (bytes.Length is 33 or 65 && NeoEcPoint.IsValidEncoding(bytes))
                return ManifestContractMatch.GroupMembershipUnknown;
        }

        return ManifestContractMatch.Denied;
    }

    private static bool IsValidManifestPermissionContract(string descriptor)
    {
        if (descriptor == "*")
            return true;

        if (!TryParseHexDescriptor(descriptor, out var bytes))
            return false;

        return bytes.Length == 20
            || (bytes.Length is 33 or 65 && NeoEcPoint.IsValidEncoding(bytes));
    }

    private static bool IsValidManifestGroupPublicKey(string descriptor)
    {
        if (!TryParseManifestGroupPublicKey(descriptor, out var bytes))
            return false;

        return NeoEcPoint.IsValidEncoding(bytes);
    }

    private static bool IsValidManifestGroupSignature(string descriptor) =>
        TryParseManifestGroupSignature(descriptor, out _);

    private static bool TryParseManifestGroupPublicKey(string descriptor, out byte[] bytes) =>
        TryParseHexDescriptor(descriptor, out bytes);

    private static bool TryParseManifestGroupSignature(string descriptor, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        if (string.IsNullOrWhiteSpace(descriptor))
            return false;

        if (TryParseHexDescriptor(descriptor, out var hexBytes))
        {
            if (hexBytes.Length != SignatureByteLength)
                return false;
            bytes = hexBytes;
            return true;
        }

        try
        {
            var decoded = Convert.FromBase64String(descriptor);
            if (decoded.Length != SignatureByteLength)
                return false;
            bytes = decoded;
            return true;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static bool VerifyManifestGroupSignature(
        string publicKeyDescriptor,
        string signatureDescriptor,
        byte[] contractHash)
    {
        if (!TryParseManifestGroupPublicKey(publicKeyDescriptor, out var publicKey)
            || !TryParseManifestGroupSignature(signatureDescriptor, out var signature))
        {
            return false;
        }

        try
        {
            var curve = Org.BouncyCastle.Asn1.Sec.SecNamedCurves.GetByName("secp256r1");
            if (curve is null)
                return false;

            var domain = new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(
                curve.Curve,
                curve.G,
                curve.N,
                curve.H,
                curve.GetSeed());
            var point = curve.Curve.DecodePoint(publicKey);
            if (point.IsInfinity)
                return false;

            var publicKeyParameters = new Org.BouncyCastle.Crypto.Parameters.ECPublicKeyParameters(point, domain);
            var verifier = new Org.BouncyCastle.Crypto.Signers.ECDsaSigner();
            verifier.Init(false, publicKeyParameters);
            byte[] digest = System.Security.Cryptography.SHA256.HashData(contractHash);
            var r = new Org.BouncyCastle.Math.BigInteger(1, signature.AsSpan(0, 32).ToArray());
            var s = new Org.BouncyCastle.Math.BigInteger(1, signature.AsSpan(32, 32).ToArray());
            return verifier.VerifySignature(digest, r, s);
        }
        catch (Exception ex) when (ex is ArgumentException
            or FormatException
            or InvalidOperationException
            or ArithmeticException)
        {
            return false;
        }
    }

    private static bool TryParseHexDescriptor(string descriptor, out byte[] bytes)
    {
        string hex = descriptor.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? descriptor[2..]
            : descriptor;

        if (hex.Length == 0 || hex.Length % 2 != 0)
        {
            bytes = Array.Empty<byte>();
            return false;
        }

        try
        {
            bytes = Convert.FromHexString(hex);
            return true;
        }
        catch (FormatException)
        {
            bytes = Array.Empty<byte>();
            return false;
        }
    }

    private static bool IsAuthorizedNep17RecipientBalanceCredit(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        SensitiveOperation operation)
    {
        if (!IsNep17TransferMethod(manifest, method))
            return false;

        var mutation = state.Telemetry.StorageOps.FirstOrDefault(op =>
            op.Offset == operation.Offset
            && op.Kind == StorageOpKind.Put);
        if (mutation is null)
            return false;

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0)
            return false;

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        if (!HasNep17SenderAuthorizationBefore(state, fromSymbol, operation.Offset))
            return false;
        if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            return false;

        var fromGet = FindStorageGetByAccountKey(state, fromSymbol);
        var toGet = FindStorageGetByAccountKey(state, toSymbol);
        var fromPut = fromGet is null ? null : FindStoragePutByAccountKey(state, fromSymbol, fromGet.Pattern, fromGet.Op.Offset);
        var toPut = toGet is null ? null : FindStoragePutByAccountKey(state, toSymbol, toGet.Pattern, toGet.Op.Offset);
        if (fromGet is null || toGet is null || fromPut is null || toPut is null)
            return false;
        if (mutation.Offset != toPut.Op.Offset)
            return false;
        if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            return false;
        if (!PathConditionsProveStorageReadAtLeastAmount(state.PathConditions, fromGet.Op.Offset, amountSymbol))
            return false;
        if (!ValueMatchesBalanceDelta(fromPut.Op.Value?.Expression, state, fromGet.Op.Offset, amountSymbol, subtract: true))
            return false;
        if (!ValueMatchesBalanceDelta(toPut.Op.Value?.Expression, state, toGet.Op.Offset, amountSymbol, subtract: false))
            return false;
        if (FindLaterStorageMutationByAccountKey(state, fromSymbol, fromGet.Pattern, fromPut.Op.Offset) is not null)
            return false;
        if (FindLaterStorageMutationByAccountKey(state, toSymbol, toGet.Pattern, toPut.Op.Offset) is not null)
            return false;

        return true;
    }

    private static bool IsAuthorizedNep11DivisibleBalanceMutation(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        SensitiveOperation operation)
    {
        if (!IsNep11DivisibleTransferMethod(manifest, method))
            return false;

        var mutation = state.Telemetry.StorageOps.FirstOrDefault(op =>
            op.Offset == operation.Offset
            && op.Kind == StorageOpKind.Put);
        if (mutation is null)
            return false;

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0 || tokenIdIndex < 0)
            return false;

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        if (!HasNep17SenderAuthorizationBefore(state, fromSymbol, operation.Offset))
            return false;
        if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            return false;

        var fromGet = FindStorageGetByAccountTokenKey(state, fromSymbol, tokenIdSymbol);
        var toGet = FindStorageGetByAccountTokenKey(state, toSymbol, tokenIdSymbol);
        var fromPut = fromGet is null ? null : FindStoragePutByAccountTokenKey(state, fromSymbol, tokenIdSymbol, fromGet.Pattern, fromGet.Op.Offset);
        var toPut = toGet is null ? null : FindStoragePutByAccountTokenKey(state, toSymbol, tokenIdSymbol, toGet.Pattern, toGet.Op.Offset);
        if (fromGet is null || toGet is null || fromPut is null || toPut is null)
            return false;
        if (mutation.Offset != fromPut.Op.Offset && mutation.Offset != toPut.Op.Offset)
            return false;
        if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            return false;
        if (!PathConditionsProveStorageReadAtLeastAmount(state.PathConditions, fromGet.Op.Offset, amountSymbol))
            return false;
        if (!ValueMatchesBalanceDelta(fromPut.Op.Value?.Expression, state, fromGet.Op.Offset, amountSymbol, subtract: true))
            return false;
        if (!ValueMatchesBalanceDelta(toPut.Op.Value?.Expression, state, toGet.Op.Offset, amountSymbol, subtract: false))
            return false;
        if (FindLaterStorageMutationByAccountTokenKey(state, fromSymbol, tokenIdSymbol, fromGet.Pattern, fromPut.Op.Offset) is not null)
            return false;
        if (FindLaterStorageMutationByAccountTokenKey(state, toSymbol, tokenIdSymbol, toGet.Pattern, toPut.Op.Offset) is not null)
            return false;

        return true;
    }

    private static bool IsAuthorizedNep11OwnerTransfer(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        SensitiveOperation operation)
    {
        if (!IsNep11TransferMethod(manifest, method))
            return false;

        var mutation = state.Telemetry.StorageOps.FirstOrDefault(op =>
            op.Offset == operation.Offset
            && op.Kind == StorageOpKind.Put);
        if (mutation is null)
            return false;

        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (toIndex < 0 || tokenIdIndex < 0)
            return false;

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
        if (ownerRead is null)
            return false;
        var ownerPut = FindStoragePutByAccountKey(state, tokenIdSymbol, ownerRead.Pattern, ownerRead.Op.Offset);
        if (ownerPut is null || mutation.Offset != ownerPut.Op.Offset)
            return false;
        if (ownerPut.Op.Value is null || !IsSymbol(ownerPut.Op.Value.Expression, toSymbol))
            return false;
        if (!HasOwnerReadAuthorizationBefore(state, ownerRead.Op.Offset, mutation.Offset))
            return false;

        return true;
    }

    private static bool IsAuthorizedNep11OwnerBalanceMutation(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        SensitiveOperation operation)
    {
        if (!IsNep11NonDivisibleTransferMethod(manifest, method))
            return false;

        var mutation = state.Telemetry.StorageOps.FirstOrDefault(op =>
            op.Offset == operation.Offset
            && op.Kind == StorageOpKind.Put);
        if (mutation is null)
            return false;

        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (toIndex < 0 || tokenIdIndex < 0)
            return false;

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
        if (ownerRead is null)
            return false;

        string ownerSymbol = StorageReadSymbolName(ownerRead.Op.Offset);
        if (!HasOwnerReadAuthorizationBefore(state, ownerRead.Op.Offset, mutation.Offset))
            return false;
        if (!PathConditionsExcludeSymbolEquality(state.PathConditions, ownerSymbol, toSymbol))
            return false;

        var fromGet = FindStorageGetByAccountKey(state, ownerSymbol);
        var toGet = FindStorageGetByAccountKey(state, toSymbol);
        var fromPut = fromGet is null ? null : FindStoragePutByAccountKey(state, ownerSymbol, fromGet.Pattern, fromGet.Op.Offset);
        var toPut = toGet is null ? null : FindStoragePutByAccountKey(state, toSymbol, toGet.Pattern, toGet.Op.Offset);
        if (fromGet is null || toGet is null || fromPut is null || toPut is null)
            return false;
        if (mutation.Offset != fromPut.Op.Offset && mutation.Offset != toPut.Op.Offset)
            return false;
        if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            return false;
        if (!PathConditionsProveStorageReadAtLeastAmount(state.PathConditions, fromGet.Op.Offset, Expr.Int(1)))
            return false;
        if (!ValueMatchesBalanceDelta(fromPut.Op.Value?.Expression, state, fromGet.Op.Offset, Expr.Int(1), subtract: true))
            return false;
        if (!ValueMatchesBalanceDelta(toPut.Op.Value?.Expression, state, toGet.Op.Offset, Expr.Int(1), subtract: false))
            return false;
        if (FindLaterStorageMutationByAccountKey(state, ownerSymbol, fromGet.Pattern, fromPut.Op.Offset) is not null)
            return false;
        if (FindLaterStorageMutationByAccountKey(state, toSymbol, toGet.Pattern, toPut.Op.Offset) is not null)
            return false;

        return true;
    }

    private static bool BytesEqual(byte[] left, byte[] right) =>
        left.AsSpan().SequenceEqual(right);

    private static string FormatHash(byte[] hash) =>
        "0x" + Convert.ToHexString(hash).ToLowerInvariant();

    private static VerificationPropertyResult? BuildIncompleteResult(
        string id,
        string method,
        string description,
        ExecutionResult execution,
        int obligations)
    {
        var reasons = IncompleteReasons(execution).ToList();
        if (reasons.Count == 0) return null;
        var counts = CountPaths(execution);
        return new VerificationPropertyResult(
            id,
            method,
            description,
            VerificationStatus.Incomplete,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            string.Join("; ", reasons.Distinct(StringComparer.Ordinal)),
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult? BuildNoSuccessfulHaltIncompleteResult(
        string id,
        string method,
        string description,
        ExecutionResult execution,
        int obligations,
        ImmutableArray<VerificationAssumption> assumptions = default)
    {
        var counts = CountPaths(execution);
        if (counts.CheckedPaths > 0) return null;

        string reason = execution.FinalStates.Length == 0
            ? "entrypoint produced no terminal states"
            : $"entrypoint reached no successful HALT paths (faulted={counts.IgnoredFaultedPaths}, stopped={counts.StoppedPaths})";
        return new VerificationPropertyResult(
            id,
            method,
            description,
            VerificationStatus.Incomplete,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            reason,
            FailedCondition: null,
            Counterexample: null,
            Assumptions: assumptions);
    }

    private static IEnumerable<string> IncompleteReasons(ExecutionResult execution)
    {
        foreach (var state in execution.Stopped)
            yield return state.TerminationReason ?? "stopped before verification reached a terminal verdict";
        foreach (var state in execution.FinalStates)
        {
            if (state.Telemetry.UnknownOpcodes.Count > 0)
                yield return "unknown opcode at " + string.Join(", ", state.Telemetry.UnknownOpcodes.Select(FormatOffset));
            if (state.Telemetry.UnknownSyscalls.Count > 0)
                yield return "unknown syscall at " + string.Join(", ", state.Telemetry.UnknownSyscalls.Select(FormatOffset));
            if (state.Telemetry.Truncated)
                yield return "state telemetry was truncated";
        }
        int concretizations = execution.FinalStates.Sum(s => s.Telemetry.SmtConcretizations);
        if (concretizations > 0)
            yield return "SMT concretized symbolic runtime operand(s); proof under-approximates unenumerated feasible values";
        if (execution.CoverageIncomplete && !string.IsNullOrWhiteSpace(execution.CoverageReason))
            yield return execution.CoverageReason;
        if (execution.BudgetExceeded && !string.IsNullOrWhiteSpace(execution.BudgetReason))
            yield return "budget: " + execution.BudgetReason;
    }

    private static IEnumerable<string> ExecutionSurfaceIncompleteReasons(ExecutionResult execution)
    {
        foreach (var state in execution.Stopped)
            yield return state.TerminationReason ?? "stopped before verification reached a terminal verdict";
        foreach (var state in execution.FinalStates)
        {
            if (state.Telemetry.UnknownOpcodes.Count > 0)
                yield return "unknown opcode at " + string.Join(", ", state.Telemetry.UnknownOpcodes.Select(FormatOffset));
            if (state.Telemetry.UnknownSyscalls.Count > 0)
                yield return "unknown syscall at " + string.Join(", ", state.Telemetry.UnknownSyscalls.Select(FormatOffset));
            if (state.Telemetry.ExternalCalls.Any(IsRuntimeLoadScriptCall))
                yield return string.Join(
                    "; ",
                    state.Telemetry.ExternalCalls
                        .Where(IsRuntimeLoadScriptCall)
                        .OrderBy(call => call.Offset)
                        .Select(RuntimeLoadScriptCompletenessReason)
                        .Distinct(StringComparer.Ordinal));
            if (state.Telemetry.Truncated)
                yield return "state telemetry was truncated";
        }
        int concretizations = execution.FinalStates.Sum(s => s.Telemetry.SmtConcretizations);
        if (concretizations > 0)
            yield return "SMT concretized symbolic runtime operand(s); proof under-approximates unenumerated feasible values";
        if (execution.BudgetExceeded && !string.IsNullOrWhiteSpace(execution.BudgetReason))
            yield return "budget: " + execution.BudgetReason;
    }

    private static void AddTransferExecutionSurfaceIncompleteReasons(
        ExecutionResult execution,
        List<string> incompleteReasons)
    {
        foreach (var reason in ExecutionSurfaceIncompleteReasons(execution))
            incompleteReasons.Add("transfer(): " + reason);
    }

    private static IEnumerable<SensitiveOperation> SensitiveOperations(ExecutionState state)
    {
        foreach (var op in state.Telemetry.StorageOps)
        {
            if (op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                yield return new SensitiveOperation(
                    op.Offset,
                    "state mutation",
                    op.Kind == StorageOpKind.Put ? "Storage.Put" : "Storage.Delete",
                    op.Value is null
                        ? ImmutableArray.Create(op.Key.Expression)
                        : ImmutableArray.Create(op.Key.Expression, op.Value.Expression));
        }

        foreach (var call in state.Telemetry.ExternalCalls)
        {
            if (call.ModeledSelfCall || IsModeledKnownNativeCall(call))
                continue;

            string target = ExternalCallDisplay(call);
            var related = ImmutableArray.CreateBuilder<Expression>();
            if (call.TargetHash is not null)
                related.Add(call.TargetHash.Expression);
            if (call.MethodArg is not null)
                related.Add(call.MethodArg.Expression);
            related.AddRange(call.Args.Select(a => a.Expression));
            yield return new SensitiveOperation(
                call.Offset,
                "external call",
                $"external call {target}",
                related.ToImmutable());
        }
    }

    private static int FirstSensitiveOperationOffset(ExecutionState state) =>
        SensitiveOperations(state)
            .OrderBy(op => op.Offset)
            .Select(op => op.Offset)
            .DefaultIfEmpty(int.MaxValue)
            .First();

    private static AccessControlAuthStatus EvaluateAccessControlAuthBefore(
        ExecutionState state,
        SensitiveOperation operation)
    {
        bool unrelatedDynamicWitness = false;
        bool unboundSignatureMessage = false;
        foreach (var witness in state.Telemetry.WitnessCheckOps.Where(w =>
                     w.Offset < operation.Offset
                     && state.Telemetry.IsWitnessCheckResultEnforced(w)))
        {
            if (AuthorizationPrincipalMatchesOperation(witness.Target.Expression, operation, state))
                return AccessControlAuthStatus.Authorized;
            unrelatedDynamicWitness = true;
        }

        bool hasCallerHashBinding = false;
        foreach (var caller in state.Telemetry.CallerHashCheckOps.Where(c => c.Offset < operation.Offset))
        {
            hasCallerHashBinding = true;
            if (CallerHashPrincipalMatchesOperation(caller.Target.Expression, operation, state))
                return AccessControlAuthStatus.Authorized;
            unrelatedDynamicWitness = true;
        }

        foreach (var signature in state.Telemetry.SignatureCheckOps.Where(s =>
                     s.Offset < operation.Offset
                     && state.Telemetry.IsSignatureCheckResultEnforced(s)))
        {
            if (SignaturePrincipalMatchesOperation(signature.PublicKeyOrKeys.Expression, operation, state))
            {
                if (SignatureMessageBindsOperation(signature, operation))
                    return AccessControlAuthStatus.Authorized;
                unboundSignatureMessage = true;
            }
            else
            {
                unrelatedDynamicWitness = true;
            }
        }

        if (!hasCallerHashBinding && state.Telemetry.CallerHashChecks.Any(o => o < operation.Offset))
            return AccessControlAuthStatus.Authorized;

        if (unboundSignatureMessage)
            return AccessControlAuthStatus.UnboundSignatureMessage;
        return unrelatedDynamicWitness
            ? AccessControlAuthStatus.UnrelatedDynamicWitness
            : AccessControlAuthStatus.Missing;
    }

    private static bool AuthorizationPrincipalMatchesOperation(
        Expression principal,
        SensitiveOperation operation,
        ExecutionState state)
    {
        if (IsStableWitnessPrincipal(principal))
            return true;

        if (IsStableDerivedAccountPrincipal(principal, state))
            return true;

        var principalSymbols = principal.FreeSymbols().ToImmutableHashSet(StringComparer.Ordinal);
        if (principalSymbols.Count == 0)
            return false;

        return operation.RelatedExpressions
            .SelectMany(e => e.FreeSymbols())
            .Any(principalSymbols.Contains);
    }

    private static bool CallerHashPrincipalMatchesOperation(
        Expression principal,
        SensitiveOperation operation,
        ExecutionState state)
    {
        if (IsStableSelfCallerPrincipal(principal))
            return true;

        return AuthorizationPrincipalMatchesOperation(principal, operation, state);
    }

    private static bool SignaturePrincipalMatchesOperation(
        Expression principal,
        SensitiveOperation operation,
        ExecutionState state)
    {
        if (IsStableSignaturePrincipal(principal))
            return true;

        if (IsStableSignaturePrincipalArray(principal, state))
            return true;

        return AuthorizationPrincipalMatchesOperation(principal, operation, state);
    }

    private static bool SignatureMessageBindsOperation(
        SignatureCheckOp signature,
        SensitiveOperation operation)
    {
        if (signature.Message is null)
            return true;

        var messageSymbols = signature.Message.Expression.FreeSymbols().ToImmutableHashSet(StringComparer.Ordinal);
        if (messageSymbols.Count == 0)
            return false;

        return operation.RelatedExpressions
            .SelectMany(e => e.FreeSymbols())
            .Any(messageSymbols.Contains);
    }

    private static bool IsStableWitnessPrincipal(Expression principal)
    {
        if (principal is not BytesConst { Value: var bytes })
            return false;

        return bytes.Length == Hash160ByteLength
            || bytes.Length == CompressedPublicKeyByteLength && NeoEcPoint.IsValidEncoding(bytes);
    }

    private static bool IsStableSignaturePrincipal(Expression principal) =>
        principal is BytesConst { Value: var bytes }
        && (bytes.Length == Ed25519PublicKeyByteLength || NeoEcPoint.IsValidEncoding(bytes));

    private static bool IsStableSignaturePrincipalArray(Expression principal, ExecutionState state)
    {
        if (principal is not HeapRef { RefSort: Sort.Array } publicKeysRef
            || state.Heap.Get(publicKeysRef.ObjectId) is not ArrayObject publicKeys
            || publicKeys.IsSymbolicOpen
            || publicKeys.Items.Count == 0)
        {
            return false;
        }

        return publicKeys.Items.All(item => IsStableSignaturePrincipal(item.Expression));
    }

    private static bool IsStableSelfCallerPrincipal(Expression principal) =>
        principal is Symbol { Sort: Sort.Bytes, Name: "executing_script_hash" };

    private static bool IsStableDerivedAccountPrincipal(Expression principal, ExecutionState state) =>
        principal switch
        {
            UnaryExpr { Sort: Sort.Bytes, Op: "standard_account", Operand: var publicKey } =>
                IsStableSignaturePrincipal(publicKey),
            BinaryExpr { Sort: Sort.Bytes, Op: "multisig_account", Left: var threshold, Right: var publicKeys } =>
                IsStableMultisigAccountPrincipal(threshold, publicKeys, state),
            _ => false,
        };

    private static bool IsStableMultisigAccountPrincipal(
        Expression threshold,
        Expression publicKeysExpression,
        ExecutionState state)
    {
        if (Expr.ConcreteInt(threshold) is not { } thresholdValue
            || thresholdValue < 1
            || !IsStableSignaturePrincipalArray(publicKeysExpression, state)
            || publicKeysExpression is not HeapRef { RefSort: Sort.Array } publicKeysRef
            || state.Heap.Get(publicKeysRef.ObjectId) is not ArrayObject publicKeys
            || thresholdValue > publicKeys.Items.Count)
        {
            return false;
        }

        return true;
    }

    private static bool HasEnforcedWitnessForSymbolBefore(
        ExecutionState state,
        string symbolName,
        int offset) =>
        state.Telemetry.WitnessCheckOps.Any(w =>
            w.Offset < offset
            && state.Telemetry.IsWitnessCheckResultEnforced(w)
            && IsSymbol(w.Target.Expression, symbolName));

    private static bool HasNep17SenderAuthorizationBefore(
        ExecutionState state,
        string fromSymbol,
        int offset) =>
        HasEnforcedWitnessForSymbolBefore(state, fromSymbol, offset)
        || state.Telemetry.CallerHashCheckOps.Any(c =>
            c.Offset < offset
            && IsSymbol(c.Target.Expression, fromSymbol));

    private static bool HasOwnerReadAuthorizationBefore(
        ExecutionState state,
        int ownerReadOffset,
        int beforeOffset) =>
        state.Telemetry.WitnessCheckOps.Any(w =>
            w.Offset > ownerReadOffset
            && w.Offset < beforeOffset
            && state.Telemetry.IsWitnessCheckResultEnforced(w)
            && IsStorageReadExpression(w.Target.Expression, ownerReadOffset))
        || state.Telemetry.CallerHashCheckOps.Any(c =>
            c.Offset > ownerReadOffset
            && c.Offset < beforeOffset
            && IsStorageReadExpression(c.Target.Expression, ownerReadOffset));

    private static bool HasEnforcedWitnessForSymbol(ExecutionState state, string symbolName) =>
        state.Telemetry.WitnessCheckOps.Any(w =>
            state.Telemetry.IsWitnessCheckResultEnforced(w)
            && IsSymbol(w.Target.Expression, symbolName));

    private static bool IsSymbol(Expression expression, string symbolName) =>
        expression is Symbol { Name: var name } && string.Equals(name, symbolName, StringComparison.Ordinal);

    private static bool IsMethodArgumentValue(SymbolicValue value, string symbolName)
    {
        if (IsSymbol(value.Expression, symbolName))
            return true;
        if (!value.Taints.Contains(symbolName))
            return false;

        // Method-entry Any coverage materializes non-symbol representatives as tainted
        // null/heap values. Do not accept arbitrary derived tainted expressions such as
        // arg_data + 1 as an exact callback/event payload match.
        return value.Expression is NullConst or HeapRef;
    }

    private static bool HasReceiverContractAbsenceProof(
        ExecutionState state,
        ContractMethodDescriptor method)
    {
        int toIndex = FindToParameter(method);
        if (toIndex < 0)
            return false;

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        return state.Telemetry.ContractExistenceQueries.Any(q =>
            !q.Exists
            && IsMethodArgumentValue(q.Target, toSymbol));
    }

    private static bool IsFullHash160AccountKeyExpression(Expression expression, string accountSymbol)
    {
        if (IsSymbol(expression, accountSymbol))
            return true;

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "left" or "right" } side
            && IsSymbol(side.Left, accountSymbol)
            && Expr.ConcreteInt(side.Right) is { } sideLength
            && sideLength == 20)
        {
            return true;
        }

        return expression is TernaryExpr { Sort: Sort.Bytes, Op: "substr" } substr
            && IsSymbol(substr.A, accountSymbol)
            && Expr.ConcreteInt(substr.B) is { IsZero: true }
            && Expr.ConcreteInt(substr.C) is { } substrLength
            && substrLength == 20;
    }

    private static Symbol AccountKeyPlaceholder() =>
        Expr.Sym(Sort.Bytes, "$account");

    private static Symbol TokenIdKeyPlaceholder() =>
        Expr.Sym(Sort.Bytes, "$tokenId");

    private static BinaryExpr ByteCat(Expression left, Expression right) =>
        new(Sort.Bytes, "cat", left, right);

    private static bool ValueMatchesBalanceDelta(
        Expression? value,
        int storageGetOffset,
        string amountSymbol,
        bool subtract) =>
        ValueMatchesBalanceDelta(value, state: null, storageGetOffset, amount => IsAmountExpression(amount, amountSymbol), subtract);

    private static bool ValueMatchesBalanceDelta(
        Expression? value,
        ExecutionState state,
        int storageGetOffset,
        string amountSymbol,
        bool subtract) =>
        ValueMatchesBalanceDelta(value, state, storageGetOffset, amount => IsAmountExpression(amount, amountSymbol), subtract);

    private static bool ValueMatchesBalanceDelta(
        Expression? value,
        int storageGetOffset,
        Expression amountExpression,
        bool subtract) =>
        ValueMatchesBalanceDelta(value, state: null, storageGetOffset, amount => amount.Equals(amountExpression), subtract);

    private static bool ValueMatchesBalanceDelta(
        Expression? value,
        ExecutionState state,
        int storageGetOffset,
        Expression amountExpression,
        bool subtract) =>
        ValueMatchesBalanceDelta(value, state, storageGetOffset, amount => amount.Equals(amountExpression), subtract);

    // Recognizes a balance write that equals `prior - amount` (debit) or `prior + amount` (credit),
    // where `prior` is the storage read at <paramref name="storageGetOffset"/> (or a proven-missing zero).
    //
    // SCOPE: this is a SYNTACTIC AST matcher, not an SMT equivalence check. It relies on the engine's
    // constant-folding (Expr.Add/Sub/Mul fold x+0->x, 0+x->x, x-0->x, x*1->x), so identity-wrapped
    // codegen such as `prior - (amount + 0)` or `prior + amount*1` reaches this method already in
    // canonical form. The credit case also accepts the commuted `amount + prior`. Real neo-devpack-dotnet
    // transfer codegen emits the canonical SUB/ADD shapes this recognizes.
    //
    // SOUNDNESS: the matcher is false-NEGATIVE-safe by construction — it returns true ONLY for a write it
    // can prove equals the correct delta, so a genuine wrong-delta write (e.g. a missing or inverted
    // debit) never matches and the obligation correctly reports Violated. It therefore never discharges
    // an incorrect delta, i.e. it cannot produce a false "proved". The residual is a false-POSITIVE risk:
    // a *correct* delta written in a non-canonical AST that survives folding (e.g. `prior + (0 - amount)`)
    // would not match and would be reported Violated. That shape is not produced by canonical codegen; if
    // it becomes a real-world concern, the principled fix is an SMT equivalence discharge (assert the write
    // != prior ∓ amount and require UNSAT) — deliberately NOT a route-to-Incomplete, which would regress
    // genuine wrong-delta detection.
    private static bool ValueMatchesBalanceDelta(
        Expression? value,
        ExecutionState? state,
        int storageGetOffset,
        Func<Expression, bool> amountMatches,
        bool subtract)
    {
        if (!subtract
            && state is not null
            && PathConditionsProveStorageReadMissing(state.PathConditions, storageGetOffset)
            && value is not null
            && amountMatches(value))
        {
            return true;
        }

        if (value is not BinaryExpr binary)
            return false;

        if (subtract)
        {
            return binary.Op == "-"
                && IsStorageReadOrMissingZeroExpression(binary.Left, state, storageGetOffset)
                && amountMatches(binary.Right);
        }

        return binary.Op == "+"
            && (IsStorageReadOrMissingZeroExpression(binary.Left, state, storageGetOffset)
                && amountMatches(binary.Right)
                || amountMatches(binary.Left)
                && IsStorageReadOrMissingZeroExpression(binary.Right, state, storageGetOffset));
    }

    private static string StorageReadSymbolName(int storageGetOffset) =>
        $"storage_value_{storageGetOffset}";

    private static bool IsStorageReadExpression(Expression expression, int storageGetOffset)
    {
        string symbolName = StorageReadSymbolName(storageGetOffset);
        return IsSymbol(expression, symbolName)
            || expression is UnaryExpr
            {
                Op: "b2i",
                Operand: Symbol { Name: var name }
            } && string.Equals(name, symbolName, StringComparison.Ordinal);
    }

    private static bool IsStorageReadOrMissingZeroExpression(
        Expression expression,
        ExecutionState? state,
        int storageGetOffset) =>
        IsStorageReadExpression(expression, storageGetOffset)
        || state is not null
        && Expr.ConcreteInt(expression) is { IsZero: true }
        && PathConditionsProveStorageReadMissing(state.PathConditions, storageGetOffset);

    private static bool ReturnMatchesStorageReadOrMissingZero(
        ExecutionState state,
        Expression returnValue,
        int storageGetOffset) =>
        IsStorageReadExpression(returnValue, storageGetOffset)
        || Expr.ConcreteInt(returnValue) is { IsZero: true }
        && PathConditionsProveStorageReadMissing(state.PathConditions, storageGetOffset);

    private static bool ReturnMatchesStorageReadOrMissingNull(
        ExecutionState state,
        Expression returnValue,
        int storageGetOffset) =>
        IsStorageReadExpression(returnValue, storageGetOffset)
        || returnValue is NullConst
        && PathConditionsProveStorageReadMissing(state.PathConditions, storageGetOffset);

    private static bool PathConditionsProveStorageReadMissing(
        IReadOnlyList<Expression> pathConditions,
        int storageGetOffset)
    {
        string symbolName = $"storage_exists_{storageGetOffset}";
        return pathConditions.Any(condition => ExpressionProvesStorageReadMissing(condition, symbolName));
    }

    private static bool ExpressionProvesStorageReadMissing(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesStorageReadMissing(binary.Left, symbolName)
                || ExpressionProvesStorageReadMissing(binary.Right, symbolName),
            UnaryExpr { Op: "not", Operand: Symbol { Name: var name } } =>
                string.Equals(name, symbolName, StringComparison.Ordinal),
            BinaryExpr { Op: "==" or "num==", Left: Symbol { Name: var name }, Right: BoolConst { Value: false } } =>
                string.Equals(name, symbolName, StringComparison.Ordinal),
            BinaryExpr { Op: "==" or "num==", Left: BoolConst { Value: false }, Right: Symbol { Name: var name } } =>
                string.Equals(name, symbolName, StringComparison.Ordinal),
            BinaryExpr { Op: "!=" or "num!=", Left: Symbol { Name: var name }, Right: BoolConst { Value: true } } =>
                string.Equals(name, symbolName, StringComparison.Ordinal),
            BinaryExpr { Op: "!=" or "num!=", Left: BoolConst { Value: true }, Right: Symbol { Name: var name } } =>
                string.Equals(name, symbolName, StringComparison.Ordinal),
            _ => false,
        };

    private static bool IsAmountExpression(Expression expression, string amountSymbol) =>
        IsSymbol(expression, amountSymbol);

    private static bool PathConditionsProveStorageReadAtLeastAmount(
        IReadOnlyList<Expression> pathConditions,
        int storageGetOffset,
        string amountSymbol) =>
        pathConditions.Any(condition =>
            ExpressionProvesStorageReadAtLeastAmount(condition, storageGetOffset, amount => IsAmountExpression(amount, amountSymbol)));

    private static bool PathConditionsProveStorageReadBelowAmount(
        IReadOnlyList<Expression> pathConditions,
        int storageGetOffset,
        string amountSymbol) =>
        pathConditions.Any(condition =>
            ExpressionProvesStorageReadBelowAmount(condition, storageGetOffset, amount => IsAmountExpression(amount, amountSymbol)));

    private static bool PathConditionsProveStorageReadOrMissingZeroAtLeastAmount(
        IReadOnlyList<Expression> pathConditions,
        int storageGetOffset,
        string amountSymbol) =>
        PathConditionsProveStorageReadAtLeastAmount(pathConditions, storageGetOffset, amountSymbol)
        || PathConditionsProveStorageReadMissing(pathConditions, storageGetOffset)
        && PathConditionsProveAmountAtMostZero(pathConditions, amountSymbol);

    private static bool PathConditionsProveStorageReadAtLeastAmount(
        IReadOnlyList<Expression> pathConditions,
        int storageGetOffset,
        Expression amountExpression) =>
        pathConditions.Any(condition =>
            ExpressionProvesStorageReadAtLeastAmount(condition, storageGetOffset, amount => amount.Equals(amountExpression)));

    private static bool PathConditionsProveAmountAtMostZero(
        IReadOnlyList<Expression> pathConditions,
        string amountSymbol) =>
        pathConditions.Any(condition => ExpressionProvesAmountAtMostZero(condition, amountSymbol));

    private static bool PathConditionsProveAmountNonNegative(
        IReadOnlyList<Expression> pathConditions,
        string amountSymbol) =>
        pathConditions.Any(condition => ExpressionProvesAmountNonNegative(condition, amountSymbol));

    private static bool ExpressionProvesAmountNonNegative(Expression condition, string amountSymbol) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesAmountNonNegative(binary.Left, amountSymbol)
                || ExpressionProvesAmountNonNegative(binary.Right, amountSymbol),
            BinaryExpr { Op: ">=" or ">" } comparison =>
                IsAmountExpression(comparison.Left, amountSymbol)
                && IsZeroIntExpression(comparison.Right),
            BinaryExpr { Op: "<=" or "<" } comparison =>
                IsZeroIntExpression(comparison.Left)
                && IsAmountExpression(comparison.Right, amountSymbol),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "<" } comparison
            } =>
                IsAmountExpression(comparison.Left, amountSymbol)
                && IsZeroIntExpression(comparison.Right),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: ">" } comparison
            } =>
                IsZeroIntExpression(comparison.Left)
                && IsAmountExpression(comparison.Right, amountSymbol),
            _ => false,
        };

    private static bool ExpressionProvesAmountAtMostZero(Expression condition, string amountSymbol) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesAmountAtMostZero(binary.Left, amountSymbol)
                || ExpressionProvesAmountAtMostZero(binary.Right, amountSymbol),
            BinaryExpr { Op: "<=" or "<" } comparison =>
                IsAmountExpression(comparison.Left, amountSymbol)
                && IsZeroIntExpression(comparison.Right),
            BinaryExpr { Op: ">=" or ">" } comparison =>
                IsZeroIntExpression(comparison.Left)
                && IsAmountExpression(comparison.Right, amountSymbol),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: ">" } comparison
            } =>
                IsAmountExpression(comparison.Left, amountSymbol)
                && IsZeroIntExpression(comparison.Right),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "<" } comparison
            } =>
                IsZeroIntExpression(comparison.Left)
                && IsAmountExpression(comparison.Right, amountSymbol),
            _ => false,
        };

    private static bool ExpressionProvesStorageReadAtLeastAmount(
        Expression condition,
        int storageGetOffset,
        Func<Expression, bool> amountMatches) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesStorageReadAtLeastAmount(binary.Left, storageGetOffset, amountMatches)
                || ExpressionProvesStorageReadAtLeastAmount(binary.Right, storageGetOffset, amountMatches),
            BinaryExpr { Op: ">=" or ">" } comparison =>
                IsStorageReadExpression(comparison.Left, storageGetOffset)
                && amountMatches(comparison.Right),
            BinaryExpr { Op: "<=" or "<" } comparison =>
                amountMatches(comparison.Left)
                && IsStorageReadExpression(comparison.Right, storageGetOffset),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "<" } comparison
            } =>
                IsStorageReadExpression(comparison.Left, storageGetOffset)
                && amountMatches(comparison.Right),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: ">" } comparison
            } =>
                amountMatches(comparison.Left)
                && IsStorageReadExpression(comparison.Right, storageGetOffset),
            _ => false,
        };

    private static bool ExpressionProvesStorageReadBelowAmount(
        Expression condition,
        int storageGetOffset,
        Func<Expression, bool> amountMatches) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesStorageReadBelowAmount(binary.Left, storageGetOffset, amountMatches)
                || ExpressionProvesStorageReadBelowAmount(binary.Right, storageGetOffset, amountMatches),
            BinaryExpr { Op: "<" } comparison =>
                IsStorageReadExpression(comparison.Left, storageGetOffset)
                && amountMatches(comparison.Right),
            BinaryExpr { Op: ">" } comparison =>
                amountMatches(comparison.Left)
                && IsStorageReadExpression(comparison.Right, storageGetOffset),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: ">=" } comparison
            } =>
                IsStorageReadExpression(comparison.Left, storageGetOffset)
                && amountMatches(comparison.Right),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "<=" } comparison
            } =>
                amountMatches(comparison.Left)
                && IsStorageReadExpression(comparison.Right, storageGetOffset),
            _ => false,
        };

    private static bool IsZeroIntExpression(Expression expression) =>
        Expr.ConcreteInt(expression) is { IsZero: true };

    private static bool IsExpectedNep17BalanceDeltaArithmetic(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        ArithmeticOp op)
    {
        bool isNep17Transfer = IsNep17TransferMethod(manifest, method);
        bool isNep11DivisibleTransfer = IsNep11DivisibleTransferMethod(manifest, method);
        bool isNep11NonDivisibleTransfer = IsNep11NonDivisibleTransferMethod(manifest, method);
        if (!isNep17Transfer && !isNep11DivisibleTransfer && !isNep11NonDivisibleTransfer)
            return false;
        if (op.Left is null || op.Right is null)
            return false;

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (fromIndex >= 0 && toIndex >= 0 && amountIndex >= 0)
        {
            if (!isNep17Transfer && !isNep11DivisibleTransfer)
                return false;

            string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
            string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
            string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
            var fromGet = FindStorageGetByAccountKey(state, fromSymbol);
            var toGet = FindStorageGetByAccountKey(state, toSymbol);
            if (IsExpectedBalanceDeltaArithmetic(state, op, fromGet, toGet, amount => IsAmountExpression(amount, amountSymbol)))
                return true;

            if (tokenIdIndex < 0)
                return false;

            string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
            var fromTokenGet = FindStorageGetByAccountTokenKey(state, fromSymbol, tokenIdSymbol);
            var toTokenGet = FindStorageGetByAccountTokenKey(state, toSymbol, tokenIdSymbol);
            return IsExpectedBalanceDeltaArithmetic(state, op, fromTokenGet, toTokenGet, amount => IsAmountExpression(amount, amountSymbol));
        }

        if (!isNep11NonDivisibleTransfer)
            return false;
        if (toIndex < 0 || tokenIdIndex < 0)
            return false;

        string ownerToSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string ownerTokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        var ownerRead = FindStorageGetByAccountKey(state, ownerTokenIdSymbol);
        if (ownerRead is null)
            return false;

        string ownerSymbol = StorageReadSymbolName(ownerRead.Op.Offset);
        var ownerGet = FindStorageGetByAccountKey(state, ownerSymbol);
        var recipientGet = FindStorageGetByAccountKey(state, ownerToSymbol);
        return IsExpectedBalanceDeltaArithmetic(state, op, ownerGet, recipientGet, amount => amount.Equals(Expr.Int(1)));
    }

    private static bool IsExpectedBalanceDeltaArithmetic(
        ExecutionState state,
        ArithmeticOp op,
        AccountKeyMatch? fromGet,
        AccountKeyMatch? toGet,
        Func<Expression, bool> amountMatches) =>
        op.Operation == "SUB"
        && fromGet is not null
        && IsStorageReadOrMissingZeroExpression(op.Left!.Expression, state, fromGet.Op.Offset)
        && amountMatches(op.Right!.Expression)
        || op.Operation == "ADD"
        && toGet is not null
        && (IsStorageReadOrMissingZeroExpression(op.Left!.Expression, state, toGet.Op.Offset)
            && amountMatches(op.Right!.Expression)
            || amountMatches(op.Left!.Expression)
            && IsStorageReadOrMissingZeroExpression(op.Right!.Expression, state, toGet.Op.Offset));

    private static bool TryCanonicalConcreteStorageKey(
        ExecutionState state,
        SymbolicValue key,
        out Expression expression)
    {
        expression = key.Expression;
        if (TryGetConcreteRuntimeBytes(state, key, out var runtimeBytes))
        {
            expression = Expr.Bytes(runtimeBytes);
            return true;
        }

        if (key.Expression.IsConcrete)
            return true;

        if (key.Expression is HeapRef href
            && state.Heap.Get(href.ObjectId) is BufferObject buffer
            && TryConcreteBufferBytes(buffer, out var bytes))
        {
            expression = Expr.Bytes(bytes);
            return true;
        }

        return false;
    }

    private static Expression RuntimeStorageKeyExpressionOrOriginal(
        ExecutionState state,
        SymbolicValue key) =>
        TryRuntimeStorageKeyExpression(state, key, out var expression)
            ? expression
            : key.Expression;

    private static bool TryRuntimeStorageKeyExpression(
        ExecutionState state,
        SymbolicValue key,
        out Expression expression)
    {
        if (TryGetRuntimeByteStringExpression(state, key, out expression))
            return true;

        if (TryCanonicalConcreteStorageKey(state, key, out expression))
            return true;

        expression = key.Expression;
        return false;
    }

    private static bool TryConcreteBufferBytes(BufferObject buffer, out byte[] bytes)
    {
        bytes = Array.Empty<byte>();
        var result = new byte[buffer.Cells.Count];
        for (int i = 0; i < buffer.Cells.Count; i++)
        {
            if (Expr.ConcreteInt(buffer.Cells[i]) is not { } value
                || value < byte.MinValue
                || value > byte.MaxValue)
            {
                return false;
            }

            result[i] = (byte)value;
        }

        bytes = result;
        return true;
    }

    private static bool StorageKeysEqual(Expression left, Expression right)
    {
        var leftBytes = Expr.CanonicalBytes(left);
        var rightBytes = Expr.CanonicalBytes(right);
        if (leftBytes is not null && rightBytes is not null)
            return leftBytes.AsSpan().SequenceEqual(rightBytes);

        return left.Equals(right);
    }

    private static bool MutationKeyMayAliasSupplyKey(
        ContractMethodDescriptor method,
        Expression mutationKey,
        ImmutableArray<Expression> supplyKeys)
    {
        var symbols = mutationKey.FreeSymbols().ToArray();
        if (symbols.Length > 0
            && symbols.All(symbol => IsHash160ParameterSymbol(method, symbol))
            && TryStorageKeyLength(method, mutationKey, out int mutationKeyLength)
            && supplyKeys.All(key => Expr.CanonicalBytes(key) is { } bytes && bytes.Length != mutationKeyLength))
        {
            return false;
        }

        return true;
    }

    private static bool TryStorageKeyLength(
        ContractMethodDescriptor method,
        Expression key,
        out int length)
    {
        if (Expr.CanonicalBytes(key) is { } bytes)
        {
            length = bytes.Length;
            return true;
        }

        if (key is Symbol { Name: var name } && IsHash160ParameterSymbol(method, name))
        {
            length = 20;
            return true;
        }

        if (Expr.TryKnownByteLength(key, out length))
            return true;

        if (key is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } binary
            && TryStorageKeyLength(method, binary.Left, out int leftLength)
            && TryStorageKeyLength(method, binary.Right, out int rightLength))
        {
            length = leftLength + rightLength;
            return true;
        }

        length = 0;
        return false;
    }

    private static bool IsHash160ParameterSymbol(ContractMethodDescriptor method, string symbol)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (!IsHash160Like(method.Parameters[i].Type))
                continue;

            string expected = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[i].Name, i);
            if (string.Equals(symbol, expected, StringComparison.Ordinal))
                return true;
        }

        return false;
    }

    private static string FormatStorageKey(Expression key) =>
        Expr.CanonicalBytes(key) is { } bytes
            ? "0x" + Convert.ToHexString(bytes).ToLowerInvariant()
            : key.ToString();

    private static bool PathConditionsProveSymbolByteLengthAtMost(
        IReadOnlyList<Expression> pathConditions,
        string symbolName,
        BigInteger maxLength) =>
        pathConditions.Any(condition => ExpressionProvesSymbolByteLengthAtMost(condition, symbolName, maxLength));

    private static bool ExpressionProvesSymbolByteLengthAtMost(
        Expression condition,
        string symbolName,
        BigInteger maxLength) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesSymbolByteLengthAtMost(binary.Left, symbolName, maxLength)
                || ExpressionProvesSymbolByteLengthAtMost(binary.Right, symbolName, maxLength),
            BinaryExpr comparison =>
                ComparisonProvesSymbolByteLengthAtMost(comparison, symbolName, maxLength),
            UnaryExpr { Op: "not", Operand: BinaryExpr comparison } =>
                NegatedComparisonProvesSymbolByteLengthAtMost(comparison, symbolName, maxLength),
            _ => false,
        };

    private static bool ComparisonProvesSymbolByteLengthAtMost(
        BinaryExpr comparison,
        string symbolName,
        BigInteger maxLength)
    {
        if (IsSymbolByteLengthExpression(comparison.Left, symbolName)
            && Expr.ConcreteInt(comparison.Right) is { } rightBound)
        {
            return comparison.Op switch
            {
                "<=" => rightBound <= maxLength,
                "<" => rightBound <= maxLength + 1,
                "==" or "num==" => rightBound <= maxLength,
                _ => false,
            };
        }

        if (IsSymbolByteLengthExpression(comparison.Right, symbolName)
            && Expr.ConcreteInt(comparison.Left) is { } leftBound)
        {
            return comparison.Op switch
            {
                ">=" => leftBound <= maxLength,
                ">" => leftBound <= maxLength + 1,
                "==" or "num==" => leftBound <= maxLength,
                _ => false,
            };
        }

        return false;
    }

    private static bool NegatedComparisonProvesSymbolByteLengthAtMost(
        BinaryExpr comparison,
        string symbolName,
        BigInteger maxLength)
    {
        if (IsSymbolByteLengthExpression(comparison.Left, symbolName)
            && Expr.ConcreteInt(comparison.Right) is { } rightBound)
        {
            return comparison.Op switch
            {
                ">" => rightBound <= maxLength,
                ">=" => rightBound <= maxLength + 1,
                "!=" or "num!=" => rightBound <= maxLength,
                _ => false,
            };
        }

        if (IsSymbolByteLengthExpression(comparison.Right, symbolName)
            && Expr.ConcreteInt(comparison.Left) is { } leftBound)
        {
            return comparison.Op switch
            {
                "<" => leftBound <= maxLength,
                "<=" => leftBound <= maxLength + 1,
                "!=" or "num!=" => leftBound <= maxLength,
                _ => false,
            };
        }

        return false;
    }

    private static bool IsSymbolByteLengthExpression(Expression expression, string symbolName) =>
        expression is UnaryExpr
        {
            Sort: Sort.Int,
            Op: "size",
            Operand: Symbol { Name: var name }
        } && string.Equals(name, symbolName, StringComparison.Ordinal);

    private static bool PathConditionsExcludeHash160Zero(
        IReadOnlyList<Expression> pathConditions,
        string symbolName) =>
        pathConditions.Any(condition => ExpressionExcludesHash160Zero(condition, symbolName));

    private static bool PathConditionsExcludeSymbolEquality(
        IReadOnlyList<Expression> pathConditions,
        string leftSymbol,
        string rightSymbol) =>
        pathConditions.Any(condition => ExpressionExcludesSymbolEquality(condition, leftSymbol, rightSymbol));

    private static bool PathConditionsProveSymbolEquality(
        IReadOnlyList<Expression> pathConditions,
        string leftSymbol,
        string rightSymbol) =>
        pathConditions.Any(condition => ExpressionProvesSymbolEquality(condition, leftSymbol, rightSymbol));

    private static bool ExpressionProvesSymbolEquality(
        Expression condition,
        string leftSymbol,
        string rightSymbol) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesSymbolEquality(binary.Left, leftSymbol, rightSymbol)
                || ExpressionProvesSymbolEquality(binary.Right, leftSymbol, rightSymbol),
            BinaryExpr { Op: "==" or "num==" } equality =>
                EqualityComparesSymbols(equality.Left, equality.Right, leftSymbol, rightSymbol),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "!=" or "num!=" } inequality
            } =>
                EqualityComparesSymbols(inequality.Left, inequality.Right, leftSymbol, rightSymbol),
            _ => false,
        };

    private static bool PathConditionsProveCallerHashEqualsSymbol(
        IReadOnlyList<Expression> pathConditions,
        string symbolName) =>
        pathConditions.Any(condition => ExpressionProvesCallerHashEqualsSymbol(condition, symbolName));

    private static bool ExpressionProvesCallerHashEqualsSymbol(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionProvesCallerHashEqualsSymbol(binary.Left, symbolName)
                || ExpressionProvesCallerHashEqualsSymbol(binary.Right, symbolName),
            BinaryExpr { Op: "==" } equality =>
                CallerHashEqualsSymbol(equality.Left, equality.Right, symbolName),
            _ => false,
        };

    private static bool CallerHashEqualsSymbol(Expression left, Expression right, string symbolName) =>
        left is Symbol { Name: var leftName }
        && IsCallingScriptHashSymbol(leftName)
        && IsSymbol(right, symbolName)
        || right is Symbol { Name: var rightName }
        && IsCallingScriptHashSymbol(rightName)
        && IsSymbol(left, symbolName);

    private static bool IsCallingScriptHashSymbol(string name) =>
        string.Equals(name, "calling_script_hash", StringComparison.Ordinal)
        || name.StartsWith("caller_hash_", StringComparison.Ordinal);

    private static bool ExpressionExcludesSymbolEquality(
        Expression condition,
        string leftSymbol,
        string rightSymbol) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionExcludesSymbolEquality(binary.Left, leftSymbol, rightSymbol)
                || ExpressionExcludesSymbolEquality(binary.Right, leftSymbol, rightSymbol),
            BinaryExpr { Op: "!=" or "num!=" } inequality =>
                EqualityComparesSymbols(inequality.Left, inequality.Right, leftSymbol, rightSymbol),
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "==" or "num==" } equality
            } =>
                EqualityComparesSymbols(equality.Left, equality.Right, leftSymbol, rightSymbol),
            _ => false,
        };

    private static bool EqualityComparesSymbols(
        Expression left,
        Expression right,
        string leftSymbol,
        string rightSymbol) =>
        IsSymbol(left, leftSymbol) && IsSymbol(right, rightSymbol)
        || IsSymbol(left, rightSymbol) && IsSymbol(right, leftSymbol);

    private static bool ExpressionExcludesHash160Zero(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionExcludesHash160Zero(binary.Left, symbolName)
                || ExpressionExcludesHash160Zero(binary.Right, symbolName),
            UnaryExpr { Op: "not", Operand: BinaryExpr { Op: "==" } equality } =>
                EqualityComparesSymbolToHash160Zero(equality.Left, equality.Right, symbolName),
            BinaryExpr { Op: "!=" } inequality =>
                EqualityComparesSymbolToHash160Zero(inequality.Left, inequality.Right, symbolName),
            BinaryExpr { Op: "num!=" } numericInequality =>
                NumericExpressionMatchesHash160Symbol(numericInequality.Left, symbolName)
                && Expr.ConcreteInt(numericInequality.Right) is { IsZero: true }
                || NumericExpressionMatchesHash160Symbol(numericInequality.Right, symbolName)
                && Expr.ConcreteInt(numericInequality.Left) is { IsZero: true },
            UnaryExpr
            {
                Op: "not",
                Operand: BinaryExpr { Op: "num==" } numericEquality
            } =>
                NumericExpressionMatchesHash160Symbol(numericEquality.Left, symbolName)
                && Expr.ConcreteInt(numericEquality.Right) is { IsZero: true }
                || NumericExpressionMatchesHash160Symbol(numericEquality.Right, symbolName)
                && Expr.ConcreteInt(numericEquality.Left) is { IsZero: true },
            _ => false,
        };

    private static bool EqualityComparesSymbolToHash160Zero(
        Expression left,
        Expression right,
        string symbolName) =>
        IsSymbol(left, symbolName) && IsHash160ZeroConstant(right)
        || IsSymbol(right, symbolName) && IsHash160ZeroConstant(left);

    private static bool IsHash160ZeroConstant(Expression expression) =>
        expression is BytesConst bytes
        && bytes.Value.Length == 20
        && bytes.Value.All(b => b == 0);

    private static bool NumericExpressionMatchesHash160Symbol(Expression expression, string symbolName) =>
        expression switch
        {
            Symbol { Sort: Sort.Bytes } symbol => string.Equals(symbol.Name, symbolName, StringComparison.Ordinal),
            UnaryExpr { Sort: Sort.Int, Op: "b2i", Operand: Symbol { Sort: Sort.Bytes } symbol } =>
                string.Equals(symbol.Name, symbolName, StringComparison.Ordinal),
            _ => false,
        };

    private static bool TryReturnMayBeTrue(
        ContractMethodDescriptor method,
        ExecutionState state,
        ISmtBackend? smtBackend,
        out bool mayBeTrue,
        out string reason)
    {
        mayBeTrue = true;
        reason = "";
        if (!string.Equals(method.ReturnType, "Boolean", StringComparison.OrdinalIgnoreCase))
            return true;
        if (state.EvaluationStack.Count == 0)
        {
            mayBeTrue = false;
            reason = $"method '{method.Name}' has no Boolean return value on a successful HALT path";
            return false;
        }

        var returned = state.Peek();
        if (returned.Sort != Sort.Bool)
        {
            mayBeTrue = false;
            reason = $"method '{method.Name}' declares return type 'Boolean', but a successful HALT path returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem";
            return false;
        }

        var returnExpr = returned.Expression;
        if (returnExpr is BoolConst concrete)
        {
            mayBeTrue = concrete.Value;
            return true;
        }

        var outcome = smtBackend?.IsSatisfiable(SuccessfulHaltPathConditions(state), returnExpr)
            ?? SmtOutcome.Unknown;
        if (outcome == SmtOutcome.Unknown)
        {
            mayBeTrue = true;
            reason = $"solver returned unknown for true-return reachability in method '{method.Name}'";
            return false;
        }

        mayBeTrue = outcome == SmtOutcome.Sat;
        return true;
    }

    private static bool TrySatisfiability(
        ExecutionState state,
        ISmtBackend? smtBackend,
        Expression condition,
        out SmtOutcome outcome,
        out string reason)
    {
        reason = "";
        if (Expr.Truthy(condition) is { } concrete)
        {
            outcome = concrete ? SmtOutcome.Sat : SmtOutcome.Unsat;
            return true;
        }

        outcome = smtBackend?.IsSatisfiable(SuccessfulHaltPathConditions(state), condition)
            ?? SmtOutcome.Unknown;
        if (outcome == SmtOutcome.Unknown)
        {
            reason = "solver returned unknown while proving ownerOf(tokenId) index balance reachability";
            return false;
        }

        return true;
    }

    private static bool TryReturnMayBeFalse(
        ContractMethodDescriptor method,
        ExecutionState state,
        ISmtBackend? smtBackend,
        out bool mayBeFalse,
        out SmtOutcome outcome,
        out string reason)
    {
        mayBeFalse = true;
        outcome = SmtOutcome.Unknown;
        reason = "";
        if (!string.Equals(method.ReturnType, "Boolean", StringComparison.OrdinalIgnoreCase))
            return true;
        if (state.EvaluationStack.Count == 0)
        {
            mayBeFalse = false;
            outcome = SmtOutcome.Unsat;
            reason = $"method '{method.Name}' has no Boolean return value on a successful HALT path";
            return false;
        }

        var returned = state.Peek();
        if (returned.Sort != Sort.Bool)
        {
            mayBeFalse = false;
            outcome = SmtOutcome.Unknown;
            reason = $"method '{method.Name}' declares return type 'Boolean', but a successful HALT path returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem";
            return false;
        }

        var returnExpr = returned.Expression;
        if (returnExpr is BoolConst concrete)
        {
            mayBeFalse = !concrete.Value;
            outcome = mayBeFalse ? SmtOutcome.Sat : SmtOutcome.Unsat;
            return true;
        }

        outcome = smtBackend?.IsSatisfiable(SuccessfulHaltPathConditions(state), Expr.Not(returnExpr))
            ?? SmtOutcome.Unknown;
        mayBeFalse = outcome != SmtOutcome.Unsat;
        return true;
    }

    private static ImmutableDictionary<string, object>? BuildStateWitness(
        ISmtBackend? smtBackend,
        ExecutionState state)
    {
        var witness = smtBackend?.BuildWitness(state.PathConditions);
        return witness is null
            ? null
            : ImmutableDictionary.CreateRange(witness);
    }

    private static ImmutableDictionary<string, object>? BuildWitness(
        ISmtBackend? smtBackend,
        IReadOnlyList<Expression> conditions)
    {
        var witness = smtBackend?.BuildWitness(conditions);
        return witness is null
            ? null
            : ImmutableDictionary.CreateRange(witness);
    }

    private static (int CheckedPaths, int IgnoredFaultedPaths, int StoppedPaths) CountPaths(
        ExecutionResult execution) =>
        (
            execution.FinalStates.Count(s => s.Status == TerminalStatus.Halted),
            execution.FinalStates.Count(s => s.Status == TerminalStatus.Faulted),
            execution.FinalStates.Count(s => s.Status == TerminalStatus.Stopped)
        );

    private static string FormatOffset(int offset) => $"0x{offset:X4}";

    private sealed record SensitiveOperation(
        int Offset,
        string Kind,
        string Display,
        ImmutableArray<Expression> RelatedExpressions);
    private sealed record ForbiddenSideEffect(
        int Offset,
        string Display,
        string FailedCondition);
    private sealed record AccountKeyMatch(StorageOp Op, Expression Pattern);

    private static ImmutableArray<Expression> BuildCounterexampleQuery(
        ImmutableArray<Expression> requires,
        IReadOnlyList<Expression> pathConditions,
        Expression ensure)
    {
        var builder = ImmutableArray.CreateBuilder<Expression>(
            requires.Length + pathConditions.Count + 1);
        builder.AddRange(requires);
        builder.AddRange(pathConditions);
        builder.Add(Expr.Not(ensure));
        return builder.ToImmutable();
    }

    private static ImmutableArray<Expression> BuildReachabilityQuery(
        ImmutableArray<Expression> requires,
        IReadOnlyList<Expression> pathConditions,
        Expression? extra = null)
    {
        var builder = ImmutableArray.CreateBuilder<Expression>(
            requires.Length + pathConditions.Count + (extra is null ? 0 : 1));
        builder.AddRange(requires);
        builder.AddRange(pathConditions);
        if (extra is not null)
            builder.Add(extra);
        return builder.ToImmutable();
    }

    private static ImmutableArray<Expression> BuildTrueReturnReachabilityQuery(
        ContractMethodDescriptor method,
        ExecutionState state,
        Expression extra)
    {
        var pathConditions = SuccessfulHaltPathConditions(state);
        var builder = ImmutableArray.CreateBuilder<Expression>(pathConditions.Length + 2);
        builder.AddRange(pathConditions);
        if (string.Equals(method.ReturnType, "Boolean", StringComparison.OrdinalIgnoreCase)
            && state.EvaluationStack.Count > 0)
        {
            var returnExpr = Expr.ToBool(state.Peek().Expression);
            if (returnExpr is BoolConst { Value: false })
                builder.Add(BoolConst.False);
            else if (returnExpr is not BoolConst { Value: true })
                builder.Add(returnExpr);
        }
        builder.Add(extra);
        return builder.ToImmutable();
    }

    private static ImmutableArray<Expression> BuildFalseReturnReachabilityQuery(
        ContractMethodDescriptor method,
        ExecutionState state)
    {
        return BuildFalseReturnReachabilityQuery(method, state, extra: null);
    }

    private static ImmutableArray<Expression> BuildFalseReturnReachabilityQuery(
        ContractMethodDescriptor method,
        ExecutionState state,
        Expression? extra)
    {
        var pathConditions = SuccessfulHaltPathConditions(state);
        var builder = ImmutableArray.CreateBuilder<Expression>(pathConditions.Length + (extra is null ? 1 : 2));
        builder.AddRange(pathConditions);
        if (string.Equals(method.ReturnType, "Boolean", StringComparison.OrdinalIgnoreCase)
            && state.EvaluationStack.Count > 0)
        {
            var returnExpr = Expr.ToBool(state.Peek().Expression);
            if (returnExpr is BoolConst { Value: true })
                builder.Add(BoolConst.False);
            else if (returnExpr is not BoolConst { Value: false })
                builder.Add(Expr.Not(returnExpr));
        }
        if (extra is not null)
            builder.Add(extra);
        return builder.ToImmutable();
    }

    private static Expression Hash160NumericExpression(string symbolName) =>
        new UnaryExpr(Sort.Int, "b2i", Expr.Sym(Sort.Bytes, symbolName));

    private static string ProvedReason(VerificationProperty property, int checkedPaths)
    {
        bool hasEnsures = !property.Ensures.IsDefaultOrEmpty;
        bool hasForbiddenSideEffects = property.HasForbiddenSideEffectObligations;
        bool hasRequires = !property.Requires.IsDefaultOrEmpty;

        if (property.ForbidFaults && !hasEnsures && !hasForbiddenSideEffects)
            return "all explicit and implicit fault obligations are unreachable under the declared requires conditions";
        if (property.ForbidFaults && !hasEnsures && hasForbiddenSideEffects)
            return "all explicit and implicit fault obligations are unreachable and no forbidden side effects are reachable under the declared requires conditions";
        if (property.ForbidFaults)
            return checkedPaths == 0
                ? "all faulted paths are unreachable under requires; no successful HALT paths reached"
                : hasForbiddenSideEffects
                    ? "all successful HALT paths imply every ensures condition, avoid forbidden side effects, and all faulted paths are unreachable under requires"
                    : "all successful HALT paths imply every ensures condition and all faulted paths are unreachable under requires";
        if (!hasEnsures && hasForbiddenSideEffects)
            return "all successful HALT paths avoid forbidden side effects under the declared requires conditions";
        if (hasEnsures && hasForbiddenSideEffects)
            return "all successful HALT paths imply every ensures condition and avoid forbidden side effects under the declared requires conditions";
        return checkedPaths == 0
            ? "property holds vacuously: no successful HALT paths reached"
            : hasRequires
                ? "all successful HALT paths under requires imply every ensures condition"
                : "all successful HALT paths imply every ensures condition";
    }

    private enum ManifestCallPermissionStatus
    {
        Allowed,
        Denied,
        Incomplete,
    }

    private enum ManifestContractMatch
    {
        Allowed,
        Denied,
        GroupMembershipUnknown,
    }

    private enum AccessControlAuthStatus
    {
        Authorized,
        Missing,
        UnrelatedDynamicWitness,
        UnboundSignatureMessage,
    }

    private sealed record ManifestCallPermissionEvaluation(
        ManifestCallPermissionStatus Status,
        string Reason)
    {
        public static ManifestCallPermissionEvaluation Allowed() =>
            new(ManifestCallPermissionStatus.Allowed, "manifest permission allows call");

        public static ManifestCallPermissionEvaluation Denied(string reason) =>
            new(ManifestCallPermissionStatus.Denied, reason);

        public static ManifestCallPermissionEvaluation Incomplete(string reason) =>
            new(ManifestCallPermissionStatus.Incomplete, reason);
    }

    private sealed record PropertyRunResult(
        VerificationPropertyResult Result,
        int StatesExplored,
        int StepsExecuted,
        bool BudgetExceeded,
        string? BudgetReason,
        bool CoverageIncomplete,
        string? CoverageReason)
    {
        public PropertyRunResult(
            VerificationPropertyResult result,
            ExecutionResult execution,
            bool includeExecutionStats = true)
            : this(
                result,
                includeExecutionStats ? execution.StatesExplored : 0,
                includeExecutionStats ? execution.StepsExecuted : 0,
                includeExecutionStats && execution.BudgetExceeded,
                includeExecutionStats ? execution.BudgetReason : null,
                includeExecutionStats && execution.CoverageIncomplete
                    || result.Status == VerificationStatus.Incomplete,
                (includeExecutionStats ? execution.CoverageReason : null)
                    ?? (result.Status == VerificationStatus.Incomplete ? result.Reason : null))
        {
        }

        public static PropertyRunResult Static(VerificationPropertyResult result) =>
            new(
                result,
                StatesExplored: 0,
                StepsExecuted: 0,
                BudgetExceeded: false,
                BudgetReason: null,
                CoverageIncomplete: false,
                CoverageReason: null);

        public static PropertyRunResult Incomplete(VerificationProperty property, string reason) =>
            Incomplete(
                property.Id,
                property.Method,
                property.Description,
                reason);

        public static PropertyRunResult Incomplete(
            string id,
            string method,
            string? description,
            string reason,
            int? methodOffset = null) =>
            new(
                new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Incomplete,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: 0,
                    Reason: reason,
                    FailedCondition: null,
                    Counterexample: null,
                    MethodOffset: methodOffset),
                StatesExplored: 0,
                StepsExecuted: 0,
                BudgetExceeded: false,
                BudgetReason: null,
                CoverageIncomplete: true,
                CoverageReason: reason);
    }
}
