using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    private static VerificationPropertyResult BuildManifestPermissionsResult(
        ContractManifest manifest,
        byte[]? contractHash)
    {
        const string id = "security.manifest_permissions.*";
        const string method = "*";
        const string description =
            "Contract manifest permissions, trusts, and groups must be narrow enough for proof-grade security.";
        int obligations = Math.Max(
            1,
            manifest.Permissions.Count
            + (manifest.Trusts.IsWildcard ? 1 : manifest.Trusts.Items.Count)
            + manifest.Groups.Count);

        foreach (var permission in manifest.Permissions)
        {
            string methods = permission.Methods.IsWildcard ? "*" : string.Join(",", permission.Methods.Items);
            if (permission.Contract == "*" && permission.Methods.IsWildcard)
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: "manifest.permissions grants contract=\"*\" methods=\"*\".",
                    FailedCondition: "manifest has no fully-wildcard contract permission",
                    Counterexample: null);
            }

            if (permission.Contract == "*" || permission.Methods.IsWildcard)
            {
                if (IsAllowedStandardCallbackWildcardPermission(manifest, permission))
                    continue;

                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: $"manifest.permissions contains wildcard component contract={permission.Contract} methods={methods}.",
                    FailedCondition: "manifest has no partial-wildcard contract permission",
                    Counterexample: null);
            }

            if (!IsValidManifestPermissionContract(permission.Contract))
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: $"manifest.permissions contains invalid contract descriptor {permission.Contract}.",
                    FailedCondition: "contract permission target is wildcard, UInt160 hash, or group public key",
                    Counterexample: null);
            }

            if (!permission.Methods.IsWildcard
                && permission.Methods.Items.Any(string.IsNullOrWhiteSpace))
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: "manifest.permissions contains an empty method name.",
                    FailedCondition: "contract permission method names are non-empty",
                    Counterexample: null);
            }
        }

        if (manifest.TrustsWildcard)
        {
            return new VerificationPropertyResult(
                id,
                method,
                description,
                VerificationStatus.Violated,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: obligations,
                Reason: "manifest.trusts is \"*\".",
                FailedCondition: "manifest has no wildcard trusts",
                Counterexample: null);
        }

        foreach (string trust in manifest.Trusts.Items)
        {
            if (!IsValidManifestPermissionContract(trust))
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: $"manifest.trusts contains invalid trust descriptor {trust}.",
                    FailedCondition: "manifest trust targets are UInt160 hashes or valid group public keys",
                    Counterexample: null);
            }
        }

        foreach (var group in manifest.Groups)
        {
            if (string.IsNullOrEmpty(group.PubKey) || group.PubKey == "*")
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: "manifest.groups contains a missing or wildcard public key.",
                    FailedCondition: "manifest groups are cryptographically pinned",
                    Counterexample: null);
            }

            if (!IsValidManifestGroupPublicKey(group.PubKey))
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: "manifest.groups contains an invalid group public key encoding.",
                    FailedCondition: "manifest group public keys are valid ECPoint encodings",
                    Counterexample: null);
            }

            if (!IsValidManifestGroupSignature(group.Signature))
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: "manifest.groups contains an invalid group signature.",
                    FailedCondition: "manifest group signatures are 64-byte signatures",
                    Counterexample: null);
            }

            if (contractHash is not { Length: Hash160ByteLength })
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Incomplete,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: "manifest.groups signatures cannot be verified because the Neo N3 contract hash is unavailable; verify a NEF with --deploy-sender-hash to bind groups to this contract.",
                    FailedCondition: null,
                    Counterexample: null);
            }

            if (!VerifyManifestGroupSignature(group.PubKey, group.Signature, contractHash))
            {
                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    CheckedPaths: 0,
                    IgnoredFaultedPaths: 0,
                    StoppedPaths: 0,
                    ObligationsChecked: obligations,
                    Reason: "manifest.groups contains a group signature that does not verify against the computed Neo N3 contract hash.",
                    FailedCondition: "manifest group signatures verify the contract hash",
                    Counterexample: null);
            }
        }

        return new VerificationPropertyResult(
            id,
            method,
            description,
            VerificationStatus.Proved,
            CheckedPaths: 0,
            IgnoredFaultedPaths: 0,
            StoppedPaths: 0,
            ObligationsChecked: obligations,
            Reason: manifest.Permissions.Any(p => IsAllowedStandardCallbackWildcardPermission(manifest, p))
                ? "manifest permissions, trusts, and groups are narrow and pinned with method-pinned standard receiver callbacks"
                : "manifest permissions, trusts, and groups are narrow and pinned",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildEntrypointReachabilityResult(
        ContractMethodDescriptor method,
        ExecutionResult execution)
    {
        string id = $"security.entrypoint_reaches_halt.{method.Name}";
        string description = "The ABI entrypoint must have at least one successful HALT path.";
        var counts = CountPaths(execution);
        const int obligations = 1;

        if (counts.CheckedPaths == 0)
        {
            string reason = execution.FinalStates.Length == 0
                ? "entrypoint produced no terminal states"
                : $"entrypoint reached no successful HALT paths (faulted={counts.IgnoredFaultedPaths}, stopped={counts.StoppedPaths})";
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                reason,
                FailedCondition: null,
                Counterexample: null);
        }

        // Review fix (#48): this is an EXISTENTIAL obligation (>=1 reachable successful HALT path); a
        // Proved verdict here does NOT assert full-coverage reachability of the entrypoint. Coverage /
        // budget incompleteness for this method is carried by the sibling vm_surface / vm_fault_free /
        // abi_return_type obligations and the report Meta, so this result deliberately does not
        // consult IncompleteReasons. Make the existential scope explicit in the reason string.
        return new VerificationPropertyResult(
            id,
            method.Name,
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            "at least one successful HALT path is reachable (existential; full-coverage reachability is "
                + "not asserted by this obligation)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildAbiReturnTypeResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.abi_return_type.{method.Name}";
        string description = "Every successful ABI entrypoint path must return a value compatible with manifest.returntype.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();
        var assumptions = new List<VerificationAssumption>();

        foreach (var state in execution.Halted)
        {
            obligations++;
            var check = CheckAbiReturnType(manifest, method, state);
            if (check.Kind == AbiReturnTypeCheckKind.Match)
            {
                if (!check.Assumptions.IsDefaultOrEmpty)
                    assumptions.AddRange(check.Assumptions);
                continue;
            }

            if (check.Kind == AbiReturnTypeCheckKind.Incomplete)
            {
                incompleteReasons.Add(check.Reason);
                continue;
            }

            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                check.Reason,
                "successful HALT return stack conforms to manifest.returntype",
                BuildStateWitness(smtBackend, state));
        }

        incompleteReasons.AddRange(IncompleteReasons(execution));
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
            "every successful HALT path returns a StackItem compatible with manifest.returntype",
            FailedCondition: null,
            Counterexample: null,
            Assumptions: assumptions.Distinct().ToImmutableArray());
    }

    private static AbiReturnTypeCheck CheckAbiReturnType(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state)
    {
        string returnType = string.IsNullOrWhiteSpace(method.ReturnType)
            ? "Void"
            : method.ReturnType;

        if (IsAbiType(returnType, "Void"))
        {
            return state.EvaluationStack.Count == 0
                ? AbiReturnTypeCheck.Match()
                : AbiReturnTypeCheck.Mismatch(
                    $"manifest method '{method.Name}' declares return type 'Void', but a successful HALT path leaves runtime {DescribeRuntimeArgumentType(state, state.Peek())} StackItem on the result stack");
        }

        if (state.EvaluationStack.Count == 0)
        {
            return AbiReturnTypeCheck.Mismatch(
                $"manifest method '{method.Name}' declares return type '{returnType}', but a successful HALT path returns no StackItem");
        }
        if (state.EvaluationStack.Count != 1)
        {
            return AbiReturnTypeCheck.Mismatch(
                $"manifest method '{method.Name}' declares return type '{returnType}', but a successful HALT path leaves {state.EvaluationStack.Count} StackItems on the result stack; ABI returntype conformance requires exactly one returned StackItem");
        }

        var returned = state.Peek();
        if (IsAbiType(returnType, "Any"))
            return AbiReturnTypeCheck.Match();
        if (AllowsNullAbiReturn(manifest, method, returned))
            return AbiReturnTypeCheck.Match();

        if (TryGetManifestFixedByteLength(returnType, out int fixedLength))
            return CheckAbiReturnFixedByteLength(manifest, method, state, returned, returnType, fixedLength);

        if (IsAbiType(returnType, "String"))
            return CheckAbiReturnString(method, state, returned);

        if (IsManifestByteStringLike(returnType))
            return RequireAbiReturnSort(method, state, returned, returnType, IsRuntimeByteStringLike(returned), "ByteString or Buffer");

        if (IsAbiType(returnType, "Integer"))
            return RequireAbiReturnSort(method, state, returned, returnType, returned.Sort == Sort.Int, "Integer");

        if (IsAbiType(returnType, "Boolean"))
            return RequireAbiReturnSort(method, state, returned, returnType, returned.Sort == Sort.Bool, "Boolean");

        if (IsAbiType(returnType, "Array"))
        {
            return RequireAbiReturnSort(
                method,
                state,
                returned,
                returnType,
                returned.Sort is Sort.Array or Sort.Struct,
                "Array or Struct");
        }

        if (IsAbiType(returnType, "Struct"))
            return RequireAbiReturnSort(method, state, returned, returnType, returned.Sort == Sort.Struct, "Struct");

        if (IsAbiType(returnType, "Map"))
            return RequireAbiReturnSort(method, state, returned, returnType, returned.Sort == Sort.Map, "Map");

        if (IsAbiType(returnType, "InteropInterface"))
        {
            return RequireAbiReturnSort(
                method,
                state,
                returned,
                returnType,
                returned.Sort == Sort.InteropInterface,
                "InteropInterface");
        }

        return AbiReturnTypeCheck.Incomplete(
            $"manifest method '{method.Name}' declares unsupported return type '{returnType}', so runtime return conformance cannot be proven");
    }

    private static bool AllowsNullAbiReturn(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        SymbolicValue returned) =>
        returned.IsConcreteNull
        && manifest.DeclaresStandard("NEP-11")
        && IsNep11NonDivisibleOwnerOfMethod(method);

    private static AbiReturnTypeCheck CheckAbiReturnString(
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue returned)
    {
        if (!IsRuntimeByteStringLike(returned))
            return ReturnTypeMismatchOrIncomplete(method, state, returned, "String", "ByteString or Buffer");

        if (TryGetConcreteRuntimeBytes(state, returned, out byte[] bytes))
        {
            return IsStrictUtf8(bytes)
                ? AbiReturnTypeCheck.Match()
                : AbiReturnTypeCheck.Mismatch(
                    $"manifest method '{method.Name}' declares return type 'String', but a successful HALT path returns ByteString that is not valid strict UTF-8");
        }

        if (TryGetRuntimeByteStringExpression(state, returned, out var returnedBytes)
            && HasStrictUtf8Constraint(state, returnedBytes))
            return AbiReturnTypeCheck.Match();

        return AbiReturnTypeCheck.Incomplete(
            $"manifest method '{method.Name}' declares return type 'String', but returned ByteString UTF-8 validity cannot be proven");
    }

    private static AbiReturnTypeCheck CheckAbiReturnFixedByteLength(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue returned,
        string returnType,
        int expectedLength)
    {
        if (!IsRuntimeByteStringLike(returned))
            return ReturnTypeMismatchOrIncomplete(method, state, returned, returnType, "ByteString or Buffer");

        if (IsAbiType(returnType, "PublicKey"))
            return CheckAbiReturnPublicKey(method, state, returned, expectedLength);

        if (TryGetKnownByteLength(state, returned, out int knownLength))
        {
            return knownLength == expectedLength
                ? AbiReturnTypeCheck.Match()
                : AbiReturnTypeCheck.Mismatch(
                    $"manifest method '{method.Name}' declares return type '{returnType}', but a successful HALT path returns ByteString with length {knownLength} bytes; expected {expectedLength} bytes");
        }

        if (TryGetRuntimeByteStringExpression(state, returned, out var returnedBytes)
            && HasByteLengthConstraint(state, returnedBytes, expectedLength))
            return AbiReturnTypeCheck.Match();

        if (AllowsAssumedNep11OwnerHash160Return(manifest, method, returnType, expectedLength, returned))
            return AbiReturnTypeCheck.Match(ImmutableArray.Create(Nep11OwnerStorageHash160EncodingAssumption));

        return AbiReturnTypeCheck.Incomplete(
            $"manifest method '{method.Name}' declares return type '{returnType}', but returned ByteString length {expectedLength} bytes cannot be proven");
    }

    private static AbiReturnTypeCheck CheckAbiReturnPublicKey(
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue returned,
        int expectedLength)
    {
        if (TryGetConcreteRuntimeBytes(state, returned, out byte[] bytes))
        {
            if (bytes.Length != expectedLength)
            {
                return AbiReturnTypeCheck.Mismatch(
                    $"manifest method '{method.Name}' declares return type 'PublicKey', but a successful HALT path returns ByteString with length {bytes.Length} bytes; expected {expectedLength} bytes");
            }

            return NeoEcPoint.IsValidEncoding(bytes)
                ? AbiReturnTypeCheck.Match()
                : AbiReturnTypeCheck.Mismatch(
                    $"manifest method '{method.Name}' declares return type 'PublicKey', but a successful HALT path returns ByteString that is not a valid ECPoint encoding");
        }

        if (!TryGetRuntimeByteStringExpression(state, returned, out var returnedBytes)
            || !HasByteLengthConstraint(state, returnedBytes, expectedLength))
        {
            return AbiReturnTypeCheck.Incomplete(
                $"manifest method '{method.Name}' declares return type 'PublicKey', but returned ByteString length {expectedLength} bytes cannot be proven");
        }

        if (HasValidEcPointConstraint(state, returnedBytes))
            return AbiReturnTypeCheck.Match();

        return AbiReturnTypeCheck.Incomplete(
            $"manifest method '{method.Name}' declares return type 'PublicKey', but returned ByteString ECPoint validity cannot be proven");
    }

    private static bool AllowsAssumedNep11OwnerHash160Return(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        string returnType,
        int expectedLength,
        SymbolicValue returned) =>
        expectedLength == Hash160ByteLength
        && IsStrictHash160(returnType)
        && IsRuntimeByteStringLike(returned)
        && manifest.DeclaresStandard("NEP-11")
        && IsNep11NonDivisibleOwnerOfMethod(method);

    private static AbiReturnTypeCheck RequireAbiReturnSort(
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue returned,
        string returnType,
        bool matches,
        string expectedRuntimeType)
    {
        if (matches)
            return AbiReturnTypeCheck.Match();

        return ReturnTypeMismatchOrIncomplete(method, state, returned, returnType, expectedRuntimeType);
    }

    private static AbiReturnTypeCheck ReturnTypeMismatchOrIncomplete(
        ContractMethodDescriptor method,
        ExecutionState state,
        SymbolicValue returned,
        string returnType,
        string expectedRuntimeType)
    {
        if (returned.Sort == Sort.Unknown)
        {
            return AbiReturnTypeCheck.Incomplete(
                $"manifest method '{method.Name}' declares return type '{returnType}', but a successful HALT path returns an unknown runtime StackItem type");
        }

        return AbiReturnTypeCheck.Mismatch(
            $"manifest method '{method.Name}' declares return type '{returnType}', but a successful HALT path returns runtime {DescribeRuntimeArgumentType(state, returned)} StackItem; expected runtime type {expectedRuntimeType}");
    }

    private static VerificationPropertyResult BuildManifestSafeResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.manifest_safe.{method.Name}";
        string description = "Manifest safe=true ABI methods must not mutate state or perform external calls.";
        var counts = CountPaths(execution);
        int obligations = 0;

        foreach (var state in execution.Halted)
        {
            var forbiddenOps = SensitiveOperations(state).OrderBy(op => op.Offset).ToList();
            obligations += forbiddenOps.Count;
            if (forbiddenOps.Count == 0) continue;

            var firstForbidden = forbiddenOps[0];
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"safe=true method reaches {firstForbidden.Display} at 0x{firstForbidden.Offset:X4}.",
                "safe manifest method has no state mutation or external call",
                BuildStateWitness(smtBackend, state));
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
            "safe=true method performs no successful state mutation or external call",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildAccessControlResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.access_control.{method.Name}";
        string description = "Every successful path that reaches a state mutation or external call must execute enforced authorization first.";
        var counts = CountPaths(execution);
        int obligations = 0;

        foreach (var state in execution.Halted)
        {
            var sensitiveOps = SensitiveOperations(state).OrderBy(op => op.Offset).ToList();
            obligations += sensitiveOps.Count;
            if (sensitiveOps.Count == 0) continue;

            foreach (var sensitiveOp in sensitiveOps)
            {
                var authStatus = EvaluateAccessControlAuthBefore(state, sensitiveOp);
                if (authStatus != AccessControlAuthStatus.Authorized)
                {
                    if (IsAuthorizedNep17RecipientBalanceCredit(manifest, method, state, sensitiveOp))
                        continue;
                    if (IsAuthorizedNep11DivisibleBalanceMutation(manifest, method, state, sensitiveOp))
                        continue;
                    if (IsAuthorizedNep11OwnerTransfer(manifest, method, state, sensitiveOp))
                        continue;
                    if (IsAuthorizedNep11OwnerBalanceMutation(manifest, method, state, sensitiveOp))
                        continue;

                    string reason = authStatus switch
                    {
                        AccessControlAuthStatus.UnboundSignatureMessage =>
                            $"signature authorization before {sensitiveOp.Display} at 0x{sensitiveOp.Offset:X4} does not bind its message to the sensitive operation.",
                        AccessControlAuthStatus.UnrelatedDynamicWitness =>
                            $"dynamic authorization principal before {sensitiveOp.Display} at 0x{sensitiveOp.Offset:X4} is unrelated to the sensitive operation.",
                        _ =>
                            $"{sensitiveOp.Display} at 0x{sensitiveOp.Offset:X4} executes before an enforced authorization check.",
                    };
                    string failedCondition = authStatus switch
                    {
                        AccessControlAuthStatus.UnboundSignatureMessage =>
                            "signature message bound to sensitive operation",
                        AccessControlAuthStatus.UnrelatedDynamicWitness =>
                            "authorized principal related to sensitive operation",
                        _ =>
                            "auth before sensitive state mutation or external call",
                    };
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        reason,
                        failedCondition,
                        BuildStateWitness(smtBackend, state));
                }
            }
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
                ? "property holds vacuously: no successful path reached a state mutation or external call"
                : "every successful sensitive operation is preceded by enforced authorization",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildExternalReturnResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        string id = $"security.external_returns.{method.Name}";
        string description = "Every successful path must check each external call return value before continuing.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int voidReceiverCallbacks = 0;
        var voidReceiverCallbackSurfaceReasons = new List<string>();

        foreach (var state in execution.Halted)
        {
            foreach (var call in state.Telemetry.ExternalCalls.Where(c => c.HasReturnValue && !c.ModeledSelfCall))
            {
                obligations++;
                if (IsStandardReceiverCallbackVoidCall(manifest, method, call))
                {
                    voidReceiverCallbacks++;
                    var surfaceReasons = ExternalCallCompletenessReasons(
                            state,
                            call,
                            dependencyProofs,
                            requireExternalSmtDependencyProofs)
                        .ToList();
                    if (surfaceReasons.Count > 0)
                    {
                        voidReceiverCallbackSurfaceReasons.AddRange(surfaceReasons.Select(
                            reason => $"standard receiver callback {call.Method} at 0x{call.Offset:X4} can be treated as Void only after its target contract proof surface is closed: {reason}"));
                    }

                    continue;
                }

                if (!call.ReturnChecked)
                {
                    string target = string.IsNullOrWhiteSpace(call.Method) ? "<dynamic>" : call.Method;
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"external call return from {target} at 0x{call.Offset:X4} is not checked by ASSERT, comparison, or branch.",
                        "external call return value checked",
                        BuildStateWitness(smtBackend, state));
                }

                if (ExternalReturnKnownFalseOnPath(state, call)
                    && PathMayReportSuccess(method, state, smtBackend, out var successReason))
                {
                    string target = string.IsNullOrWhiteSpace(call.Method) ? "<dynamic>" : call.Method;
                    string reason = $"external call return from {target} at 0x{call.Offset:X4} can be false while the path still reports success";
                    if (!string.IsNullOrWhiteSpace(successReason))
                        reason += $": {successReason}";
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        reason,
                        "external call false return cannot reach a successful result",
                        BuildStateWitness(smtBackend, state));
                }
            }
        }

        if (voidReceiverCallbackSurfaceReasons.Count > 0)
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
                string.Join("; ", voidReceiverCallbackSurfaceReasons.Distinct(StringComparer.Ordinal)),
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
                ? "property holds vacuously: no successful path returned from an external call"
                : voidReceiverCallbacks > 0
                    ? "all non-void external-call returns are checked; standard receiver callbacks are Void and fail by FAULT/ABORT, not by returning false"
                : "all successful external-call returns are checked",
            FailedCondition: null,
            Counterexample: null);
    }

    private static bool ExternalReturnKnownFalseOnPath(ExecutionState state, ExternalCall call)
    {
        string symbolName = ExternalReturnSymbolName(call);
        return state.PathConditions.Any(condition => ExpressionRequiresExternalReturnFalse(condition, symbolName));
    }

    private static string ExternalReturnSymbolName(ExternalCall call) =>
        $"ext_ret_{call.Offset}";

    private static bool ExpressionRequiresExternalReturnFalse(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionRequiresExternalReturnFalse(binary.Left, symbolName)
                || ExpressionRequiresExternalReturnFalse(binary.Right, symbolName),
            UnaryExpr { Op: "not", Operand: var operand } =>
                ExpressionRequiresExternalReturnTrue(operand, symbolName),
            BinaryExpr { Op: "==", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: false, allowNumeric: false),
            BinaryExpr { Op: "num==", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: false, allowNumeric: true),
            BinaryExpr { Op: "!=", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: true, allowNumeric: false),
            BinaryExpr { Op: "num!=", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: true, allowNumeric: true),
            _ => false,
        };

    private static bool ExpressionRequiresExternalReturnTrue(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and" } binary =>
                ExpressionRequiresExternalReturnTrue(binary.Left, symbolName)
                || ExpressionRequiresExternalReturnTrue(binary.Right, symbolName),
            Symbol { Name: var name } =>
                string.Equals(name, symbolName, StringComparison.Ordinal),
            UnaryExpr { Op: "tobool" or "nz", Operand: var operand } =>
                ExpressionReferencesSymbol(operand, symbolName),
            BinaryExpr { Op: "==", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: true, allowNumeric: false),
            BinaryExpr { Op: "num==", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: true, allowNumeric: true),
            BinaryExpr { Op: "!=", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: false, allowNumeric: false),
            BinaryExpr { Op: "num!=", Left: var left, Right: var right } =>
                ExternalReturnEqualsBool(left, right, symbolName, expected: false, allowNumeric: true),
            _ => false,
        };

    private static bool ExpressionRequiresExternalReturnInteger(Expression condition, string symbolName) =>
        condition switch
        {
            BinaryExpr { Op: "and" or "or" } binary =>
                ExpressionRequiresExternalReturnInteger(binary.Left, symbolName)
                || ExpressionRequiresExternalReturnInteger(binary.Right, symbolName),
            UnaryExpr { Op: "not", Operand: var operand } =>
                ExpressionRequiresExternalReturnInteger(operand, symbolName),
            BinaryExpr { Op: var op, Left: var left, Right: var right } when IsNeoVmIntegerBinaryOperation(op) =>
                ExpressionIsExternalReturnIntegerSource(left, symbolName)
                || ExpressionIsExternalReturnIntegerSource(right, symbolName),
            TernaryExpr { Op: var op, A: var first, B: var second, C: var third } when IsNeoVmIntegerTernaryOperation(op) =>
                ExpressionIsExternalReturnIntegerSource(first, symbolName)
                || ExpressionIsExternalReturnIntegerSource(second, symbolName)
                || ExpressionIsExternalReturnIntegerSource(third, symbolName),
            UnaryExpr { Op: var op, Operand: var operand } when IsNeoVmIntegerUnaryOperation(op) =>
                ExpressionIsExternalReturnIntegerSource(operand, symbolName),
            BinaryExpr { Left: var left, Right: var right } =>
                ExpressionRequiresExternalReturnInteger(left, symbolName)
                || ExpressionRequiresExternalReturnInteger(right, symbolName),
            TernaryExpr { A: var first, B: var second, C: var third } =>
                ExpressionRequiresExternalReturnInteger(first, symbolName)
                || ExpressionRequiresExternalReturnInteger(second, symbolName)
                || ExpressionRequiresExternalReturnInteger(third, symbolName),
            _ => false,
        };

    private static bool ExpressionIsExternalReturnIntegerSource(Expression expression, string symbolName) =>
        expression switch
        {
            Symbol { Name: var name } =>
                string.Equals(name, symbolName, StringComparison.Ordinal),
            UnaryExpr { Op: var op, Operand: var operand } when IsNeoVmIntegerUnaryOperation(op) =>
                ExpressionIsExternalReturnIntegerSource(operand, symbolName),
            BinaryExpr { Op: var op, Left: var left, Right: var right } when IsNeoVmIntegerBinaryOperation(op) =>
                ExpressionIsExternalReturnIntegerSource(left, symbolName)
                || ExpressionIsExternalReturnIntegerSource(right, symbolName),
            TernaryExpr { Op: var op, A: var first, B: var second, C: var third } when IsNeoVmIntegerTernaryOperation(op) =>
                ExpressionIsExternalReturnIntegerSource(first, symbolName)
                || ExpressionIsExternalReturnIntegerSource(second, symbolName)
                || ExpressionIsExternalReturnIntegerSource(third, symbolName),
            _ => false,
        };

    private static bool IsNeoVmIntegerUnaryOperation(string op) =>
        op is "nz" or "neg" or "abs" or "sign" or "sqrt" or "~";

    private static bool IsNeoVmIntegerBinaryOperation(string op) =>
        op is "+" or "-" or "*" or "/" or "%" or "pow"
            or "<<" or ">>" or "&" or "|" or "^"
            or "<" or "<=" or ">" or ">="
            or "num==" or "num!="
            or "min" or "max";

    private static bool IsNeoVmIntegerTernaryOperation(string op) =>
        op is "within" or "modmul" or "modpow";

    private static bool ExternalReturnEqualsBool(
        Expression left,
        Expression right,
        string symbolName,
        bool expected,
        bool allowNumeric) =>
        ExpressionIsExternalReturnValue(left, symbolName)
        && ExpressionIsBoolLiteral(right, expected, allowNumeric)
        || ExpressionIsExternalReturnValue(right, symbolName)
        && ExpressionIsBoolLiteral(left, expected, allowNumeric);

    private static bool ExpressionIsExternalReturnValue(Expression expression, string symbolName) =>
        IsSymbol(expression, symbolName)
        || expression is UnaryExpr { Op: "tobool" or "nz", Operand: var operand }
        && ExpressionReferencesSymbol(operand, symbolName);

    private static bool ExpressionIsBoolLiteral(Expression expression, bool expected, bool allowNumeric) =>
        expression is BoolConst b
            ? b.Value == expected
            : allowNumeric
            && Expr.ConcreteInt(expression) is { } value
            && (expected ? value.IsOne : value.IsZero);

    private static bool ExpressionReferencesSymbol(Expression expression, string symbolName) =>
        expression.FreeSymbols().Any(symbol => string.Equals(symbol, symbolName, StringComparison.Ordinal));

    private static bool PathMayReportSuccess(
        ContractMethodDescriptor method,
        ExecutionState state,
        ISmtBackend? smtBackend,
        out string reason)
    {
        reason = "";
        if (!string.Equals(method.ReturnType, "Boolean", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!TryReturnMayBeTrue(method, state, smtBackend, out bool mayBeTrue, out reason))
            return mayBeTrue;
        return mayBeTrue;
    }

    private static VerificationPropertyResult BuildManifestCallPermissionsResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.manifest_call_permissions.{method.Name}";
        string description = "Every reachable external contract call must be covered by manifest.permissions.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        foreach (var state in execution.FinalStates)
        {
            foreach (var call in state.Telemetry.ExternalCalls.Where(c => !c.ModeledSelfCall).OrderBy(c => c.Offset))
            {
                obligations++;
                var permission = EvaluateManifestCallPermission(manifest, state, call);
                switch (permission.Status)
                {
                    case ManifestCallPermissionStatus.Allowed:
                        continue;
                    case ManifestCallPermissionStatus.Incomplete:
                        incompleteReasons.Add(permission.Reason);
                        continue;
                    case ManifestCallPermissionStatus.Denied:
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            permission.Reason,
                            "external call target and method are allowed by manifest.permissions",
                            BuildStateWitness(smtBackend, state));
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
                ? "property holds vacuously: no reachable path reached an external contract call"
                : "every reachable external contract call is covered by manifest.permissions",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildArithmeticSafetyResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.arithmetic.{method.Name}";
        string description = "Every successful path must avoid unchecked overflow and divide-by-zero arithmetic hazards.";
        var counts = CountPaths(execution);
        int obligations = 0;

        foreach (var state in execution.Halted)
        {
            foreach (var op in state.Telemetry.ArithmeticOps)
            {
                if (IsExpectedNep17BalanceDeltaArithmetic(manifest, method, state, op))
                    continue;

                obligations++;
                if (!op.Checked && (op.OverflowPossible || op.DivisorMaybeZero))
                {
                    string hazard = op.DivisorMaybeZero ? "possible divide by zero" : "possible overflow";
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"{op.Operation} at 0x{op.Offset:X4} has {hazard} on a successful path.",
                        "checked arithmetic safety",
                        BuildStateWitness(smtBackend, state));
                }
            }
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
                ? "property holds vacuously: no successful path performed modeled arithmetic"
                : "no successful path reached unchecked arithmetic hazards",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildVmFaultFreedomResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs,
        ImmutableArray<byte> currentScriptHash)
    {
        string id = $"security.vm_fault_free.{method.Name}";
        string description = "Every ABI entrypoint path must avoid reachable NeoVM and syscall faults.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var unknownReasons = new List<string>();
        var incompleteReasons = new List<string>();
        bool usedTokenStorageIntegerInvariant = false;
        var externalCallAssumptions = ImmutableArray.CreateBuilder<VerificationAssumption>();
        var profileProperty = new VerificationProperty(
            id,
            method.Name,
            description,
            ForbidFaults: true,
            Requires: ImmutableArray<VerificationCondition>.Empty,
            Ensures: ImmutableArray<VerificationCondition>.Empty);

        foreach (var state in execution.Faulted)
        {
            if (IsExplicitProfileRejectionFault(state))
                continue;

            var profileRequires = ProfileStorageIntegerEncodingRequires(manifest, method, state);
            usedTokenStorageIntegerInvariant |= profileRequires.Length > 0;
            var assumptions = NepTokenStorageIntegerEncodingAssumptions(usedTokenStorageIntegerInvariant);
            obligations++;
            var faultQuery = BuildReachabilityQuery(profileRequires, state.PathConditions);
            var faultOutcome = smtBackend?.IsSatisfiable(faultQuery) ?? SmtOutcome.Unknown;
            if (faultOutcome == SmtOutcome.Sat)
            {
                var witness = smtBackend?.BuildWitness(faultQuery);
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"faulted path is reachable: {state.TerminationReason ?? "VM fault"}",
                    "no VM or syscall fault is reachable",
                    witness is null ? null : ImmutableDictionary.CreateRange(witness),
                    Assumptions: assumptions);
            }

            if (faultOutcome == SmtOutcome.Unknown)
                unknownReasons.Add(
                    $"solver returned unknown for fault reachability: {state.TerminationReason ?? "VM fault"}");
        }

        foreach (var state in execution.Halted)
        {
            var profileRequires = ProfileStorageIntegerEncodingRequires(manifest, method, state);
            usedTokenStorageIntegerInvariant |= profileRequires.Length > 0;
            var assumptions = NepTokenStorageIntegerEncodingAssumptions(usedTokenStorageIntegerInvariant);
            if (CheckFaultPreconditions(
                    profileProperty,
                    state,
                    profileRequires,
                    smtBackend,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    ref obligations,
                    unknownReasons,
                    skipFaultCondition: null,
                    assumptions) is { } syscallFault)
            {
                return syscallFault;
            }

            // Review fix (#4): Neo's ApplicationEngine.RuntimeNotify faults (InvalidOperationException)
            // when an emitted event is not declared in the manifest ABI, or its argument count/type
            // does not match the declared event signature. The engine's Notify handler records the
            // notification telemetry but does not model that fault, so without this check
            // security.vm_fault_free could be Proved for a method that always faults at Runtime.Notify.
            // CheckRuntimeNotificationManifest validates emitted notifications against the declared ABI
            // (Violated on a concrete undeclared event / arg-count / arg-type mismatch; Incomplete when
            // the event name or arguments are symbolic).
            if (CheckRuntimeNotificationManifest(
                    manifest,
                    profileProperty,
                    state,
                    currentScriptHash,
                    profileRequires,
                    smtBackend,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    ref obligations,
                    unknownReasons,
                    incompleteReasons) is { } notificationFault)
            {
                return notificationFault;
            }

            incompleteReasons.AddRange(ProfileExternalCallCompletenessReasons(
                manifest,
                method,
                state,
                dependencyProofs,
                requireExternalSmtDependencyProofs));
            externalCallAssumptions.AddRange(ProfileExternalCallCompletenessAssumptions(
                state,
                dependencyProofs,
                requireExternalSmtDependencyProofs));
        }

        incompleteReasons.AddRange(IncompleteReasons(execution));
        var proofAssumptions = CombineAssumptions(
            NepTokenStorageIntegerEncodingAssumptions(usedTokenStorageIntegerInvariant),
            externalCallAssumptions.ToImmutable());
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
                Counterexample: null,
                Assumptions: proofAssumptions);
        }

        if (unknownReasons.Count > 0 || smtBackend is null)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Unknown,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                smtBackend is null
                    ? "no SMT backend was provided"
                    : string.Join("; ", unknownReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null,
                Assumptions: proofAssumptions);
        }
        if (BuildNoSuccessfulHaltIncompleteResult(
                id,
                method.Name,
                description,
                execution,
                obligations,
                proofAssumptions) is { } noHalt)
        {
            return noHalt;
        }

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
                ? "no explored path reached modeled VM/syscall fault preconditions"
                : usedTokenStorageIntegerInvariant
                    ? "all reachable VM/syscall fault preconditions were proven unsatisfiable under the NEP token storage integer encoding invariant"
                    : "all reachable VM/syscall fault preconditions were proven unsatisfiable",
            FailedCondition: null,
            Counterexample: null,
            Assumptions: proofAssumptions);
    }

    private static VerificationPropertyResult BuildVmSurfaceResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs)
    {
        string id = $"security.vm_surface.{method.Name}";
        string description = "The proof must not rely on unknown VM opcodes, unknown syscalls, truncated states, or stopped paths.";
        var counts = CountPaths(execution);
        var reasons = IncompleteReasons(execution).ToList();
        var assumptions = ImmutableArray.CreateBuilder<VerificationAssumption>();

        foreach (var state in execution.FinalStates)
        {
            if (state.Telemetry.UnknownOpcodes.Count > 0)
                reasons.Add("unknown opcode at " + string.Join(", ", state.Telemetry.UnknownOpcodes.Select(FormatOffset)));
            if (state.Telemetry.UnknownSyscalls.Count > 0)
                reasons.Add("unknown syscall at " + string.Join(", ", state.Telemetry.UnknownSyscalls.Select(FormatOffset)));
            if (state.Telemetry.Truncated)
                reasons.Add("state telemetry was truncated");
            reasons.AddRange(ProfileExternalCallCompletenessReasons(
                manifest,
                method,
                state,
                dependencyProofs,
                requireExternalSmtDependencyProofs));
            assumptions.AddRange(ProfileExternalCallCompletenessAssumptions(
                state,
                dependencyProofs,
                requireExternalSmtDependencyProofs));
        }

        var resultAssumptions = assumptions
            .Distinct()
            .ToImmutableArray();

        if (reasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                counts.CheckedPaths,
                string.Join("; ", reasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null,
                Assumptions: resultAssumptions);
        }
        if (BuildNoSuccessfulHaltIncompleteResult(
                id,
                method.Name,
                description,
                execution,
                counts.CheckedPaths,
                resultAssumptions) is { } noHalt)
        {
            return noHalt;
        }

        return new VerificationPropertyResult(
            id,
            method.Name,
            description,
            VerificationStatus.Proved,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            counts.CheckedPaths,
            "all explored paths stayed within modeled Neo VM/syscall surface and reached terminal verdicts",
            FailedCondition: null,
            Counterexample: null,
            Assumptions: resultAssumptions);
    }
}
