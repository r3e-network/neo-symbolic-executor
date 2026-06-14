using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    private static VerificationPropertyResult BuildNep11SymbolValueResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options) =>
        BuildTokenSymbolValueResult(
            manifest,
            program,
            options,
            standardId: "nep11",
            standardName: "NEP-11");

    private static VerificationPropertyResult BuildNep11AbiResult(ContractManifest manifest)
    {
        const string id = "security.nep11.abi.*";
        const string method = "*";
        const string description = "Contracts declaring NEP-11 must expose the standard NFT ABI methods and Transfer event shape.";
        int obligations = 8;

        if (FindAbiMethod(manifest, "symbol", IsStringSafeNoParameterMethod) is null)
        {
            if (FindAbiMethod(manifest, "symbol") is null)
                return Violated("NEP-11 manifest is missing method symbol.", "NEP-11 ABI declares symbol()");
            return Violated("NEP-11 method symbol must be safe=true with no parameters and String return type.",
                "symbol(): String safe=true");
        }

        if (FindAbiMethod(manifest, "decimals", IsIntegerSafeNoParameterMethod) is null)
        {
            if (FindAbiMethod(manifest, "decimals") is null)
                return Violated("NEP-11 manifest is missing method decimals.", "NEP-11 ABI declares decimals()");
            return Violated("NEP-11 method decimals must be safe=true with no parameters and Integer return type.",
                "decimals(): Integer safe=true");
        }

        if (FindAbiMethod(manifest, "totalSupply", IsIntegerSafeNoParameterMethod) is null)
        {
            if (FindAbiMethod(manifest, "totalSupply") is null)
                return Violated("NEP-11 manifest is missing method totalSupply.", "NEP-11 ABI declares totalSupply()");
            return Violated("NEP-11 method totalSupply must be safe=true with no parameters and Integer return type.",
                "totalSupply(): Integer safe=true");
        }

        if (FindAbiMethod(manifest, "ownerOf") is null)
            return Violated("NEP-11 manifest is missing method ownerOf.", "NEP-11 ABI declares ownerOf(tokenId)");
        if (FindAbiMethod(manifest, "balanceOf") is null)
            return Violated("NEP-11 manifest is missing method balanceOf.", "NEP-11 ABI declares balanceOf(owner[,tokenId])");

        if (FindAbiMethod(manifest, "tokensOf", IsNep11TokensOfMethod) is null)
        {
            if (FindAbiMethod(manifest, "tokensOf") is null)
                return Violated("NEP-11 manifest is missing method tokensOf.", "NEP-11 ABI declares tokensOf(owner)");
            return Violated("NEP-11 method tokensOf must be safe=true with (Hash160 owner) and InteropInterface return type.",
                "tokensOf(Hash160 owner): InteropInterface safe=true");
        }

        if (FindAbiMethod(manifest, "properties") is not null)
        {
            obligations++;
            if (FindAbiMethod(manifest, "properties", IsNep11PropertiesMethod) is null)
            {
                return Violated("NEP-11 optional method properties must be safe=true with a ByteString-compatible tokenId and Map return type when declared.",
                    "properties(ByteString source tokenId / ByteArray manifest tokenId): Map safe=true");
            }
        }

        if (FindAbiMethod(manifest, "tokens") is not null)
        {
            obligations++;
            if (FindAbiMethod(manifest, "tokens", IsNep11TokensMethod) is null)
            {
                return Violated("NEP-11 optional method tokens must be safe=true with no parameters and InteropInterface return type when declared.",
                    "tokens(): InteropInterface safe=true");
            }
        }

        if (FindAbiMethod(manifest, "transfer") is null)
            return Violated("NEP-11 manifest is missing method transfer.", "NEP-11 ABI declares transfer(...)");

        bool nonDivisible =
            FindAbiMethod(manifest, "balanceOf", IsNep11NonDivisibleBalanceOfMethod) is not null
            && FindAbiMethod(manifest, "ownerOf", IsNep11NonDivisibleOwnerOfMethod) is not null
            && FindAbiMethod(manifest, "transfer", IsNep11NonDivisibleTransferMethodShape) is not null;
        bool divisible =
            FindAbiMethod(manifest, "balanceOf", IsNep11DivisibleBalanceOfMethod) is not null
            && FindAbiMethod(manifest, "ownerOf", IsNep11DivisibleOwnerOfMethod) is not null
            && FindAbiMethod(manifest, "transfer", IsNep11DivisibleTransferMethodShape) is not null;
        if (!nonDivisible && !divisible)
        {
            return Violated(
                "NEP-11 manifest must match either the non-divisible ABI (balanceOf(owner), ownerOf(tokenId): Hash160, transfer(to,tokenId,data)) or the divisible ABI (balanceOf(owner,tokenId), ownerOf(tokenId): InteropInterface, transfer(from,to,amount,tokenId,data)).",
                "NEP-11 ABI matches non-divisible or divisible NFT method shape");
        }

        var transferEvent = manifest.Abi.Events.FirstOrDefault(
            e => string.Equals(e.Name, "Transfer", StringComparison.Ordinal));
        if (transferEvent is null)
            return Violated("NEP-11 manifest is missing Transfer event.", "NEP-11 ABI declares Transfer event");
        if (transferEvent.Parameters.Count != 4
            || !HasStandardParameter(transferEvent.Parameters, 0, "from", IsStrictHash160)
            || !HasStandardParameter(transferEvent.Parameters, 1, "to", IsStrictHash160)
            || !HasStandardParameter(transferEvent.Parameters, 2, "amount", type => IsType(type, "Integer"))
            || !HasStandardParameter(transferEvent.Parameters, 3, "tokenId", IsByteStringLike))
        {
            return Violated("NEP-11 Transfer event must declare exactly standard parameters (Hash160 from, Hash160 to, Integer amount, ByteString-compatible tokenId).",
                "Transfer(Hash160 from, Hash160 to, Integer amount, ByteString source tokenId / ByteArray manifest tokenId)");
        }

        bool usesManifestByteArrayTokenId = UsesManifestByteArrayTokenIdAbi(manifest);
        string csharpByteArrayNote = usesManifestByteArrayTokenId
            ? "; tokenId ABI fields use ByteArray, accepted for Neo N3 C# manifest compatibility with source-level ByteString token IDs"
            : "";

        return new VerificationPropertyResult(
            id,
            method,
            description,
            VerificationStatus.Proved,
            CheckedPaths: 0,
            IgnoredFaultedPaths: 0,
            StoppedPaths: 0,
            ObligationsChecked: obligations,
            Reason: nonDivisible
                ? "NEP-11 manifest exposes the required non-divisible methods, optional metadata methods when declared, safe flags, return types, and Transfer event shape" + csharpByteArrayNote
                : "NEP-11 manifest exposes the required divisible methods, optional metadata methods when declared, safe flags, return types, and Transfer event shape" + csharpByteArrayNote,
            FailedCondition: null,
            Counterexample: null);

        VerificationPropertyResult Violated(string reason, string failedCondition) =>
            new(
                id,
                method,
                description,
                VerificationStatus.Violated,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: obligations,
                Reason: reason,
                FailedCondition: failedCondition,
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11IteratorReturnResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options)
    {
        const string id = "security.nep11.iterator_returns.*";
        const string method = "*";
        const string description = "NEP-11 iterator ABI methods must return InteropInterface iterator values at runtime.";
        int obligations = 0;
        var incompleteReasons = new List<string>();

        var methods = new List<(ContractMethodDescriptor? Method, string DisplayName)>
        {
            (FindAbiMethod(manifest, "tokensOf", IsNep11TokensOfMethod), "tokensOf(owner)"),
        };
        if (FindAbiMethod(manifest, "tokens") is not null)
            methods.Add((FindAbiMethod(manifest, "tokens", IsNep11TokensMethod), "tokens()"));
        if (FindAbiMethod(manifest, "ownerOf", IsNep11DivisibleOwnerOfMethod) is { } divisibleOwnerOf)
            methods.Add((divisibleOwnerOf, "ownerOf(tokenId)"));

        if (methods.Any(entry => entry.Method is null))
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
                Reason: "NEP-11 ABI iterator methods must be valid before runtime iterator return checking",
                FailedCondition: null,
                Counterexample: null);
        }

        int checkedPaths = 0;
        int ignoredFaulted = 0;
        int stopped = 0;
        foreach (var (iteratorMethod, displayName) in methods.Select(entry => (entry.Method!, entry.DisplayName)))
        {
            var execution = RunMethodEntry(program, options, iteratorMethod);
            checkedPaths += execution.FinalStates.Count(s => s.Status == TerminalStatus.Halted);
            ignoredFaulted += execution.FinalStates.Count(s => s.Status == TerminalStatus.Faulted);
            stopped += execution.FinalStates.Count(s => s.Status == TerminalStatus.Stopped);
            foreach (var reason in IncompleteReasons(execution))
                incompleteReasons.Add($"{displayName}: {reason}");

            var halted = execution.Halted.ToList();
            if (halted.Count == 0)
            {
                incompleteReasons.Add($"{displayName} produced no successful HALT path");
                continue;
            }

            foreach (var state in halted)
            {
                obligations++;
                if (state.EvaluationStack.Count == 0)
                {
                    return Violated(
                        $"{displayName} halts without returning an InteropInterface iterator.",
                        $"{displayName}: InteropInterface runtime return");
                }

                var returned = state.Peek();
                if (returned.Sort != Sort.InteropInterface)
                {
                    return Violated(
                        $"{displayName} returns {DescribeRuntimeArgumentType(returned)} instead of an InteropInterface iterator.",
                        $"{displayName}: InteropInterface runtime return");
                }

                var iteratorReturn = ClassifyIteratorReturn(state, returned, out string interopDescription);
                if (iteratorReturn == IteratorReturnClassification.KnownNonIterator)
                {
                    return Violated(
                        $"{displayName} returns {interopDescription} instead of a Neo iterator InteropInterface.",
                        $"{displayName}: Neo iterator runtime return");
                }

                if (iteratorReturn == IteratorReturnClassification.Unknown)
                {
                    incompleteReasons.Add(
                        $"{displayName} returns {interopDescription}; the verifier cannot prove it is a Neo iterator");
                }

                if (string.Equals(displayName, "tokensOf(owner)", StringComparison.Ordinal)
                    || string.Equals(displayName, "tokens()", StringComparison.Ordinal)
                    || string.Equals(displayName, "ownerOf(tokenId)", StringComparison.Ordinal))
                {
                    bool validShape;
                    string? violationReason;
                    string? failedCondition;
                    string? incompleteReason;
                    if (string.Equals(displayName, "tokensOf(owner)", StringComparison.Ordinal))
                    {
                        validShape = TryValidateNep11TokensOfIteratorShape(
                            iteratorMethod,
                            state,
                            returned,
                            out violationReason,
                            out failedCondition,
                            out incompleteReason);
                    }
                    else if (string.Equals(displayName, "tokens()", StringComparison.Ordinal))
                    {
                        validShape = TryValidateNep11TokensIteratorShape(
                            state,
                            returned,
                            out violationReason,
                            out failedCondition,
                            out incompleteReason);
                    }
                    else
                    {
                        validShape = TryValidateNep11DivisibleOwnerOfIteratorShape(
                            iteratorMethod,
                            state,
                            returned,
                            out violationReason,
                            out failedCondition,
                            out incompleteReason);
                    }

                    if (validShape)
                    {
                        continue;
                    }

                    if (violationReason is not null)
                        return Violated(violationReason, failedCondition!);

                    incompleteReasons.Add(incompleteReason!);
                }
            }
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                method,
                description,
                VerificationStatus.Incomplete,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }

        return new VerificationPropertyResult(
            id,
            method,
            description,
            VerificationStatus.Proved,
            checkedPaths,
            ignoredFaulted,
            stopped,
            obligations,
            "NEP-11 iterator ABI methods return Neo iterator InteropInterface values on every successful HALT path",
            FailedCondition: null,
            Counterexample: null);

        VerificationPropertyResult Violated(string reason, string failedCondition) =>
            new(
                id,
                method,
                description,
                VerificationStatus.Violated,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                reason,
                failedCondition,
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DecimalsConsistencyResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.decimals_consistency.decimals";
        const string methodName = "decimals";
        const string description = "NEP-11 decimals() must match the declared non-divisible or divisible NFT ABI shape.";
        const string nonDivisibleFailedCondition = "non-divisible NEP-11 decimals() == 0";
        const string divisibleFailedCondition = "divisible NEP-11 decimals() != 0";

        if (FindAbiMethod(manifest, methodName, IsIntegerSafeNoParameterMethod) is not { } decimals)
        {
            return Incomplete(
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                "NEP-11 manifest has no proof-grade decimals(): Integer safe=true method to check consistency",
                MethodOffset: null);
        }

        bool nonDivisible =
            FindAbiMethod(manifest, "balanceOf", IsNep11NonDivisibleBalanceOfMethod) is not null
            && FindAbiMethod(manifest, "ownerOf", IsNep11NonDivisibleOwnerOfMethod) is not null
            && FindAbiMethod(manifest, "transfer", IsNep11NonDivisibleTransferMethodShape) is not null;
        bool divisible =
            FindAbiMethod(manifest, "balanceOf", IsNep11DivisibleBalanceOfMethod) is not null
            && FindAbiMethod(manifest, "ownerOf", IsNep11DivisibleOwnerOfMethod) is not null
            && FindAbiMethod(manifest, "transfer", IsNep11DivisibleTransferMethodShape) is not null;

        if (nonDivisible == divisible)
        {
            string reason = nonDivisible
                ? "NEP-11 manifest exposes both non-divisible and divisible method shapes; decimals() consistency cannot choose one proof profile"
                : "NEP-11 manifest does not match a complete non-divisible or divisible method shape; decimals() consistency depends on the ABI-shape proof";
            return Incomplete(
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                reason,
                MethodOffset: decimals.Offset);
        }

        if (decimals.Offset < 0 || decimals.Offset >= program.Bytes.Length)
        {
            return Incomplete(
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                $"decimals() offset {decimals.Offset} is outside script bytes",
                MethodOffset: decimals.Offset);
        }

        var execution = RunMethodEntry(program, options, decimals);
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = IncompleteReasons(execution)
            .Select(reason => "decimals(): " + reason)
            .ToList();
        var halted = execution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("decimals() produced no successful HALT path");

        foreach (var state in halted)
        {
            obligations++;
            string failedCondition = nonDivisible
                ? nonDivisibleFailedCondition
                : divisibleFailedCondition;
            if (state.EvaluationStack.Count == 0)
            {
                return Violated(
                    counts,
                    obligations,
                    "decimals() halts without returning an Integer value.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    decimals.Offset);
            }

            var returnValue = state.Peek().Expression;
            if (returnValue.Sort != Sort.Int)
            {
                string kind = nonDivisible ? "non-divisible" : "divisible";
                return Violated(
                    counts,
                    obligations,
                    $"{kind} NEP-11 decimals() returns a {returnValue.Sort} StackItem instead of Integer.",
                    failedCondition,
                    BuildStateWitness(null, state),
                    decimals.Offset);
            }

            var violationCondition = nonDivisible
                ? Expr.NumNe(returnValue, Expr.Int(0))
                : Expr.NumEq(returnValue, Expr.Int(0));

            if (violationCondition is BoolConst { Value: false })
                continue;

            if (violationCondition is BoolConst { Value: true })
            {
                string reason = ConcreteDecimalsViolationReason(nonDivisible, returnValue);
                return Violated(
                    counts,
                    obligations,
                    reason,
                    failedCondition,
                    BuildStateWitness(null, state),
                    decimals.Offset);
            }

            var query = BuildReachabilityQuery(
                ImmutableArray<Expression>.Empty,
                state.PathConditions,
                violationCondition);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Sat)
            {
                string reason = nonDivisible
                    ? "non-divisible NEP-11 decimals() can return a non-zero value."
                    : "divisible NEP-11 decimals() can return 0; divisible NEP-11 decimals() must be non-zero.";
                return Violated(
                    counts,
                    obligations,
                    reason,
                    failedCondition,
                    BuildWitness(smtBackend, query),
                    decimals.Offset);
            }

            if (outcome == SmtOutcome.Unknown)
            {
                incompleteReasons.Add(nonDivisible
                    ? "solver returned unknown while proving non-divisible NEP-11 decimals() == 0"
                    : "solver returned unknown while proving divisible NEP-11 decimals() is non-zero");
            }
        }

        if (incompleteReasons.Count > 0)
        {
            return Incomplete(
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                decimals.Offset);
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
            nonDivisible
                ? "NEP-11 non-divisible decimals() returns 0 on every successful path"
                : "NEP-11 divisible decimals() returns a non-zero value on every successful path",
            FailedCondition: null,
            Counterexample: null,
            MethodOffset: decimals.Offset);

        static string ConcreteDecimalsViolationReason(bool nonDivisible, Expression returnValue)
        {
            var concrete = Expr.ConcreteInt(returnValue);
            string display = concrete is { } value
                ? value.ToString(System.Globalization.CultureInfo.InvariantCulture)
                : "a forbidden value";
            return nonDivisible
                ? $"non-divisible NEP-11 decimals() returns {display} instead of 0."
                : "divisible NEP-11 decimals() returns 0, but divisible NEP-11 decimals() must be non-zero.";
        }

        static VerificationPropertyResult Incomplete(
            int CheckedPaths,
            int IgnoredFaultedPaths,
            int StoppedPaths,
            int ObligationsChecked,
            string Reason,
            int? MethodOffset) =>
            new(
                id,
                methodName,
                description,
                VerificationStatus.Incomplete,
                CheckedPaths,
                IgnoredFaultedPaths,
                StoppedPaths,
                ObligationsChecked,
                Reason,
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: MethodOffset);

        static VerificationPropertyResult Violated(
            (int CheckedPaths, int IgnoredFaultedPaths, int StoppedPaths) Counts,
            int ObligationsChecked,
            string Reason,
            string FailedCondition,
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
                FailedCondition,
                Counterexample,
                MethodOffset: MethodOffset);
    }

    private static VerificationPropertyResult BuildNep11TransferSuccessFeasibilityResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend) =>
        BuildTokenTransferSuccessFeasibilityResult(
            method,
            execution,
            smtBackend,
            standardId: "nep11",
            standardName: "NEP-11");

    private static VerificationPropertyResult BuildNep11DivisibleSenderAuthorizationResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.sender_authorized.{method.Name}";
        string description = "Divisible NEP-11 transfer true-return paths must be authorized by the from account or caller contract.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int fromIndex = FindFromParameter(method);
        var incompleteReasons = new List<string>();
        if (fromIndex < 0)
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
                "divisible NEP-11 transfer method has no recognizable from Hash160 parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
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

            if (!HasEnforcedWitnessForSymbol(state, fromSymbol)
                && !PathConditionsProveCallerHashEqualsSymbol(state.PathConditions, fromSymbol))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without proving Runtime.CallingScriptHash == from or enforcing CheckWitness(from).",
                    "from argument authorized before true-return divisible NEP-11 transfer",
                    BuildStateWitness(smtBackend, state));
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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every true-return divisible NEP-11 transfer path is authorized by Runtime.CallingScriptHash == from or enforced CheckWitness(from)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11LifecycleZeroAddressResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep11MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string label = isMint ? "to" : "from";
        string id = $"security.nep11.lifecycle_zero_address.{method.Name}";
        string description = $"NEP-11 {lifecycle} paths that mutate totalSupply() must reject UInt160.Zero {label} accounts.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

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
                "NEP-11 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
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

        int accountIndex = isMint ? FindToParameter(method) : FindFromParameter(method);
        if (accountIndex < 0)
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
                $"NEP-11 {lifecycle} method has no recognizable {label} Hash160 parameter",
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

        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, execution, obligations) is { } noHalt)
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

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool pathMutatesSupply = false;
            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                if (!TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                        incompleteReasons.Add($"successful NEP-11 {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                pathMutatesSupply = true;
                break;
            }

            if (!pathMutatesSupply)
                continue;

            obligations++;
            if (PathConditionsExcludeHash160Zero(state.PathConditions, accountSymbol))
                continue;

            var query = BuildTrueReturnReachabilityQuery(
                method,
                state,
                Expr.Eq(Hash160NumericExpression(accountSymbol), Expr.Int(0)));
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Unsat)
                continue;

            string zeroCondition = $"{label} != UInt160.Zero before {lifecycle}";
            if (outcome == SmtOutcome.Sat)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"NEP-11 {lifecycle} can mutate totalSupply() with {label} == UInt160.Zero.",
                    zeroCondition,
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
                $"solver could not prove {label} is non-zero on a successful NEP-11 {lifecycle} path that mutates totalSupply()",
                zeroCondition,
                BuildWitness(smtBackend, query));
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
                ? $"property holds vacuously: no successful NEP-11 {lifecycle} path mutates totalSupply() storage"
                : $"every successful NEP-11 {lifecycle} path that mutates totalSupply() proves {label} is not UInt160.Zero",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11LifecycleBalanceResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep11MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string accountLabel = isMint ? "recipient" : "sender";
        string id = $"security.nep11.lifecycle_balance.{method.Name}";
        string description = $"NEP-11 {lifecycle} paths that mutate totalSupply() must maintain balanceOf(owner) storage.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

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
                "NEP-11 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
                FailedCondition: null,
                Counterexample: null);
        }

        var divisibleBalanceOf = FindAbiMethod(manifest, "balanceOf", IsNep11DivisibleBalanceOfMethod);
        var nonDivisibleBalanceOf = FindAbiMethod(manifest, "balanceOf", IsNep11NonDivisibleBalanceOfMethod);
        bool isDivisible = divisibleBalanceOf is not null;
        var balanceOf = divisibleBalanceOf ?? nonDivisibleBalanceOf;
        if (balanceOf is null)
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
                "NEP-11 manifest has no balanceOf(owner) or balanceOf(owner, tokenId) method to infer lifecycle balance storage keys from",
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

        if (balanceOf.Offset < 0 || balanceOf.Offset >= program.Bytes.Length)
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
                $"balanceOf offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        int accountIndex = isMint ? FindToParameter(method) : FindFromParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        int amountIndex = FindAmountParameter(method);
        if (accountIndex < 0 || tokenIdIndex < 0 || (isDivisible && amountIndex < 0))
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
                $"NEP-11 {lifecycle} method has no recognizable {(isMint ? "to" : "from")} Hash160, {(isDivisible ? "amount Integer, " : "")}and tokenId ByteString parameters",
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

        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, execution, obligations) is { } noHalt)
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

        var balanceExecution = RunMethodEntry(program, options, balanceOf);
        foreach (var reason in IncompleteReasons(balanceExecution))
            incompleteReasons.Add("balanceOf: " + reason);

        var balancePatterns = isDivisible
            ? InferDivisibleBalanceOfStorageKeyPatterns(balanceOf, balanceExecution, incompleteReasons)
            : InferBalanceOfStorageKeyPatterns(balanceOf, balanceExecution, incompleteReasons);
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

        if (balancePatterns.IsDefaultOrEmpty)
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
                isDivisible
                    ? "balanceOf(owner, tokenId) did not expose a supported owner/tokenId balance storage key template"
                    : "balanceOf(owner) did not expose a supported owner balance storage key template",
                FailedCondition: null,
                Counterexample: null);
        }

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        string? amountSymbol = isDivisible
            ? SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex)
            : null;
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool pathMutatesSupply = false;
            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                if (!TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                        incompleteReasons.Add($"successful NEP-11 {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                pathMutatesSupply = true;
                break;
            }

            if (!pathMutatesSupply)
                continue;

            obligations++;
            var balanceGet = isDivisible
                ? FindStorageGetByAccountTokenKey(state, accountSymbol, tokenIdSymbol, balancePatterns)
                : FindStorageGetByAccountKey(state, accountSymbol, balancePatterns);
            var balancePut = balanceGet is null
                ? null
                : isDivisible
                    ? FindStoragePutByAccountTokenKey(state, accountSymbol, tokenIdSymbol, balanceGet.Pattern, balanceGet.Op.Offset)
                    : FindStoragePutByAccountKey(state, accountSymbol, balanceGet.Pattern, balanceGet.Op.Offset);
            if (balanceGet is null)
            {
                bool mentionsBalance = isDivisible
                    ? StorageMentionsAccountTokenSymbols(state, accountSymbol, tokenIdSymbol)
                    : StorageMentionsAccountSymbol(state, accountSymbol);
                if (mentionsBalance)
                {
                    incompleteReasons.Add($"successful NEP-11 {lifecycle} uses {accountLabel} balance storage keys the lifecycle balance proof cannot yet normalize");
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
                    $"successful NEP-11 {lifecycle} mutates totalSupply() without a direct {accountLabel} balance read-write pair.",
                    isMint
                        ? $"mint credits {accountLabel} balance by {(isDivisible ? "amount" : "1")}"
                        : $"burn debits {accountLabel} balance by {(isDivisible ? "amount" : "1")}",
                    BuildStateWitness(smtBackend, state));
            }

            if (balancePut is null)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"successful NEP-11 {lifecycle} mutates totalSupply() after reading the {accountLabel} balance without writing the updated balance.",
                    isMint
                        ? $"mint credits {accountLabel} balance by {(isDivisible ? "amount" : "1")}"
                        : $"burn debits {accountLabel} balance by {(isDivisible ? "amount" : "1")}",
                    BuildStateWitness(smtBackend, state));
            }

            if (!isMint)
            {
                bool balanceProvedSufficient = isDivisible
                    ? PathConditionsProveStorageReadOrMissingZeroAtLeastAmount(state.PathConditions, balanceGet.Op.Offset, amountSymbol!)
                    : PathConditionsProveStorageReadAtLeastAmount(state.PathConditions, balanceGet.Op.Offset, Expr.Int(1));
                if (!balanceProvedSufficient)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 burn can return true without proving the {accountLabel} balance is at least {(isDivisible ? "amount" : "1")} before debit.",
                        $"{accountLabel} balance is at least {(isDivisible ? "amount" : "1")} before burn debit",
                        BuildStateWitness(smtBackend, state));
                }
            }

            bool deltaMatches = isDivisible
                ? ValueMatchesBalanceDelta(
                    balancePut.Op.Value?.Expression,
                    state,
                    balanceGet.Op.Offset,
                    amountSymbol!,
                    subtract: !isMint)
                : ValueMatchesBalanceDelta(
                    balancePut.Op.Value?.Expression,
                    state,
                    balanceGet.Op.Offset,
                    Expr.Int(1),
                    subtract: !isMint);
            if (!deltaMatches)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"successful NEP-11 {lifecycle} writes the {accountLabel} balance at 0x{balancePut.Op.Offset:X4} without {(isMint ? "adding" : "subtracting")} {(isDivisible ? "amount" : "1")}.",
                    isMint
                        ? $"mint credits {accountLabel} balance by {(isDivisible ? "amount" : "1")}"
                        : $"burn debits {accountLabel} balance by {(isDivisible ? "amount" : "1")}",
                    BuildStateWitness(smtBackend, state));
            }

            var later = isDivisible
                ? FindLaterStorageMutationByAccountTokenKey(state, accountSymbol, tokenIdSymbol, balanceGet.Pattern, balancePut.Op.Offset)
                : FindLaterStorageMutationByAccountKey(state, accountSymbol, balanceGet.Pattern, balancePut.Op.Offset);
            if (later is not null)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"successful NEP-11 {lifecycle} mutates the {accountLabel} balance again with {later.Kind} at 0x{later.Offset:X4} after the proved balance update.",
                    isMint
                        ? $"final {accountLabel} balance remains credited by {(isDivisible ? "amount" : "1")}"
                        : $"final {accountLabel} balance remains debited by {(isDivisible ? "amount" : "1")}",
                    BuildStateWitness(smtBackend, state));
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
                ? $"property holds vacuously: no successful NEP-11 {lifecycle} path mutates totalSupply() storage"
                : $"every successful NEP-11 {lifecycle} path that mutates totalSupply() maintains balanceOf(owner) storage",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11LifecycleAmountNonNegativeResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep11MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep11.lifecycle_amount_non_negative.{method.Name}";
        string description = $"Divisible NEP-11 {lifecycle} paths that mutate totalSupply() must prove amount is non-negative.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

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
                "NEP-11 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
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

        int amountIndex = FindAmountParameter(method);
        if (amountIndex < 0)
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
                $"divisible NEP-11 {lifecycle} method has no recognizable amount Integer parameter",
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

        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, execution, obligations) is { } noHalt)
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

        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool pathMutatesSupply = false;
            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                if (!TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                        incompleteReasons.Add($"successful divisible NEP-11 {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                pathMutatesSupply = true;
                break;
            }

            if (!pathMutatesSupply)
                continue;

            obligations++;
            var negativeAmount = Expr.Lt(Expr.Sym(Sort.Int, amountSymbol), Expr.Int(0));
            var query = BuildTrueReturnReachabilityQuery(method, state, negativeAmount);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Unsat)
                continue;

            string failedCondition = $"{lifecycle} amount >= 0 before supply mutation";
            if (outcome == SmtOutcome.Sat)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"successful divisible NEP-11 {lifecycle} can mutate totalSupply() with amount < 0.",
                    failedCondition,
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
                $"solver could not prove amount is non-negative on a successful divisible NEP-11 {lifecycle} path that mutates totalSupply()",
                failedCondition,
                BuildWitness(smtBackend, query));
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
                ? $"property holds vacuously: no successful divisible NEP-11 {lifecycle} path mutates totalSupply() storage"
                : $"every successful divisible NEP-11 {lifecycle} path that mutates totalSupply() proves amount is non-negative",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11LifecycleEventResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep11MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep11.lifecycle_event.{method.Name}";
        string description = $"NEP-11 {lifecycle} paths that mutate totalSupply() must emit the standard Transfer lifecycle event.";
        var counts = CountPaths(execution);
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
                "NEP-11 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
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

        int accountIndex = isMint ? FindToParameter(method) : FindFromParameter(method);
        int amountIndex = FindAmountParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (tokenIdIndex < 0 || (isMint && accountIndex < 0))
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
                $"NEP-11 {lifecycle} method has no recognizable {(isMint ? "to Hash160 and " : "")}tokenId ByteString parameters",
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

        if (BuildNoSuccessfulHaltIncompleteResult(id, method.Name, description, execution, obligations) is { } noHalt)
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

        string? amountSymbol = amountIndex >= 0
            ? SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex)
            : null;
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

            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                if (!TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                        incompleteReasons.Add($"successful NEP-11 {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                obligations++;
                var supplyRead = FindStorageGetByCanonicalKey(state, mutationKey, beforeOffset: mutation.Offset);
                if (supplyRead is null)
                {
                    incompleteReasons.Add($"successful NEP-11 {lifecycle} mutates totalSupply() storage without a preceding readable supply value");
                    continue;
                }

                bool supplyDeltaMatches = amountSymbol is null
                    ? ValueMatchesBalanceDelta(
                        mutation.Value?.Expression,
                        state,
                        supplyRead.Offset,
                        Expr.Int(1),
                        subtract: !isMint)
                    : ValueMatchesBalanceDelta(
                        mutation.Value?.Expression,
                        state,
                        supplyRead.Offset,
                        amountSymbol,
                        subtract: !isMint);
                if (mutation.Value is null || !supplyDeltaMatches)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 {lifecycle} mutates totalSupply() without updating it by {(isMint ? "+" : "-")}{(amountSymbol is null ? "1" : "amount")}.",
                        isMint
                            ? $"mint updates totalSupply'=totalSupply+{(amountSymbol is null ? "1" : "amount")}"
                            : $"burn updates totalSupply'=totalSupply-{(amountSymbol is null ? "1" : "amount")}",
                        BuildStateWitness(smtBackend, state));
                }

                if (state.Telemetry.Notifications.Any(n => Nep11LifecycleTransferNotificationPayloadMatches(
                        state,
                        method,
                        n,
                        accountIndex,
                        amountIndex,
                        tokenIdIndex,
                        isMint,
                        currentScriptHash)))
                {
                    continue;
                }

                if (CurrentTransferNotifications(state, currentScriptHash).Any())
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 {lifecycle} mutates totalSupply() while emitting Transfer with the wrong lifecycle payload.",
                        isMint
                            ? "mint emits Transfer(null,to,1,tokenId)"
                            : $"burn emits Transfer(from,null,{(amountSymbol is null ? "1" : "amount")},tokenId)",
                        BuildStateWitness(smtBackend, state));
                }

                if (state.Telemetry.Notifications.Any(n => n.ConcreteName is null))
                {
                    incompleteReasons.Add($"successful NEP-11 {lifecycle} emits a notification with symbolic or unknown event name");
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
                    $"successful NEP-11 {lifecycle} mutates totalSupply() without emitting {(isMint ? "Transfer(null, to, 1, tokenId)" : $"Transfer(from, null, {(amountSymbol is null ? "1" : "amount")}, tokenId)")}.",
                    isMint
                        ? "mint emits Transfer(null,to,1,tokenId)"
                        : $"burn emits Transfer(from,null,{(amountSymbol is null ? "1" : "amount")},tokenId)",
                    BuildStateWitness(smtBackend, state));
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
                ? $"property holds vacuously: no successful NEP-11 {lifecycle} path mutates totalSupply() storage"
                : $"every successful NEP-11 {lifecycle} path that mutates totalSupply() emits the standard Transfer lifecycle event",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11LifecycleIndexResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep11MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep11.lifecycle_index.{method.Name}";
        string description = $"NEP-11 {lifecycle} paths that mutate totalSupply() must maintain token enumeration indexes.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

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
                "NEP-11 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
                FailedCondition: null,
                Counterexample: null);
        }

        if (FindAbiMethod(manifest, "tokensOf", IsNep11TokensOfMethod) is not { } tokensOf)
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
                "NEP-11 manifest has no tokensOf(owner) method to infer owner enumeration index keys from",
                FailedCondition: null,
                Counterexample: null);
        }

        ContractMethodDescriptor? tokens = null;
        if (FindAbiMethod(manifest, "tokens") is not null)
        {
            tokens = FindAbiMethod(manifest, "tokens", IsNep11TokensMethod);
            if (tokens is null)
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
                    "NEP-11 manifest declares tokens() but it is not a safe no-argument InteropInterface method",
                    FailedCondition: null,
                    Counterexample: null);
            }
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

        if (tokensOf.Offset < 0 || tokensOf.Offset >= program.Bytes.Length)
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
                $"tokensOf(owner) offset {tokensOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        if (tokens is not null && (tokens.Offset < 0 || tokens.Offset >= program.Bytes.Length))
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
                $"tokens() offset {tokens.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        int accountIndex = isMint ? FindToParameter(method) : FindFromParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (accountIndex < 0 || tokenIdIndex < 0)
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
                $"NEP-11 {lifecycle} method has no recognizable {(isMint ? "to" : "from")} Hash160 or tokenId ByteString parameter",
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

        var tokensOfExecution = RunMethodEntry(program, options, tokensOf);
        foreach (var reason in IncompleteReasons(tokensOfExecution))
            incompleteReasons.Add("tokensOf(owner): " + reason);
        var tokensOfPatterns = InferNep11TokensOfIndexKeyPatterns(tokensOf, tokensOfExecution, incompleteReasons);

        ImmutableArray<Expression> tokenPatterns = ImmutableArray<Expression>.Empty;
        if (tokens is not null)
        {
            var tokensExecution = RunMethodEntry(program, options, tokens);
            foreach (var reason in IncompleteReasons(tokensExecution))
                incompleteReasons.Add("tokens(): " + reason);
            tokenPatterns = InferNep11TokensIndexKeyPatterns(tokens, tokensExecution, incompleteReasons);
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

        if (tokensOfPatterns.IsDefaultOrEmpty)
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
                "tokensOf(owner) did not expose a supported owner/tokenId enumeration index key template",
                FailedCondition: null,
                Counterexample: null);
        }

        if (tokens is not null && tokenPatterns.IsDefaultOrEmpty)
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
                "tokens() did not expose a supported tokenId enumeration index key template",
                FailedCondition: null,
                Counterexample: null);
        }

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool pathMutatesSupply = false;
            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                if (!TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                        incompleteReasons.Add($"successful NEP-11 {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                pathMutatesSupply = true;
                break;
            }

            if (!pathMutatesSupply)
                continue;

            obligations++;
            if (isMint)
            {
                if (tokens is not null)
                {
                    var tokenPut = FindStoragePutByTokenIdKey(state, tokenIdSymbol, tokenPatterns, afterOffset: -1);
                    if (tokenPut is null)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            "successful NEP-11 mint mutates totalSupply() without writing the minted tokenId into the tokens() enumeration index.",
                            "write minted tokenId indexes",
                            BuildStateWitness(smtBackend, state));
                    }

                    if (FindLaterStorageDeleteByTokenIdKey(state, tokenIdSymbol, tokenPatterns, tokenPut.Op.Offset) is { } laterTokenDelete)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            $"successful NEP-11 mint writes the tokens() enumeration index and then deletes it at 0x{laterTokenDelete.Offset:X4}.",
                            "minted tokenId remains in tokens() index after mint",
                            BuildStateWitness(smtBackend, state));
                    }
                }

                var ownerPut = FindStoragePutByAccountTokenKey(state, accountSymbol, tokenIdSymbol, tokensOfPatterns, afterOffset: -1);
                if (ownerPut is null)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        "successful NEP-11 mint mutates totalSupply() without writing the minted tokenId into the tokensOf(to) enumeration index.",
                        "write minted tokenId indexes",
                        BuildStateWitness(smtBackend, state));
                }

                if (FindLaterStorageDeleteByAccountTokenKey(state, accountSymbol, tokenIdSymbol, tokensOfPatterns, ownerPut.Op.Offset) is { } laterOwnerDelete)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 mint writes the tokensOf(to) enumeration index and then deletes it at 0x{laterOwnerDelete.Offset:X4}.",
                        "minted tokenId remains in tokensOf(to) index after mint",
                        BuildStateWitness(smtBackend, state));
                }
            }
            else
            {
                if (tokens is not null)
                {
                    var tokenDelete = FindStorageDeleteByTokenIdKey(state, tokenIdSymbol, tokenPatterns, afterOffset: -1);
                    if (tokenDelete is null)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            "successful NEP-11 burn mutates totalSupply() without deleting the burned tokenId from the tokens() enumeration index.",
                            "delete burned tokenId indexes",
                            BuildStateWitness(smtBackend, state));
                    }

                    if (FindLaterStoragePutByTokenIdKey(state, tokenIdSymbol, tokenPatterns, tokenDelete.Op.Offset) is { } laterTokenPut)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            $"successful NEP-11 burn deletes the tokens() enumeration index and then restores it with Storage.Put at 0x{laterTokenPut.Offset:X4}.",
                            "burned tokenId remains deleted from tokens() index after burn",
                            BuildStateWitness(smtBackend, state));
                    }
                }

                var ownerDelete = FindStorageDeleteByAccountTokenKey(state, accountSymbol, tokenIdSymbol, tokensOfPatterns, afterOffset: -1);
                if (ownerDelete is null)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        "successful NEP-11 burn mutates totalSupply() without deleting the burned tokenId from the tokensOf(from) enumeration index.",
                        "delete burned tokenId indexes",
                        BuildStateWitness(smtBackend, state));
                }

                if (FindLaterStoragePutByAccountTokenKey(state, accountSymbol, tokenIdSymbol, tokensOfPatterns, ownerDelete.Op.Offset) is { } laterOwnerPut)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 burn deletes the tokensOf(from) enumeration index and then restores it with Storage.Put at 0x{laterOwnerPut.Offset:X4}.",
                        "burned tokenId remains deleted from tokensOf(from) index after burn",
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
                ? $"property holds vacuously: no successful NEP-11 {lifecycle} path mutates totalSupply() storage"
                : $"every successful NEP-11 {lifecycle} path that mutates totalSupply() maintains token enumeration indexes",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11LifecycleOwnerStorageResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep11MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep11.lifecycle_owner_storage.{method.Name}";
        string description = $"Non-divisible NEP-11 {lifecycle} paths that mutate totalSupply() must maintain ownerOf(tokenId) storage.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

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
                "NEP-11 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
                FailedCondition: null,
                Counterexample: null);
        }

        if (FindAbiMethod(manifest, "ownerOf", IsNep11NonDivisibleOwnerOfMethod) is not { } ownerOf)
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
                "NEP-11 manifest has no non-divisible ownerOf(tokenId) method to infer owner storage keys from",
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

        if (ownerOf.Offset < 0 || ownerOf.Offset >= program.Bytes.Length)
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
                $"ownerOf(tokenId) offset {ownerOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        int accountIndex = isMint ? FindToParameter(method) : FindFromParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (accountIndex < 0 || tokenIdIndex < 0)
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
                $"NEP-11 {lifecycle} method has no recognizable {(isMint ? "to" : "from")} Hash160 or tokenId ByteString parameter",
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

        var ownerOfExecution = RunMethodEntry(program, options, ownerOf);
        foreach (var reason in IncompleteReasons(ownerOfExecution))
            incompleteReasons.Add("ownerOf(tokenId): " + reason);

        var ownerOfPatterns = InferOwnerOfStorageKeyPatterns(ownerOf, ownerOfExecution, incompleteReasons);
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

        if (ownerOfPatterns.IsDefaultOrEmpty)
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
                "ownerOf(tokenId) did not expose a supported tokenId owner storage key template",
                FailedCondition: null,
                Counterexample: null);
        }

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool pathMutatesSupply = false;
            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                if (!TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                        incompleteReasons.Add($"successful NEP-11 {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                pathMutatesSupply = true;
                break;
            }

            if (!pathMutatesSupply)
                continue;

            obligations++;
            if (isMint)
            {
                var ownerPut = FindStoragePutByAccountKey(state, tokenIdSymbol, ownerOfPatterns, afterOffset: -1);
                if (ownerPut is null)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        "successful NEP-11 mint mutates totalSupply() without writing ownerOf(tokenId) storage to the minted recipient.",
                        "mint writes ownerOf(tokenId) to recipient",
                        BuildStateWitness(smtBackend, state));
                }

                if (ownerPut.Op.Value is null || !IsSymbol(ownerPut.Op.Value.Expression, accountSymbol))
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 mint writes ownerOf(tokenId) storage at 0x{ownerPut.Op.Offset:X4} without storing the minted recipient.",
                        "mint writes ownerOf(tokenId) to recipient",
                        BuildStateWitness(smtBackend, state));
                }

                if (FindLaterStorageMutationByAccountKey(state, tokenIdSymbol, ownerPut.Pattern, ownerPut.Op.Offset) is { } laterMutation)
                {
                    string opName = laterMutation.Kind == StorageOpKind.Put ? "Storage.Put" : "Storage.Delete";
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 mint writes ownerOf(tokenId) to the recipient and then mutates it with {opName} at 0x{laterMutation.Offset:X4}.",
                        "mint preserves ownerOf(tokenId) recipient after write",
                        BuildStateWitness(smtBackend, state));
                }
            }
            else
            {
                var ownerDelete = FindStorageDeleteByAccountKey(state, tokenIdSymbol, ownerOfPatterns, afterOffset: -1);
                if (ownerDelete is null)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        "successful NEP-11 burn mutates totalSupply() without deleting ownerOf(tokenId) storage for the burned token.",
                        "burn deletes ownerOf(tokenId)",
                        BuildStateWitness(smtBackend, state));
                }

                if (FindStoragePutByAccountKey(state, tokenIdSymbol, ownerOfPatterns, ownerDelete.Op.Offset) is { } laterPut)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"successful NEP-11 burn deletes ownerOf(tokenId) storage and then restores it with Storage.Put at 0x{laterPut.Op.Offset:X4}.",
                        "burn keeps ownerOf(tokenId) deleted",
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
                ? $"property holds vacuously: no successful NEP-11 {lifecycle} path mutates totalSupply() storage"
                : $"every successful NEP-11 {lifecycle} path that mutates totalSupply() maintains ownerOf(tokenId) storage",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleLifecycleOwnerOfIndexResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep11MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep11.lifecycle_ownerof_index.{method.Name}";
        string description = $"Divisible NEP-11 {lifecycle} paths that mutate totalSupply() must maintain ownerOf(tokenId) owner indexes.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

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
                "NEP-11 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
                FailedCondition: null,
                Counterexample: null);
        }

        if (FindAbiMethod(manifest, "ownerOf", IsNep11DivisibleOwnerOfMethod) is not { } ownerOf)
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
                "NEP-11 manifest has no divisible ownerOf(tokenId) method to infer owner enumeration index keys from",
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

        if (ownerOf.Offset < 0 || ownerOf.Offset >= program.Bytes.Length)
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
                $"ownerOf(tokenId) offset {ownerOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        int accountIndex = isMint ? FindToParameter(method) : FindFromParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (accountIndex < 0 || tokenIdIndex < 0)
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
                $"divisible NEP-11 {lifecycle} method has no recognizable {(isMint ? "to" : "from")} Hash160 or tokenId ByteString parameter",
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

        var ownerOfExecution = RunMethodEntry(program, options, ownerOf);
        foreach (var reason in IncompleteReasons(ownerOfExecution))
            incompleteReasons.Add("ownerOf(tokenId): " + reason);

        var ownerIndexPatterns = InferNep11DivisibleOwnerOfIndexKeyPatterns(ownerOf, ownerOfExecution, incompleteReasons);
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

        if (ownerIndexPatterns.IsDefaultOrEmpty)
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
                "ownerOf(tokenId) did not expose a supported tokenId/owner Storage.Find index key template",
                FailedCondition: null,
                Counterexample: null);
        }

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool pathMutatesSupply = false;
            foreach (var mutation in state.Telemetry.StorageOps
                         .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                         .OrderBy(op => op.Offset))
            {
                if (!TryCanonicalConcreteStorageKey(state, mutation.Key, out var mutationKey))
                {
                    if (MutationKeyMayAliasSupplyKey(method, RuntimeStorageKeyExpressionOrOriginal(state, mutation.Key), supplyKeys))
                        incompleteReasons.Add($"successful divisible NEP-11 {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                pathMutatesSupply = true;
                break;
            }

            if (!pathMutatesSupply)
                continue;

            obligations++;
            var balanceGet = FindStorageGetByAccountTokenKey(state, accountSymbol, tokenIdSymbol);
            var balancePut = balanceGet is null
                ? null
                : FindStoragePutByAccountTokenKey(state, accountSymbol, tokenIdSymbol, balanceGet.Pattern, balanceGet.Op.Offset);
            if (balanceGet is null || balancePut is null)
            {
                if (StorageMentionsAccountTokenSymbols(state, accountSymbol, tokenIdSymbol))
                {
                    incompleteReasons.Add($"successful divisible NEP-11 {lifecycle} uses token balance storage keys the ownerOf(tokenId) lifecycle proof cannot yet normalize");
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
                    $"successful divisible NEP-11 {lifecycle} mutates totalSupply() without direct account/token balance read-write pairs for ownerOf(tokenId) index maintenance.",
                    "ownerOf(tokenId) lifecycle index update is based on final account/token balance",
                    BuildStateWitness(smtBackend, state));
            }

            if (balancePut.Op.Value?.Expression is not { } finalBalance)
            {
                incompleteReasons.Add($"successful divisible NEP-11 {lifecycle} writes a token balance value the ownerOf(tokenId) lifecycle proof cannot inspect");
                continue;
            }

            if (isMint)
            {
                var ownerPut = FindStoragePutByAccountTokenKey(
                    state,
                    accountSymbol,
                    tokenIdSymbol,
                    ownerIndexPatterns,
                    afterOffset: balanceGet.Op.Offset);
                if (ownerPut is null)
                {
                    if (!TrySatisfiability(state, smtBackend, Expr.Gt(finalBalance, Expr.Int(0)), out var finalMayBePositive, out var finalPositiveReason))
                    {
                        incompleteReasons.Add(finalPositiveReason);
                        continue;
                    }

                    if (finalMayBePositive == SmtOutcome.Sat)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            "successful divisible NEP-11 mint can leave the recipient with a positive final token balance without writing the recipient/tokenId ownerOf(tokenId) index entry.",
                            "write recipient/tokenId ownerOf index when minted owner final balance is positive",
                            BuildStateWitness(smtBackend, state));
                    }
                }
                else
                {
                    if (!TrySatisfiability(state, smtBackend, Expr.NumEq(finalBalance, Expr.Int(0)), out var finalMayBeZero, out var finalZeroReason))
                    {
                        incompleteReasons.Add(finalZeroReason);
                        continue;
                    }

                    if (finalMayBeZero == SmtOutcome.Sat)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            $"successful divisible NEP-11 mint writes the recipient/tokenId ownerOf(tokenId) index entry at 0x{ownerPut.Op.Offset:X4} even though the recipient final token balance can be zero.",
                            "recipient/tokenId ownerOf index is present only when recipient final balance is positive",
                            BuildStateWitness(smtBackend, state));
                    }

                    if (FindLaterStorageDeleteByAccountTokenKey(state, accountSymbol, tokenIdSymbol, ownerIndexPatterns, ownerPut.Op.Offset) is { } laterDelete)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            $"successful divisible NEP-11 mint writes the recipient ownerOf(tokenId) index entry and then deletes it at 0x{laterDelete.Offset:X4}.",
                            "recipient/tokenId ownerOf index remains present when recipient final balance is positive",
                            BuildStateWitness(smtBackend, state));
                    }
                }
            }
            else
            {
                var ownerDelete = FindStorageDeleteByAccountTokenKey(
                    state,
                    accountSymbol,
                    tokenIdSymbol,
                    ownerIndexPatterns,
                    afterOffset: balanceGet.Op.Offset);
                if (ownerDelete is null)
                {
                    if (!TrySatisfiability(state, smtBackend, Expr.NumEq(finalBalance, Expr.Int(0)), out var finalMayBeZero, out var finalZeroReason))
                    {
                        incompleteReasons.Add(finalZeroReason);
                        continue;
                    }

                    if (finalMayBeZero == SmtOutcome.Sat)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            "successful divisible NEP-11 burn can leave the sender with zero final token balance without deleting the sender/tokenId ownerOf(tokenId) index entry.",
                            "delete sender/tokenId ownerOf index when burned owner final balance is zero",
                            BuildStateWitness(smtBackend, state));
                    }
                }
                else
                {
                    if (!TrySatisfiability(state, smtBackend, Expr.Gt(finalBalance, Expr.Int(0)), out var finalMayBePositive, out var finalPositiveReason))
                    {
                        incompleteReasons.Add(finalPositiveReason);
                        continue;
                    }

                    if (finalMayBePositive == SmtOutcome.Sat)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            $"successful divisible NEP-11 burn deletes the sender/tokenId ownerOf(tokenId) index entry at 0x{ownerDelete.Op.Offset:X4} even though the sender final token balance can remain positive.",
                            "sender/tokenId ownerOf index remains present while sender final balance is positive",
                            BuildStateWitness(smtBackend, state));
                    }

                    if (FindLaterStoragePutByAccountTokenKey(state, accountSymbol, tokenIdSymbol, ownerIndexPatterns, ownerDelete.Op.Offset) is { } laterPut)
                    {
                        return new VerificationPropertyResult(
                            id,
                            method.Name,
                            description,
                            VerificationStatus.Violated,
                            counts.CheckedPaths,
                            counts.IgnoredFaultedPaths,
                            counts.StoppedPaths,
                            obligations,
                            $"successful divisible NEP-11 burn deletes the sender ownerOf(tokenId) index entry and then restores it with Storage.Put at 0x{laterPut.Offset:X4}.",
                            "sender/tokenId ownerOf index remains deleted when sender final balance is zero",
                            BuildStateWitness(smtBackend, state));
                    }
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
                ? $"property holds vacuously: no successful divisible NEP-11 {lifecycle} path mutates totalSupply() storage"
                : $"every successful divisible NEP-11 {lifecycle} path that mutates totalSupply() keeps ownerOf(tokenId) owner indexes synchronized with final token balances",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11TokenIdLengthResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.tokenid_length.{method.Name}";
        string description = $"NEP-11 transfer true-return paths must prove tokenId length <= {Nep11MaxTokenIdLength} bytes.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        var incompleteReasons = new List<string>();
        if (tokenIdIndex < 0)
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
                "NEP-11 transfer method has no recognizable tokenId ByteString parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
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
            if (PathConditionsProveSymbolByteLengthAtMost(state.PathConditions, tokenIdSymbol, Nep11MaxTokenIdLength))
                continue;

            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"transfer can return true without proving tokenId length is at most {Nep11MaxTokenIdLength} bytes.",
                $"tokenId length <= {Nep11MaxTokenIdLength} before true-return NEP-11 transfer",
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
                ? "property holds vacuously: no successful transfer path can return true"
                : $"every true-return NEP-11 transfer path proves tokenId length <= {Nep11MaxTokenIdLength}",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11TokenIdParameterLengthResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.tokenid_length.*";
        const string method = "*";
        string description = $"NEP-11 tokenId query and lifecycle methods must prove tokenId length <= {Nep11MaxTokenIdLength} bytes before successful return.";
        string failedCondition = $"tokenId length <= {Nep11MaxTokenIdLength} before successful NEP-11 tokenId method return";

        var methods = manifest.Abi.Methods
            .Where(m => !string.Equals(m.Name, "transfer", StringComparison.OrdinalIgnoreCase))
            .Where(m => IsNep11TokenIdLengthBoundedMethod(manifest, m))
            .ToList();

        int checkedPaths = 0;
        int ignoredFaulted = 0;
        int stopped = 0;
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (methods.Count == 0)
        {
            return new VerificationPropertyResult(
                id,
                method,
                description,
                VerificationStatus.Incomplete,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                "NEP-11 manifest has no proof-grade non-transfer tokenId method for tokenId length checking",
                FailedCondition: null,
                Counterexample: null);
        }

        foreach (var tokenIdMethod in methods)
        {
            int tokenIdIndex = FindNamedNep11TokenIdParameter(tokenIdMethod);
            string displayName = $"{tokenIdMethod.Name}({string.Join(",", tokenIdMethod.Parameters.Select(p => p.Name))})";
            if (tokenIdIndex < 0)
            {
                incompleteReasons.Add($"{displayName}: no standard tokenId ByteString parameter");
                continue;
            }

            if (tokenIdMethod.Offset < 0 || tokenIdMethod.Offset >= program.Bytes.Length)
            {
                incompleteReasons.Add($"{displayName}: offset {tokenIdMethod.Offset} is outside script bytes");
                continue;
            }

            if (ProfileDuplicateParameterNameReason(tokenIdMethod) is { } duplicateParameterReason)
            {
                incompleteReasons.Add($"{displayName}: {duplicateParameterReason}");
                continue;
            }

            var execution = RunMethodEntry(program, OptionsForMethod(manifest, tokenIdMethod, options), tokenIdMethod);
            checkedPaths += execution.FinalStates.Count(s => s.Status == TerminalStatus.Halted);
            ignoredFaulted += execution.FinalStates.Count(s => s.Status == TerminalStatus.Faulted);
            stopped += execution.FinalStates.Count(s => s.Status == TerminalStatus.Stopped);
            foreach (var reason in IncompleteReasons(execution))
                incompleteReasons.Add($"{displayName}: {reason}");

            var halted = execution.Halted.ToList();
            if (halted.Count == 0)
            {
                incompleteReasons.Add($"{displayName}: produced no successful HALT path");
                continue;
            }

            string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(
                tokenIdMethod.Parameters[tokenIdIndex].Name,
                tokenIdIndex);
            foreach (var state in halted)
            {
                obligations++;
                if (PathConditionsProveSymbolByteLengthAtMost(state.PathConditions, tokenIdSymbol, Nep11MaxTokenIdLength))
                    continue;

                return new VerificationPropertyResult(
                    id,
                    method,
                    description,
                    VerificationStatus.Violated,
                    checkedPaths,
                    ignoredFaulted,
                    stopped,
                    obligations,
                    $"{displayName} can successfully return without proving tokenId length is at most {Nep11MaxTokenIdLength} bytes.",
                    failedCondition,
                    BuildStateWitness(smtBackend, state));
            }
        }

        if (incompleteReasons.Count > 0)
        {
            return new VerificationPropertyResult(
                id,
                method,
                description,
                VerificationStatus.Incomplete,
                checkedPaths,
                ignoredFaulted,
                stopped,
                obligations,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
        }

        return new VerificationPropertyResult(
            id,
            method,
            description,
            VerificationStatus.Proved,
            checkedPaths,
            ignoredFaulted,
            stopped,
            obligations,
            $"every successful NEP-11 non-transfer tokenId method path proves tokenId length <= {Nep11MaxTokenIdLength}",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleAmountDecimalsBoundResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.amount_lte_decimals.{method.Name}";
        string description = "Divisible NEP-11 transfer true-return paths must prove amount <= pow(10, decimals()).";
        const string failedCondition = "amount <= 10^decimals()";
        var counts = CountPaths(execution);
        int obligations = 0;
        int amountIndex = FindAmountParameter(method);
        var incompleteReasons = new List<string>();
        if (amountIndex < 0)
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
                "divisible NEP-11 transfer method has no recognizable amount parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        if (!TryGetConcreteNep11Decimals(
            manifest,
            program,
            options,
            out var decimals,
            out var decimalsReason,
            out var decimalsOffset))
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
                decimalsReason,
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: method.Offset);
        }

        if (decimals < 0)
        {
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"divisible NEP-11 decimals() returns negative value {decimals}.",
                "decimals() >= 0",
                Counterexample: null,
                MethodOffset: decimalsOffset);
        }

        if (decimals > int.MaxValue)
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
                $"divisible NEP-11 decimals() value {decimals} is too large to compute pow(10, decimals())",
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: decimalsOffset);
        }

        BigInteger maxAmount;
        try
        {
            maxAmount = BigInteger.Pow(new BigInteger(10), (int)decimals);
        }
        catch (ArgumentOutOfRangeException ex)
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
                $"divisible NEP-11 decimals() value {decimals} cannot be used for pow(10, decimals()): {ex.Message}",
                FailedCondition: null,
                Counterexample: null,
                MethodOffset: decimalsOffset);
        }

        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        var amountExpr = Expr.Sym(Sort.Int, amountSymbol);
        var tooLargeAmount = Expr.Gt(amountExpr, Expr.Int(maxAmount));
        string displayCondition = $"{failedCondition} ({maxAmount.ToString(System.Globalization.CultureInfo.InvariantCulture)})";

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
            var query = BuildTrueReturnReachabilityQuery(method, state, tooLargeAmount);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Unsat)
                continue;

            if (outcome == SmtOutcome.Sat)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer can return true with amount greater than 10^decimals() ({maxAmount}).",
                    displayCondition,
                    BuildWitness(smtBackend, query));
            }

            incompleteReasons.Add("solver returned unknown while proving divisible NEP-11 amount <= 10^decimals()");
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
                ? "property holds vacuously: no successful transfer path can return true"
                : $"every true-return divisible NEP-11 transfer path proves amount <= 10^decimals() ({maxAmount})",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11OwnerAuthorizationResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.owner_authorized.{method.Name}";
        string description = "NEP-11 transfer true-return paths must be authorized by the current token owner or caller contract.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        var incompleteReasons = new List<string>();
        if (tokenIdIndex < 0)
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
                "NEP-11 transfer method has no recognizable tokenId ByteString parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
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
            int authorizationBoundary = FirstSensitiveOperationOffset(state);
            if (FindStorageGetByAccountKey(state, tokenIdSymbol) is not { } ownerRead)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without reading the current NFT owner from tokenId-indexed storage.",
                    "owner authorization before true-return NEP-11 transfer",
                    BuildStateWitness(smtBackend, state));
            }

            if (!HasOwnerReadAuthorizationBefore(state, ownerRead.Op.Offset, authorizationBoundary))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without proving Runtime.CallingScriptHash == ownerOf(tokenId) or enforcing CheckWitness(ownerOf(tokenId)).",
                    "owner authorization before true-return NEP-11 transfer",
                    BuildStateWitness(smtBackend, state));
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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every true-return NEP-11 transfer path is authorized by Runtime.CallingScriptHash == ownerOf(tokenId) or enforced CheckWitness(ownerOf(tokenId))",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11OwnerUpdateResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.owner_update.{method.Name}";
        string description = "NEP-11 transfer true-return paths must update ownerOf(tokenId) to the recipient.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        var incompleteReasons = new List<string>();
        if (toIndex < 0 || tokenIdIndex < 0)
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
                "NEP-11 transfer method has no recognizable to Hash160 or tokenId ByteString parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
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
            if (FindStorageGetByAccountKey(state, tokenIdSymbol) is not { } ownerRead)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without reading ownerOf(tokenId) before updating ownership.",
                    "ownerOf(tokenId) updated to transfer.to",
                    BuildStateWitness(smtBackend, state));
            }

            var ownerPut = FindStoragePutByAccountKey(state, tokenIdSymbol, ownerRead.Pattern, ownerRead.Op.Offset);
            if (ownerPut is null || ownerPut.Op.Value is null || !IsSymbol(ownerPut.Op.Value.Expression, toSymbol))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without writing ownerOf(tokenId) to transfer.to.",
                    "ownerOf(tokenId) updated to transfer.to",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageMutationByAccountKey(state, tokenIdSymbol, ownerRead.Pattern, ownerPut.Op.Offset) is { } later)
            {
                string opName = later.Kind == StorageOpKind.Put ? "Storage.Put" : "Storage.Delete";
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer updates ownerOf(tokenId) to transfer.to and then overwrites it with {opName} at 0x{later.Offset:X4}.",
                    "ownerOf(tokenId) remains transfer.to after ownership update",
                    BuildStateWitness(smtBackend, state));
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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every true-return NEP-11 transfer updates ownerOf(tokenId) to transfer.to and preserves that owner key",
            FailedCondition: null,
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11OwnerBalanceDeltaResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.owner_balance_delta.{method.Name}";
        string description = "Non-divisible NEP-11 transfer true-return paths must debit the current owner balance and credit the recipient balance by 1.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        var incompleteReasons = new List<string>();
        if (toIndex < 0 || tokenIdIndex < 0)
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
                "NEP-11 transfer method has no recognizable to Hash160 or tokenId ByteString parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
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
            if (FindStorageGetByAccountKey(state, tokenIdSymbol) is not { } ownerRead)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without reading ownerOf(tokenId) before updating owner balances.",
                    "owner balance from'=from-1 and to'=to+1",
                    BuildStateWitness(smtBackend, state));
            }

            string ownerSymbol = StorageReadSymbolName(ownerRead.Op.Offset);
            if (PathConditionsProveSymbolEquality(state.PathConditions, ownerSymbol, toSymbol))
            {
                if (SelfTransferBalanceMutation(state, ownerSymbol, toSymbol, out var mutation, out var mutationReason))
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"self-transfer can return true after {mutation!.Kind} mutates an owner balance key at 0x{mutation.Offset:X4}.",
                        "self-transfer leaves owner balance storage unchanged",
                        BuildStateWitness(smtBackend, state));
                }

                if (!string.IsNullOrWhiteSpace(mutationReason))
                    incompleteReasons.Add(mutationReason);
                continue;
            }

            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, ownerSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return NEP-11 transfer path does not prove whether owner == to or owner != to");
                continue;
            }

            var fromGet = FindStorageGetByAccountKey(state, ownerSymbol);
            var toGet = FindStorageGetByAccountKey(state, toSymbol);
            var fromPut = fromGet is null ? null : FindStoragePutByAccountKey(state, ownerSymbol, fromGet.Pattern, fromGet.Op.Offset);
            var toPut = toGet is null ? null : FindStoragePutByAccountKey(state, toSymbol, toGet.Pattern, toGet.Op.Offset);

            if (fromGet is null || toGet is null || fromPut is null || toPut is null)
            {
                if (StorageMentionsOwnerBalanceSymbols(state, ownerSymbol, toSymbol, tokenIdSymbol))
                {
                    incompleteReasons.Add("true-return NEP-11 transfer uses owner balance storage keys the proof cannot yet normalize");
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
                    "transfer can return true without direct owner/to balance read-write pairs.",
                    "owner balance from'=from-1 and to'=to+1",
                    BuildStateWitness(smtBackend, state));
            }

            if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer reads owner/to balances through different storage key templates.",
                    "owner and recipient balances use the same owner balance key template",
                    BuildStateWitness(smtBackend, state));
            }

            if (!PathConditionsProveStorageReadAtLeastAmount(state.PathConditions, fromGet.Op.Offset, Expr.Int(1)))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without proving the owner balance is at least 1 before debit.",
                    "owner balance is at least 1 before debit",
                    BuildStateWitness(smtBackend, state));
            }

            if (!ValueMatchesBalanceDelta(fromPut.Op.Value?.Expression, state, fromGet.Op.Offset, Expr.Int(1), subtract: true))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer writes the owner balance at 0x{fromPut.Op.Offset:X4} without subtracting 1 from its prior value.",
                    "owner balance write equals previous owner balance minus 1",
                    BuildStateWitness(smtBackend, state));
            }

            if (!ValueMatchesBalanceDelta(toPut.Op.Value?.Expression, state, toGet.Op.Offset, Expr.Int(1), subtract: false))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer writes the recipient balance at 0x{toPut.Op.Offset:X4} without adding 1 to its prior value.",
                    "recipient balance write equals previous recipient balance plus 1",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageMutationByAccountKey(state, ownerSymbol, fromGet.Pattern, fromPut.Op.Offset) is { } laterFrom)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer mutates the owner balance again with {laterFrom.Kind} at 0x{laterFrom.Offset:X4} after the proved debit.",
                    "final owner balance remains previous owner balance minus 1",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageMutationByAccountKey(state, toSymbol, toGet.Pattern, toPut.Op.Offset) is { } laterTo)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer mutates the recipient balance again with {laterTo.Kind} at 0x{laterTo.Offset:X4} after the proved credit.",
                    "final recipient balance remains previous recipient balance plus 1",
                    BuildStateWitness(smtBackend, state));
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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every true-return non-divisible NEP-11 transfer path either leaves self-transfer balance unchanged or debits owner and credits recipient by 1",
            FailedCondition: null,
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11TokensOfIndexResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.tokensof_index.transfer";
        const string methodName = "transfer";
        const string description = "Non-divisible NEP-11 transfer true-return paths must keep tokensOf(owner) enumeration indexes in sync.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, "tokensOf", IsNep11TokensOfMethod) is not { } tokensOf)
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
                "NEP-11 manifest has no tokensOf(owner) method to compare against transfer enumeration indexes",
                FailedCondition: null,
                Counterexample: null);
        }

        if (tokensOf.Offset < 0 || tokensOf.Offset >= program.Bytes.Length)
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
                $"tokensOf(owner) offset {tokensOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        int toIndex = FindToParameter(transfer);
        int tokenIdIndex = FindNep11TokenIdParameter(transfer);
        if (toIndex < 0 || tokenIdIndex < 0)
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
                "NEP-11 transfer method has no recognizable to Hash160 or tokenId ByteString parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        var tokensOfExecution = RunMethodEntry(program, options, tokensOf);
        foreach (var reason in IncompleteReasons(tokensOfExecution))
            incompleteReasons.Add("tokensOf(owner): " + reason);

        var indexPatterns = InferNep11TokensOfIndexKeyPatterns(tokensOf, tokensOfExecution, incompleteReasons);
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
                Counterexample: null);
        }

        if (indexPatterns.IsDefaultOrEmpty)
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
                "tokensOf(owner) did not expose a supported owner/tokenId Storage.Find index key template",
                FailedCondition: null,
                Counterexample: null);
        }

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(transfer.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(transfer.Parameters[tokenIdIndex].Name, tokenIdIndex);
        foreach (var state in transferExecution.Halted)
        {
            if (!TryReturnMayBeTrue(transfer, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            obligations++;
            if (FindStorageGetByAccountKey(state, tokenIdSymbol) is not { } ownerRead)
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
                    "transfer can return true without reading ownerOf(tokenId) before updating tokensOf(owner) index entries.",
                    "tokensOf(owner) index update is based on current ownerOf(tokenId)",
                    BuildStateWitness(smtBackend, state));
            }

            string ownerSymbol = StorageReadSymbolName(ownerRead.Op.Offset);
            if (PathConditionsProveSymbolEquality(state.PathConditions, ownerSymbol, toSymbol))
            {
                if (FindAnyStorageMutationByAccountTokenKey(state, ownerSymbol, tokenIdSymbol, indexPatterns, afterOffset: ownerRead.Op.Offset) is { } mutation)
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
                        $"self-transfer can return true after {mutation.Kind} mutates a tokensOf(owner) index key at 0x{mutation.Offset:X4}.",
                        "self-transfer leaves tokensOf(owner) index unchanged",
                        BuildStateWitness(smtBackend, state));
                }

                continue;
            }

            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, ownerSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return NEP-11 transfer path does not prove whether owner == to or owner != to for tokensOf(owner) index maintenance");
                continue;
            }

            var oldDelete = FindStorageDeleteByAccountTokenKey(
                state,
                ownerSymbol,
                tokenIdSymbol,
                indexPatterns,
                afterOffset: ownerRead.Op.Offset);
            if (oldDelete is null)
            {
                if (StorageMentionsAccountTokenSymbols(state, ownerSymbol, tokenIdSymbol)
                    || StorageMentionsAccountTokenSymbols(state, toSymbol, tokenIdSymbol))
                {
                    incompleteReasons.Add("true-return transfer uses tokensOf(owner) index storage keys the proof cannot yet normalize");
                    continue;
                }

                return new VerificationPropertyResult(
                    id,
                    methodName,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without deleting the previous owner/tokenId tokensOf(owner) index entry.",
                    "delete previous owner/tokenId index before returning true",
                    BuildStateWitness(smtBackend, state));
            }

            var newPut = FindStoragePutByAccountTokenKey(
                state,
                toSymbol,
                tokenIdSymbol,
                indexPatterns,
                afterOffset: ownerRead.Op.Offset);
            if (newPut is null)
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
                    "transfer can return true without writing the recipient/tokenId tokensOf(owner) index entry.",
                    "write recipient/tokenId index before returning true",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStoragePutByAccountTokenKey(state, ownerSymbol, tokenIdSymbol, indexPatterns, oldDelete.Op.Offset) is { } laterOldPut)
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
                    $"transfer deletes the previous tokensOf(owner) index entry and then restores it with Storage.Put at 0x{laterOldPut.Offset:X4}.",
                    "previous owner/tokenId index remains deleted after transfer",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageDeleteByAccountTokenKey(state, toSymbol, tokenIdSymbol, indexPatterns, newPut.Op.Offset) is { } laterNewDelete)
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
                    $"transfer writes the recipient tokensOf(owner) index entry and then deletes it at 0x{laterNewDelete.Offset:X4}.",
                    "recipient/tokenId index remains present after transfer",
                    BuildStateWitness(smtBackend, state));
            }
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
                Counterexample: null);
        }
        if (BuildIncompleteResult(id, methodName, description, transferExecution, obligations) is { } incomplete)
            return incomplete;
        if (BuildNoSuccessfulHaltIncompleteResult(id, methodName, description, transferExecution, obligations) is { } noHalt)
            return noHalt;

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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every true-return non-divisible NEP-11 transfer updates the tokensOf(owner) index from current owner/tokenId to recipient/tokenId",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11OwnerOfStorageConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.ownerof_storage_consistency.ownerOf";
        const string methodName = "ownerOf";
        const string description = "NEP-11 ownerOf(tokenId) must read the token owner storage updated by transfer.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep11NonDivisibleOwnerOfMethod) is not { } ownerOf)
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
                "NEP-11 manifest has no ownerOf(tokenId) method to compare against transfer owner storage",
                FailedCondition: null,
                Counterexample: null);
        }

        if (ownerOf.Offset < 0 || ownerOf.Offset >= program.Bytes.Length)
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
                $"ownerOf(tokenId) offset {ownerOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep11TransferOwnerKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
        if (transferPatterns.IsDefaultOrEmpty)
        {
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
                    Counterexample: null);
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
                "property holds vacuously: no true-return transfer owner storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var ownerOfExecution = RunMethodEntry(program, options, ownerOf);
        foreach (var reason in IncompleteReasons(ownerOfExecution))
            incompleteReasons.Add("ownerOf(tokenId): " + reason);

        var ownerOfPatterns = InferOwnerOfStorageKeyPatterns(ownerOf, ownerOfExecution, incompleteReasons);
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
                Counterexample: null);
        }

        if (ownerOfPatterns.IsDefaultOrEmpty)
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
                "ownerOf(tokenId) does not read transfer owner storage.",
                "ownerOf reads the same token owner key template as transfer",
                Counterexample: null);
        }

        var missingPattern = transferPatterns.FirstOrDefault(transferPattern =>
            !ownerOfPatterns.Any(ownerOfPattern => StorageKeysEqual(ownerOfPattern, transferPattern)));
        if (missingPattern is not null)
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
                $"ownerOf(tokenId) does not read transfer owner storage template {FormatStorageKey(missingPattern)}.",
                "ownerOf reads the same token owner key template as transfer",
                Counterexample: null);
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
            "ownerOf(tokenId) reads the same token owner storage template updated by transfer",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11OwnerOfReturnConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.ownerof_return_consistency.ownerOf";
        const string methodName = "ownerOf";
        const string description = "NEP-11 ownerOf(tokenId) must return the token owner storage value it reads.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep11NonDivisibleOwnerOfMethod) is not { } ownerOf)
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
                "NEP-11 manifest has no ownerOf(tokenId) method to compare against transfer owner storage",
                FailedCondition: null,
                Counterexample: null);
        }

        if (ownerOf.Offset < 0 || ownerOf.Offset >= program.Bytes.Length)
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
                $"ownerOf(tokenId) offset {ownerOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep11TransferOwnerKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
        if (transferPatterns.IsDefaultOrEmpty)
        {
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
                    Counterexample: null);
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
                "property holds vacuously: no true-return transfer owner storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var ownerOfExecution = RunMethodEntry(program, options, ownerOf);
        foreach (var reason in IncompleteReasons(ownerOfExecution))
            incompleteReasons.Add("ownerOf(tokenId): " + reason);

        var halted = ownerOfExecution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("ownerOf(tokenId) produced no successful HALT path");
        if (ownerOf.Parameters.Count == 0)
            incompleteReasons.Add("ownerOf(tokenId) has no tokenId parameter");

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
                Counterexample: null);
        }

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(ownerOf.Parameters[0].Name, 0);
        foreach (var state in halted)
        {
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
                    "ownerOf(tokenId) halts without returning the token owner.",
                    "ownerOf returns the token owner storage value",
                    BuildStateWitness(smtBackend, state));
            }

            var returnValue = state.Peek().Expression;
            foreach (var transferPattern in transferPatterns)
            {
                var matchingReads = state.Telemetry.StorageOps
                    .Where(op => op.Kind == StorageOpKind.Get)
                    .Where(op => TryAccountStorageKeyPattern(state, op.Key, tokenIdSymbol, out var pattern)
                                 && StorageKeysEqual(pattern, transferPattern))
                    .ToList();

                if (matchingReads.Count == 0)
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
                        "ownerOf(tokenId) does not read transfer owner storage before returning.",
                        "ownerOf returns the token owner storage value",
                        BuildStateWitness(smtBackend, state));
                }

                if (matchingReads.Any(read => ReturnMatchesStorageReadOrMissingNull(state, returnValue, read.Offset)))
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
                    "ownerOf(tokenId) does not return the storage value it reads.",
                    "ownerOf returns the token owner storage value",
                    BuildStateWitness(smtBackend, state));
            }
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
            "ownerOf(tokenId) returns the same token owner storage value it reads",
            FailedCondition: null,
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11BalanceOfStorageConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.balanceof_storage_consistency.balanceOf";
        const string methodName = "balanceOf";
        const string description = "Non-divisible NEP-11 balanceOf(owner) must read the owner balance storage updated by transfer.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep11NonDivisibleBalanceOfMethod) is not { } balanceOf)
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
                "NEP-11 manifest has no balanceOf(owner) method to compare against transfer owner balance storage",
                FailedCondition: null,
                Counterexample: null);
        }

        if (balanceOf.Offset < 0 || balanceOf.Offset >= program.Bytes.Length)
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
                $"balanceOf(owner) offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep11OwnerBalanceKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
        if (transferPatterns.IsDefaultOrEmpty)
        {
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
                    Counterexample: null);
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
                "property holds vacuously: no non-self true-return transfer owner balance storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var balanceOfExecution = RunMethodEntry(program, options, balanceOf);
        foreach (var reason in IncompleteReasons(balanceOfExecution))
            incompleteReasons.Add("balanceOf(owner): " + reason);

        var balanceOfPatterns = InferBalanceOfStorageKeyPatterns(balanceOf, balanceOfExecution, incompleteReasons);
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
                Counterexample: null);
        }

        if (balanceOfPatterns.IsDefaultOrEmpty)
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
                "balanceOf(owner) does not read transfer owner balance storage.",
                "balanceOf reads the same owner balance key template as transfer",
                Counterexample: null);
        }

        bool allTransferPatternsCovered = transferPatterns.All(transferPattern =>
            balanceOfPatterns.Any(balanceOfPattern => StorageKeysEqual(balanceOfPattern, transferPattern)));
        if (!allTransferPatternsCovered)
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
                "balanceOf(owner) reads a different owner balance key template than transfer updates.",
                "balanceOf reads the same owner balance key template as transfer",
                Counterexample: null);
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
            "balanceOf(owner) reads the same owner balance storage template updated by transfer",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11BalanceOfReturnConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.balanceof_return_consistency.balanceOf";
        const string methodName = "balanceOf";
        const string description = "Non-divisible NEP-11 balanceOf(owner) must return the owner balance storage value it reads.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep11NonDivisibleBalanceOfMethod) is not { } balanceOf)
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
                "NEP-11 manifest has no balanceOf(owner) method to compare against transfer owner balance storage",
                FailedCondition: null,
                Counterexample: null);
        }

        if (balanceOf.Offset < 0 || balanceOf.Offset >= program.Bytes.Length)
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
                $"balanceOf(owner) offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep11OwnerBalanceKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
        if (transferPatterns.IsDefaultOrEmpty)
        {
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
                    Counterexample: null);
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
                "property holds vacuously: no non-self true-return transfer owner balance storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var balanceOfExecution = RunMethodEntry(program, options, balanceOf);
        foreach (var reason in IncompleteReasons(balanceOfExecution))
            incompleteReasons.Add("balanceOf(owner): " + reason);

        var halted = balanceOfExecution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("balanceOf(owner) produced no successful HALT path");
        if (balanceOf.Parameters.Count == 0)
            incompleteReasons.Add("balanceOf(owner) has no owner parameter");

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
                Counterexample: null);
        }

        string ownerSymbol = SymbolicEngine.MethodEntryArgSymbolName(balanceOf.Parameters[0].Name, 0);
        foreach (var state in halted)
        {
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
                    "balanceOf(owner) halts without returning the owner balance.",
                    "balanceOf returns the owner balance storage value",
                    BuildStateWitness(smtBackend, state));
            }

            var returnValue = state.Peek().Expression;
            foreach (var transferPattern in transferPatterns)
            {
                var matchingReads = state.Telemetry.StorageOps
                    .Where(op => op.Kind == StorageOpKind.Get)
                    .Where(op => TryAccountStorageKeyPattern(state, op.Key, ownerSymbol, out var pattern)
                                 && StorageKeysEqual(pattern, transferPattern))
                    .ToList();

                if (matchingReads.Count == 0)
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
                        "balanceOf(owner) does not read transfer owner balance storage before returning.",
                        "balanceOf returns the owner balance storage value",
                        BuildStateWitness(smtBackend, state));
                }

                if (matchingReads.Any(read => ReturnMatchesStorageReadOrMissingZero(state, returnValue, read.Offset)))
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
                    "balanceOf(owner) does not return the storage value it reads.",
                    "balanceOf returns the owner balance storage value",
                    BuildStateWitness(smtBackend, state));
            }
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
            "balanceOf(owner) returns the same owner balance storage value it reads",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11FailureNoStateChangeResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.failure_no_state_change.{method.Name}";
        string description = "NEP-11 transfer false-return paths must not perform observable side effects.";
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
            var sideEffect = FalseReturnSideEffects(state, "false-return transfer path has no Storage.Put, Storage.Delete, Runtime.Notify, or external side-effect call")
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
                    $"transfer can return false after {sideEffect.Display}.",
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
                $"solver could not prove a side-effecting transfer path at 0x{sideEffect.Offset:X4} cannot return false",
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
                ? "property holds vacuously: no successful transfer path can return false"
                : "every false-return NEP-11 transfer path avoids Storage.Put, Storage.Delete, Runtime.Notify, and external side-effect calls",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11InvalidTokenFalseResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.invalid_token_false.{method.Name}";
        string description = "Non-divisible NEP-11 transfer must return false when tokenId has no current owner.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (tokenIdIndex < 0)
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
                "NEP-11 transfer method has no recognizable tokenId ByteString parameter",
                FailedCondition: null,
                Counterexample: null);
        }

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);

        foreach (var state in execution.Faulted)
        {
            var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
            if (ownerRead is null)
            {
                if (StorageMentionsTokenSymbol(state, tokenIdSymbol))
                    incompleteReasons.Add("faulted NEP-11 transfer path uses owner storage keys the token-key proof cannot yet normalize");
                continue;
            }

            if (!PathConditionsProveStorageReadMissing(state.PathConditions, ownerRead.Op.Offset))
                continue;

            obligations++;
            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"transfer faults instead of returning false when tokenId has no owner: {state.TerminationReason ?? "VM fault"}.",
                "transfer when tokenId has no owner returns false",
                BuildStateWitness(smtBackend, state));
        }

        bool hasCleanInvalidTokenFalsePath = false;
        foreach (var state in execution.Halted)
        {
            var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
            if (ownerRead is null)
            {
                if (StorageMentionsTokenSymbol(state, tokenIdSymbol))
                    incompleteReasons.Add("false-return NEP-11 transfer uses owner storage keys the token-key proof cannot yet normalize");
                continue;
            }

            if (!PathConditionsProveStorageReadMissing(state.PathConditions, ownerRead.Op.Offset))
            {
                if (TryReturnMayBeFalse(method, state, smtBackend, out bool maybeFalseWithoutMissingProof, out _, out var missingReturnReason)
                    && maybeFalseWithoutMissingProof)
                {
                    incompleteReasons.Add("false-return NEP-11 transfer path does not prove tokenId has no current owner");
                }
                else if (!string.IsNullOrEmpty(missingReturnReason))
                {
                    incompleteReasons.Add(missingReturnReason);
                }
                continue;
            }

            obligations++;
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var trueReturnReason))
            {
                incompleteReasons.Add(trueReturnReason);
                continue;
            }
            if (returnMayBeTrue)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "non-divisible NEP-11 transfer can return true when tokenId has no current owner.",
                    "transfer when tokenId has no owner returns false",
                    BuildStateWitness(smtBackend, state));
            }

            if (!TryReturnMayBeFalse(method, state, smtBackend, out bool returnMayBeFalse, out _, out var falseReturnReason))
            {
                incompleteReasons.Add(falseReturnReason);
                continue;
            }
            if (!returnMayBeFalse)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "non-divisible NEP-11 transfer reaches a missing-owner path without returning false.",
                    "transfer when tokenId has no owner returns false",
                    BuildStateWitness(smtBackend, state));
            }

            if (FalseReturnSideEffects(state, "invalid-token false-return path has no Storage.Put, Storage.Delete, Runtime.Notify, or external side-effect call")
                .Any())
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "non-divisible NEP-11 transfer can return false for missing owner after observable side effects.",
                    "invalid-token false-return path has no Storage.Put, Storage.Delete, Runtime.Notify, or external side-effect call",
                    BuildStateWitness(smtBackend, state));
            }

            hasCleanInvalidTokenFalsePath = true;
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

        return hasCleanInvalidTokenFalsePath
            ? new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Proved,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                "every proven non-divisible NEP-11 missing-owner transfer path returns false without side effects",
                FailedCondition: null,
                Counterexample: null)
            : new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                "NEP-11 transfer has no feasible false-return path for tokenId without a current owner.",
                "transfer when tokenId has no owner returns false",
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleInsufficientBalanceFalseResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.insufficient_balance_false.{method.Name}";
        string description = "Divisible NEP-11 transfer must return false when from token balance is below amount.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0 || tokenIdIndex < 0)
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
                "divisible NEP-11 transfer method has no recognizable from/to/amount/tokenId parameters",
                FailedCondition: null,
                Counterexample: null);
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);

        foreach (var state in execution.Faulted)
        {
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
                continue;
            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
                continue;

            var fromGet = FindStorageGetByAccountTokenKey(state, fromSymbol, tokenIdSymbol);
            if (fromGet is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol, tokenIdSymbol))
                    incompleteReasons.Add("faulted divisible transfer path uses token balance storage keys the account/tokenId proof cannot yet normalize");
                continue;
            }

            obligations++;
            if (!PathConditionsProveStorageReadBelowAmount(state.PathConditions, fromGet.Op.Offset, amountSymbol))
                continue;

            return new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                $"transfer faults instead of returning false when from token balance is insufficient: {state.TerminationReason ?? "VM fault"}.",
                "non-self transfer with from token balance < amount returns false",
                BuildStateWitness(smtBackend, state));
        }

        bool hasCleanInsufficientBalanceFalsePath = false;
        foreach (var state in execution.Halted)
        {
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
                continue;
            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                if (TryReturnMayBeFalse(method, state, smtBackend, out bool maybeFalseOnUnclassifiedSelf, out _, out var selfReturnReason)
                    && maybeFalseOnUnclassifiedSelf)
                {
                    incompleteReasons.Add("false-return divisible transfer path does not prove whether from == to or from != to");
                }
                else if (!string.IsNullOrEmpty(selfReturnReason))
                {
                    incompleteReasons.Add(selfReturnReason);
                }
                continue;
            }

            var fromGet = FindStorageGetByAccountTokenKey(state, fromSymbol, tokenIdSymbol);
            if (fromGet is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol, tokenIdSymbol))
                {
                    incompleteReasons.Add("false-return divisible transfer uses token balance storage keys the account/tokenId proof cannot yet normalize");
                    continue;
                }

                if (TryReturnMayBeFalse(method, state, smtBackend, out bool maybeFalseWithoutBalanceRead, out _, out var noBalanceReturnReason)
                    && maybeFalseWithoutBalanceRead)
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        "transfer can return false without reading the from token balance.",
                        "non-self transfer with from token balance < amount returns false",
                        BuildStateWitness(smtBackend, state));
                }
                if (!string.IsNullOrEmpty(noBalanceReturnReason))
                    incompleteReasons.Add(noBalanceReturnReason);
                continue;
            }

            if (!PathConditionsProveStorageReadBelowAmount(state.PathConditions, fromGet.Op.Offset, amountSymbol))
            {
                if (TryReturnMayBeFalse(method, state, smtBackend, out bool maybeFalseWithoutInsufficientProof, out _, out var insufficientReturnReason)
                    && maybeFalseWithoutInsufficientProof)
                {
                    incompleteReasons.Add("false-return divisible transfer path does not prove from token balance < amount");
                }
                else if (!string.IsNullOrEmpty(insufficientReturnReason))
                {
                    incompleteReasons.Add(insufficientReturnReason);
                }
                continue;
            }

            obligations++;
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var trueReturnReason))
            {
                incompleteReasons.Add(trueReturnReason);
                continue;
            }
            if (returnMayBeTrue)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "non-self divisible NEP-11 transfer can return true when from token balance < amount.",
                    "non-self transfer with from token balance < amount returns false",
                    BuildStateWitness(smtBackend, state));
            }

            if (!TryReturnMayBeFalse(method, state, smtBackend, out bool returnMayBeFalse, out _, out var falseReturnReason))
            {
                incompleteReasons.Add(falseReturnReason);
                continue;
            }
            if (!returnMayBeFalse)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "non-self divisible NEP-11 transfer reaches a proven insufficient-balance path without returning false.",
                    "non-self transfer with from token balance < amount returns false",
                    BuildStateWitness(smtBackend, state));
            }

            if (FalseReturnSideEffects(state, "insufficient-balance false-return path has no Storage.Put, Storage.Delete, Runtime.Notify, or external side-effect call")
                .Any())
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "non-self divisible NEP-11 transfer can return false for insufficient balance after observable side effects.",
                    "insufficient-balance false-return path has no Storage.Put, Storage.Delete, Runtime.Notify, or external side-effect call",
                    BuildStateWitness(smtBackend, state));
            }

            hasCleanInsufficientBalanceFalsePath = true;
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

        return hasCleanInsufficientBalanceFalsePath
            ? new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Proved,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                "every proven non-self divisible NEP-11 insufficient-balance transfer path returns false without side effects",
                FailedCondition: null,
                Counterexample: null)
            : new VerificationPropertyResult(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                obligations,
                "Divisible NEP-11 transfer has no feasible false-return path for insufficient from token balance.",
                "non-self transfer with from token balance < amount returns false",
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleBalanceDeltaResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.balance_delta.{method.Name}";
        string description = "Divisible NEP-11 transfer true-return paths must debit from and credit to token balances by amount.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        var incompleteReasons = new List<string>();

        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0 || tokenIdIndex < 0)
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
                "divisible NEP-11 transfer method has no recognizable from/to/amount/tokenId parameters",
                FailedCondition: null,
                Counterexample: null);
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);

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
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                if (SelfTransferTokenBalanceMutation(state, fromSymbol, toSymbol, tokenIdSymbol, out var mutation, out var mutationReason))
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"self-transfer can return true after {mutation!.Kind} mutates a token balance key at 0x{mutation.Offset:X4}.",
                        "self-transfer leaves token balance storage unchanged",
                        BuildStateWitness(smtBackend, state));
                }

                if (!string.IsNullOrWhiteSpace(mutationReason))
                    incompleteReasons.Add(mutationReason);
                continue;
            }

            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return divisible NEP-11 transfer path does not prove whether from == to or from != to");
                continue;
            }

            var fromGet = FindStorageGetByAccountTokenKey(state, fromSymbol, tokenIdSymbol);
            var toGet = FindStorageGetByAccountTokenKey(state, toSymbol, tokenIdSymbol);
            var fromPut = fromGet is null ? null : FindStoragePutByAccountTokenKey(state, fromSymbol, tokenIdSymbol, fromGet.Pattern, fromGet.Op.Offset);
            var toPut = toGet is null ? null : FindStoragePutByAccountTokenKey(state, toSymbol, tokenIdSymbol, toGet.Pattern, toGet.Op.Offset);

            if (fromGet is null || toGet is null || fromPut is null || toPut is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol, tokenIdSymbol))
                {
                    incompleteReasons.Add("true-return divisible NEP-11 transfer uses token balance storage keys the proof cannot yet normalize");
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
                    "transfer can return true without direct from/to token balance read-write pairs.",
                    "true-return transfer writes from'=from-amount and to'=to+amount for the same tokenId",
                    BuildStateWitness(smtBackend, state));
            }

            if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer reads from/to token balances through different storage key templates.",
                    "from and to token balances use the same account/tokenId key template",
                    BuildStateWitness(smtBackend, state));
            }

            if (!PathConditionsProveStorageReadAtLeastAmount(state.PathConditions, fromGet.Op.Offset, amountSymbol))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without proving the from token balance is at least amount before debit.",
                    "from token balance is at least amount before debit",
                    BuildStateWitness(smtBackend, state));
            }

            if (!ValueMatchesBalanceDelta(fromPut.Op.Value?.Expression, state, fromGet.Op.Offset, amountSymbol, subtract: true))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer writes the from token balance at 0x{fromPut.Op.Offset:X4} without subtracting amount from its prior value.",
                    "from token balance write equals previous from token balance minus amount",
                    BuildStateWitness(smtBackend, state));
            }

            if (!ValueMatchesBalanceDelta(toPut.Op.Value?.Expression, state, toGet.Op.Offset, amountSymbol, subtract: false))
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer writes the to token balance at 0x{toPut.Op.Offset:X4} without adding amount to its prior value.",
                    "to token balance write equals previous to token balance plus amount",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageMutationByAccountTokenKey(state, fromSymbol, tokenIdSymbol, fromGet.Pattern, fromPut.Op.Offset) is { } laterFrom)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer mutates the from token balance again with {laterFrom.Kind} at 0x{laterFrom.Offset:X4} after the proved debit.",
                    "final from token balance remains previous from token balance minus amount",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageMutationByAccountTokenKey(state, toSymbol, tokenIdSymbol, toGet.Pattern, toPut.Op.Offset) is { } laterTo)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    $"transfer mutates the to token balance again with {laterTo.Kind} at 0x{laterTo.Offset:X4} after the proved credit.",
                    "final to token balance remains previous to token balance plus amount",
                    BuildStateWitness(smtBackend, state));
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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every true-return divisible NEP-11 transfer path either leaves self-transfer balance unchanged or debits from and credits to by amount for the same tokenId",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleOwnerOfIndexResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.ownerof_index.transfer";
        const string methodName = "transfer";
        const string description = "Divisible NEP-11 transfer true-return paths must keep ownerOf(tokenId) owner enumeration indexes in sync.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, "ownerOf", IsNep11DivisibleOwnerOfMethod) is not { } ownerOf)
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
                "NEP-11 manifest has no divisible ownerOf(tokenId) method to compare against transfer owner indexes",
                FailedCondition: null,
                Counterexample: null);
        }

        if (ownerOf.Offset < 0 || ownerOf.Offset >= program.Bytes.Length)
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
                $"ownerOf(tokenId) offset {ownerOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        int fromIndex = FindFromParameter(transfer);
        int toIndex = FindToParameter(transfer);
        int amountIndex = FindAmountParameter(transfer);
        int tokenIdIndex = FindNep11TokenIdParameter(transfer);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0 || tokenIdIndex < 0)
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
                "divisible NEP-11 transfer method has no recognizable from/to/amount/tokenId parameters",
                FailedCondition: null,
                Counterexample: null);
        }

        var ownerOfExecution = RunMethodEntry(program, options, ownerOf);
        foreach (var reason in IncompleteReasons(ownerOfExecution))
            incompleteReasons.Add("ownerOf(tokenId): " + reason);

        var ownerIndexPatterns = InferNep11DivisibleOwnerOfIndexKeyPatterns(ownerOf, ownerOfExecution, incompleteReasons);
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
                Counterexample: null);
        }

        if (ownerIndexPatterns.IsDefaultOrEmpty)
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
                "ownerOf(tokenId) did not expose a supported tokenId/owner Storage.Find index key template",
                FailedCondition: null,
                Counterexample: null);
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(transfer.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(transfer.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(transfer.Parameters[tokenIdIndex].Name, tokenIdIndex);

        foreach (var state in transferExecution.Halted)
        {
            if (!TryReturnMayBeTrue(transfer, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            obligations++;
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                if (FindAnyStorageMutationByAccountTokenKey(state, fromSymbol, tokenIdSymbol, ownerIndexPatterns, afterOffset: 0) is { } mutation)
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
                        $"self-transfer can return true after {mutation.Kind} mutates an ownerOf(tokenId) index key at 0x{mutation.Offset:X4}.",
                        "self-transfer leaves ownerOf(tokenId) index unchanged",
                        BuildStateWitness(smtBackend, state));
                }

                continue;
            }

            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return divisible NEP-11 transfer path does not prove whether from == to or from != to for ownerOf(tokenId) index maintenance");
                continue;
            }

            var fromGet = FindStorageGetByAccountTokenKey(state, fromSymbol, tokenIdSymbol);
            var toGet = FindStorageGetByAccountTokenKey(state, toSymbol, tokenIdSymbol);
            var fromPut = fromGet is null ? null : FindStoragePutByAccountTokenKey(state, fromSymbol, tokenIdSymbol, fromGet.Pattern, fromGet.Op.Offset);
            var toPut = toGet is null ? null : FindStoragePutByAccountTokenKey(state, toSymbol, tokenIdSymbol, toGet.Pattern, toGet.Op.Offset);

            if (fromGet is null || toGet is null || fromPut is null || toPut is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol, tokenIdSymbol))
                {
                    incompleteReasons.Add("true-return divisible NEP-11 transfer uses token balance storage keys the ownerOf(tokenId) index proof cannot yet normalize");
                    continue;
                }

                return new VerificationPropertyResult(
                    id,
                    methodName,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true without direct from/to token balance read-write pairs for ownerOf(tokenId) index maintenance.",
                    "ownerOf(tokenId) index update is based on final from/to token balances",
                    BuildStateWitness(smtBackend, state));
            }

            if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
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
                    "transfer reads from/to token balances through different storage key templates before ownerOf(tokenId) index maintenance.",
                    "from and to token balances use the same account/tokenId key template",
                    BuildStateWitness(smtBackend, state));
            }

            if (fromPut.Op.Value?.Expression is not { } finalFromBalance
                || toPut.Op.Value?.Expression is not { } finalToBalance)
            {
                incompleteReasons.Add("true-return divisible NEP-11 transfer writes a token balance value the ownerOf(tokenId) index proof cannot inspect");
                continue;
            }

            var oldDelete = FindStorageDeleteByAccountTokenKey(
                state,
                fromSymbol,
                tokenIdSymbol,
                ownerIndexPatterns,
                afterOffset: fromGet.Op.Offset);
            var newPut = FindStoragePutByAccountTokenKey(
                state,
                toSymbol,
                tokenIdSymbol,
                ownerIndexPatterns,
                afterOffset: toGet.Op.Offset);

            if (!TrySatisfiability(state, smtBackend, Expr.NumEq(finalFromBalance, Expr.Int(0)), out var finalFromMayBeZero, out var finalFromReason))
            {
                incompleteReasons.Add(finalFromReason);
                continue;
            }

            if (oldDelete is null)
            {
                if (finalFromMayBeZero == SmtOutcome.Sat)
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
                        "transfer can return true while the sender's final token balance is zero without deleting the sender/tokenId ownerOf(tokenId) index entry.",
                        "delete sender/tokenId ownerOf index when sender final balance is zero",
                        BuildStateWitness(smtBackend, state));
                }
            }
            else if (!TrySatisfiability(state, smtBackend, Expr.Gt(finalFromBalance, Expr.Int(0)), out var finalFromMayBePositive, out var finalFromPositiveReason))
            {
                incompleteReasons.Add(finalFromPositiveReason);
                continue;
            }
            else if (finalFromMayBePositive == SmtOutcome.Sat)
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
                    $"transfer deletes the sender/tokenId ownerOf(tokenId) index entry at 0x{oldDelete.Op.Offset:X4} even though the sender can retain a positive final token balance.",
                    "sender/tokenId ownerOf index remains present while sender final balance is positive",
                    BuildStateWitness(smtBackend, state));
            }

            if (!TrySatisfiability(state, smtBackend, Expr.Gt(finalToBalance, Expr.Int(0)), out var finalToMayBePositive, out var finalToReason))
            {
                incompleteReasons.Add(finalToReason);
                continue;
            }

            if (newPut is null)
            {
                if (finalToMayBePositive == SmtOutcome.Sat)
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
                        "transfer can return true while the recipient's final token balance is positive without writing the recipient/tokenId ownerOf(tokenId) index entry.",
                        "write recipient/tokenId ownerOf index when recipient final balance is positive",
                        BuildStateWitness(smtBackend, state));
                }
            }
            else if (!TrySatisfiability(state, smtBackend, Expr.NumEq(finalToBalance, Expr.Int(0)), out var finalToMayBeZero, out var finalToZeroReason))
            {
                incompleteReasons.Add(finalToZeroReason);
                continue;
            }
            else if (finalToMayBeZero == SmtOutcome.Sat)
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
                    $"transfer writes the recipient/tokenId ownerOf(tokenId) index entry at 0x{newPut.Op.Offset:X4} even though the recipient final token balance can be zero.",
                    "recipient/tokenId ownerOf index is present only when recipient final balance is positive",
                    BuildStateWitness(smtBackend, state));
            }

            if (oldDelete is not null
                && FindLaterStoragePutByAccountTokenKey(state, fromSymbol, tokenIdSymbol, ownerIndexPatterns, oldDelete.Op.Offset) is { } laterOldPut)
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
                    $"transfer deletes the sender ownerOf(tokenId) index entry and then restores it with Storage.Put at 0x{laterOldPut.Offset:X4}.",
                    "sender/tokenId ownerOf index remains deleted when sender final balance is zero",
                    BuildStateWitness(smtBackend, state));
            }

            if (newPut is not null
                && FindLaterStorageDeleteByAccountTokenKey(state, toSymbol, tokenIdSymbol, ownerIndexPatterns, newPut.Op.Offset) is { } laterNewDelete)
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
                    $"transfer writes the recipient ownerOf(tokenId) index entry and then deletes it at 0x{laterNewDelete.Offset:X4}.",
                    "recipient/tokenId ownerOf index remains present when recipient final balance is positive",
                    BuildStateWitness(smtBackend, state));
            }
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
                Counterexample: null);
        }
        if (BuildIncompleteResult(id, methodName, description, transferExecution, obligations) is { } incomplete)
            return incomplete;
        if (BuildNoSuccessfulHaltIncompleteResult(id, methodName, description, transferExecution, obligations) is { } noHalt)
            return noHalt;

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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every true-return divisible NEP-11 transfer keeps ownerOf(tokenId) owner indexes synchronized with final token balances",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleBalanceOfStorageConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.balanceof_storage_consistency.balanceOf";
        const string methodName = "balanceOf";
        const string description = "Divisible NEP-11 balanceOf(owner, tokenId) must read the token balance storage updated by transfer.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep11DivisibleBalanceOfMethod) is not { } balanceOf)
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
                "NEP-11 manifest has no balanceOf(owner, tokenId) method to compare against transfer balance storage",
                FailedCondition: null,
                Counterexample: null);
        }

        if (balanceOf.Offset < 0 || balanceOf.Offset >= program.Bytes.Length)
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
                $"balanceOf(owner, tokenId) offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep11DivisibleTransferBalanceKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
        if (transferPatterns.IsDefaultOrEmpty)
        {
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
                    Counterexample: null);
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
                "property holds vacuously: no non-self true-return transfer token balance storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var balanceOfExecution = RunMethodEntry(program, options, balanceOf);
        foreach (var reason in IncompleteReasons(balanceOfExecution))
            incompleteReasons.Add("balanceOf(owner, tokenId): " + reason);

        var balanceOfPatterns = InferDivisibleBalanceOfStorageKeyPatterns(balanceOf, balanceOfExecution, incompleteReasons);
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
                Counterexample: null);
        }

        if (balanceOfPatterns.IsDefaultOrEmpty)
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
                "balanceOf(owner, tokenId) does not read transfer balance storage.",
                "balanceOf reads the same owner/tokenId balance key template as transfer",
                Counterexample: null);
        }

        var missingPattern = transferPatterns.FirstOrDefault(transferPattern =>
            !balanceOfPatterns.Any(balanceOfPattern => StorageKeysEqual(balanceOfPattern, transferPattern)));
        if (missingPattern is not null)
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
                $"balanceOf(owner, tokenId) reads a different balance key template than transfer updates: missing {FormatStorageKey(missingPattern)}.",
                "balanceOf reads the same owner/tokenId balance key template as transfer",
                Counterexample: null);
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
            "balanceOf(owner, tokenId) reads the same token balance storage template updated by transfer",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleBalanceOfReturnConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep11.balanceof_return_consistency.balanceOf";
        const string methodName = "balanceOf";
        const string description = "Divisible NEP-11 balanceOf(owner, tokenId) must return the token balance storage value it reads.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep11DivisibleBalanceOfMethod) is not { } balanceOf)
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
                "NEP-11 manifest has no balanceOf(owner, tokenId) method to compare against transfer balance storage",
                FailedCondition: null,
                Counterexample: null);
        }

        if (balanceOf.Offset < 0 || balanceOf.Offset >= program.Bytes.Length)
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
                $"balanceOf(owner, tokenId) offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep11DivisibleTransferBalanceKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
        if (transferPatterns.IsDefaultOrEmpty)
        {
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
                    Counterexample: null);
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
                "property holds vacuously: no non-self true-return transfer token balance storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var balanceOfExecution = RunMethodEntry(program, options, balanceOf);
        foreach (var reason in IncompleteReasons(balanceOfExecution))
            incompleteReasons.Add("balanceOf(owner, tokenId): " + reason);

        var halted = balanceOfExecution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("balanceOf(owner, tokenId) produced no successful HALT path");
        if (balanceOf.Parameters.Count < 2)
            incompleteReasons.Add("balanceOf(owner, tokenId) has no owner/tokenId parameters");

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
                Counterexample: null);
        }

        string ownerSymbol = SymbolicEngine.MethodEntryArgSymbolName(balanceOf.Parameters[0].Name, 0);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(balanceOf.Parameters[1].Name, 1);
        foreach (var state in halted)
        {
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
                    "balanceOf(owner, tokenId) halts without returning the token balance.",
                    "balanceOf returns the owner/tokenId balance storage value",
                    BuildStateWitness(smtBackend, state));
            }

            var returnValue = state.Peek().Expression;
            foreach (var transferPattern in transferPatterns)
            {
                var matchingReads = state.Telemetry.StorageOps
                    .Where(op => op.Kind == StorageOpKind.Get)
                    .Where(op => TryAccountTokenStorageKeyPattern(state, op.Key, ownerSymbol, tokenIdSymbol, out var pattern)
                                 && StorageKeysEqual(pattern, transferPattern))
                    .ToList();

                if (matchingReads.Count == 0)
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
                        "balanceOf(owner, tokenId) does not read transfer balance storage before returning.",
                        "balanceOf returns the owner/tokenId balance storage value",
                        BuildStateWitness(smtBackend, state));
                }

                if (matchingReads.Any(read => ReturnMatchesStorageReadOrMissingZero(state, returnValue, read.Offset)))
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
                    "balanceOf(owner, tokenId) does not return the storage value it reads.",
                    "balanceOf returns the owner/tokenId balance storage value",
                    BuildStateWitness(smtBackend, state));
            }
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
            "balanceOf(owner, tokenId) returns the same token balance storage value it reads",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11TransferEventResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.transfer_event.{method.Name}";
        string description = "NEP-11 transfer success paths must emit Transfer(owner,to,1,tokenId).";
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
            var transferNotifications = CurrentTransferNotifications(state, currentScriptHash).ToList();
            if (transferNotifications.Any(n => Nep11TransferNotificationPayloadMatches(state, method, n, currentScriptHash)))
                continue;

            if (transferNotifications.Count > 0)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true while emitting Transfer with the wrong NEP-11 payload shape or argument binding.",
                    "true-return transfer emits Transfer(owner,to,1,tokenId)",
                    BuildStateWitness(smtBackend, state));
            }

            if (state.Telemetry.Notifications.Any(n => n.ConcreteName is null))
            {
                incompleteReasons.Add("transfer path emits a notification with symbolic or unknown event name");
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
                "transfer can return true without emitting a Transfer notification.",
                "true-return transfer emits Transfer(owner,to,1,tokenId)",
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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every successful true-return NEP-11 transfer emits Transfer(owner,to,1,tokenId)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11CallbackOrderPayloadResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.callback_order_payload.{method.Name}";
        string description = "NEP-11 receiver callbacks must target `to`, follow Transfer, and pass (owner, 1, tokenId, data).";
        var counts = CountPaths(execution);
        int obligations = 0;
        int receiverAbsenceObligations = 0;
        var incompleteReasons = new List<string>();

        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        int dataIndex = FindDataParameter(method);
        if (toIndex < 0 || tokenIdIndex < 0 || dataIndex < 0)
            incompleteReasons.Add("NEP-11 transfer method does not expose recognizable to/tokenId/data parameters");

        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool sawPaymentCallback = false;
            bool sawDynamicSelector = false;
            foreach (var call in state.Telemetry.ExternalCalls.Where(c => !c.ModeledSelfCall).OrderBy(c => c.Offset))
            {
                if (call.MethodDynamic)
                {
                    sawDynamicSelector = true;
                    incompleteReasons.Add(
                        $"true-return transfer path has a dynamic external call selector at 0x{call.Offset:X4} that may be onNEP11Payment");
                    continue;
                }

                if (!IsNep11PaymentCallback(call))
                    continue;

                sawPaymentCallback = true;
                obligations++;
                if (!Nep11CallbackTargetsRecipient(method, call))
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"onNEP11Payment call at 0x{call.Offset:X4} does not target the transfer `to` argument.",
                        "onNEP11Payment target is transfer.to",
                        BuildStateWitness(smtBackend, state));
                }

                if (!Nep11CallbackPayloadMatches(state, method, call))
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"onNEP11Payment call at 0x{call.Offset:X4} has wrong argument binding.",
                        "onNEP11Payment(owner, 1, tokenId, data)",
                        BuildStateWitness(smtBackend, state));
                }

                if (HasPriorMatchingNep11TransferNotification(state, method, currentScriptHash, call.Offset))
                    continue;

                if (state.Telemetry.Notifications.Any(n => n.Offset < call.Offset && n.ConcreteName is null))
                {
                    incompleteReasons.Add(
                        $"onNEP11Payment call at 0x{call.Offset:X4} is preceded by a notification with symbolic or unknown event name");
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
                    $"onNEP11Payment call at 0x{call.Offset:X4} can occur before Transfer(owner, to, 1, tokenId).",
                    "onNEP11Payment occurs after Transfer(owner, to, 1, tokenId)",
                    BuildStateWitness(smtBackend, state));
            }

            if (!sawPaymentCallback && !sawDynamicSelector)
            {
                if (HasReceiverContractAbsenceProof(state, method))
                {
                    receiverAbsenceObligations++;
                    obligations++;
                    continue;
                }

                incompleteReasons.Add(
                    "true-return transfer path does not call onNEP11Payment; verifier cannot prove the receiver is not a contract");
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
                ? "property holds vacuously: no true-return transfer path calls onNEP11Payment"
                : receiverAbsenceObligations > 0
                    ? "every true-return NEP-11 transfer path either proves the receiver is not a contract or calls onNEP11Payment after Transfer with (owner, 1, tokenId, data)"
                : "every observed true-return NEP-11 onNEP11Payment call targets to, follows Transfer, and passes (owner, 1, tokenId, data)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleTransferEventResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.transfer_event.{method.Name}";
        string description = "Divisible NEP-11 transfer success paths must emit Transfer(from,to,amount,tokenId).";
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
            var transferNotifications = CurrentTransferNotifications(state, currentScriptHash).ToList();
            if (transferNotifications.Any(n => Nep11DivisibleTransferNotificationPayloadMatches(state, method, n, currentScriptHash)))
                continue;

            if (transferNotifications.Count > 0)
            {
                return new VerificationPropertyResult(
                    id,
                    method.Name,
                    description,
                    VerificationStatus.Violated,
                    counts.CheckedPaths,
                    counts.IgnoredFaultedPaths,
                    counts.StoppedPaths,
                    obligations,
                    "transfer can return true while emitting Transfer with the wrong divisible NEP-11 payload shape or argument binding.",
                    "true-return transfer emits Transfer(from,to,amount,tokenId)",
                    BuildStateWitness(smtBackend, state));
            }

            if (state.Telemetry.Notifications.Any(n => n.ConcreteName is null))
            {
                incompleteReasons.Add("transfer path emits a notification with symbolic or unknown event name");
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
                "transfer can return true without emitting a Transfer notification.",
                "true-return transfer emits Transfer(from,to,amount,tokenId)",
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
                ? "property holds vacuously: no successful transfer path can return true"
                : "every successful true-return divisible NEP-11 transfer emits Transfer(from,to,amount,tokenId)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11DivisibleCallbackOrderPayloadResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep11.callback_order_payload.{method.Name}";
        string description = "Divisible NEP-11 receiver callbacks must target `to`, follow Transfer, and pass (from, amount, tokenId, data).";
        var counts = CountPaths(execution);
        int obligations = 0;
        int receiverAbsenceObligations = 0;
        var incompleteReasons = new List<string>();

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        int dataIndex = FindDataParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0 || tokenIdIndex < 0 || dataIndex < 0)
        {
            incompleteReasons.Add("divisible NEP-11 transfer method does not expose recognizable from/to/amount/tokenId/data parameters");
        }

        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            bool sawPaymentCallback = false;
            bool sawDynamicSelector = false;
            foreach (var call in state.Telemetry.ExternalCalls.Where(c => !c.ModeledSelfCall).OrderBy(c => c.Offset))
            {
                if (call.MethodDynamic)
                {
                    sawDynamicSelector = true;
                    incompleteReasons.Add(
                        $"true-return transfer path has a dynamic external call selector at 0x{call.Offset:X4} that may be onNEP11Payment");
                    continue;
                }

                if (!IsNep11PaymentCallback(call))
                    continue;

                sawPaymentCallback = true;
                obligations++;
                if (!Nep11CallbackTargetsRecipient(method, call))
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"onNEP11Payment call at 0x{call.Offset:X4} does not target the transfer `to` argument.",
                        "onNEP11Payment target is transfer.to",
                        BuildStateWitness(smtBackend, state));
                }

                if (!Nep11DivisibleCallbackPayloadMatches(method, call))
                {
                    return new VerificationPropertyResult(
                        id,
                        method.Name,
                        description,
                        VerificationStatus.Violated,
                        counts.CheckedPaths,
                        counts.IgnoredFaultedPaths,
                        counts.StoppedPaths,
                        obligations,
                        $"onNEP11Payment call at 0x{call.Offset:X4} has wrong argument binding.",
                        "onNEP11Payment(from, amount, tokenId, data)",
                        BuildStateWitness(smtBackend, state));
                }

                if (HasPriorMatchingNep11DivisibleTransferNotification(state, method, currentScriptHash, call.Offset))
                    continue;

                if (state.Telemetry.Notifications.Any(n => n.Offset < call.Offset && n.ConcreteName is null))
                {
                    incompleteReasons.Add(
                        $"onNEP11Payment call at 0x{call.Offset:X4} is preceded by a notification with symbolic or unknown event name");
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
                    $"onNEP11Payment call at 0x{call.Offset:X4} can occur before Transfer(from, to, amount, tokenId).",
                    "onNEP11Payment occurs after Transfer(from, to, amount, tokenId)",
                    BuildStateWitness(smtBackend, state));
            }

            if (!sawPaymentCallback && !sawDynamicSelector)
            {
                if (HasReceiverContractAbsenceProof(state, method))
                {
                    receiverAbsenceObligations++;
                    obligations++;
                    continue;
                }

                incompleteReasons.Add(
                    "true-return transfer path does not call onNEP11Payment; verifier cannot prove the receiver is not a contract");
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
                ? "property holds vacuously: no true-return transfer path calls onNEP11Payment"
                : receiverAbsenceObligations > 0
                    ? "every true-return divisible NEP-11 transfer path either proves the receiver is not a contract or calls onNEP11Payment after Transfer with (from, amount, tokenId, data)"
                : "every observed true-return divisible NEP-11 onNEP11Payment call targets to, follows Transfer, and passes (from, amount, tokenId, data)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep11TotalSupplyConservationResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend) =>
        BuildTokenTotalSupplyConservationResult(
            manifest,
            method,
            transferExecution,
            program,
            options,
            smtBackend,
            standardId: "nep11",
            standardName: "NEP-11");

    private static VerificationPropertyResult BuildNep11TotalSupplyReturnConsistencyResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options) =>
        BuildTokenTotalSupplyReturnConsistencyResult(
            manifest,
            program,
            options,
            standardId: "nep11",
            standardName: "NEP-11");

    private static VerificationPropertyResult BuildNep11TotalSupplyNonNegativeResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend) =>
        BuildTokenTotalSupplyNonNegativeResult(
            manifest,
            program,
            options,
            smtBackend,
            standardId: "nep11",
            standardName: "NEP-11");

    private static VerificationPropertyResult BuildNep11BalanceOfNonNegativeResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        var nonDivisible = FindAbiMethod(manifest, "balanceOf", IsNep11NonDivisibleBalanceOfMethod);
        var divisible = FindAbiMethod(manifest, "balanceOf", IsNep11DivisibleBalanceOfMethod);
        if (nonDivisible is not null && divisible is not null)
        {
            return new VerificationPropertyResult(
                "security.nep11.balanceof_non_negative.balanceOf",
                "balanceOf",
                "NEP-11 balanceOf(...) must return a non-negative integer.",
                VerificationStatus.Incomplete,
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                Reason: "NEP-11 manifest exposes both non-divisible and divisible balanceOf method shapes; balance non-negativity cannot choose one proof profile",
                FailedCondition: null,
                Counterexample: null);
        }

        return (nonDivisible ?? divisible) is { } balanceOf
            ? BuildTokenBalanceOfNonNegativeResult(
                balanceOf,
                program,
                options,
                smtBackend,
                standardId: "nep11",
                standardName: "NEP-11",
                methodSignature: divisible is not null ? "balanceOf(owner, tokenId)" : "balanceOf(owner)")
            : BuildMissingBalanceOfNonNegativeResult(
                standardId: "nep11",
                standardName: "NEP-11",
                methodSignature: "balanceOf(owner[, tokenId])");
    }
}
