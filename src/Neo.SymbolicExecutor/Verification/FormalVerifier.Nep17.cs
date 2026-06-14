using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    private static VerificationPropertyResult BuildNep17AbiResult(ContractManifest manifest)
    {
        const string id = "security.nep17.abi.*";
        const string method = "*";
        const string description = "Contracts declaring NEP-17 must expose the required ABI methods and Transfer event shape.";
        const int obligations = 6;

        if (FindAbiMethod(manifest, "symbol", IsStringSafeNoParameterMethod) is null)
        {
            if (FindAbiMethod(manifest, "symbol") is null)
                return Violated("NEP-17 manifest is missing method symbol.", "NEP-17 ABI declares symbol()");
            return Violated("NEP-17 method symbol must be safe=true with no parameters and String return type.",
                "symbol(): String safe=true");
        }
        if (FindAbiMethod(manifest, "decimals", IsIntegerSafeNoParameterMethod) is null)
        {
            if (FindAbiMethod(manifest, "decimals") is null)
                return Violated("NEP-17 manifest is missing method decimals.", "NEP-17 ABI declares decimals()");
            return Violated("NEP-17 method decimals must be safe=true with no parameters and Integer return type.",
                "decimals(): Integer safe=true");
        }

        if (FindAbiMethod(manifest, "totalSupply", IsIntegerSafeNoParameterMethod) is null)
        {
            if (FindAbiMethod(manifest, "totalSupply") is null)
                return Violated("NEP-17 manifest is missing method totalSupply.", "NEP-17 ABI declares totalSupply()");
            return Violated("NEP-17 method totalSupply must be safe=true with no parameters and Integer return type.",
                "totalSupply(): Integer safe=true");
        }

        if (FindAbiMethod(manifest, "balanceOf", IsNep17BalanceOfMethod) is null)
        {
            if (FindAbiMethod(manifest, "balanceOf") is null)
                return Violated("NEP-17 manifest is missing method balanceOf.", "NEP-17 ABI declares balanceOf(account)");
            return Violated("NEP-17 method balanceOf must be safe=true with (Hash160 account) and Integer return type.",
                "balanceOf(Hash160 account): Integer safe=true");
        }

        if (FindAbiMethod(manifest, "transfer", IsNep17TransferMethodShape) is null)
        {
            if (FindAbiMethod(manifest, "transfer") is null)
                return Violated("NEP-17 manifest is missing method transfer.", "NEP-17 ABI declares transfer(from,to,amount,data)");
            return Violated("NEP-17 method transfer must be safe=false with standard parameters (Hash160 from, Hash160 to, Integer amount, Any data) and Boolean return type.",
                "transfer(Hash160 from, Hash160 to, Integer amount, Any data): Boolean safe=false");
        }

        var transferEvent = manifest.Abi.Events.FirstOrDefault(
            e => string.Equals(e.Name, "Transfer", StringComparison.Ordinal));
        if (transferEvent is null)
            return Violated("NEP-17 manifest is missing Transfer event.", "NEP-17 ABI declares Transfer event");
        if (transferEvent.Parameters.Count != 3
            || !HasStandardParameter(transferEvent.Parameters, 0, "from", IsStrictHash160)
            || !HasStandardParameter(transferEvent.Parameters, 1, "to", IsStrictHash160)
            || !HasStandardParameter(transferEvent.Parameters, 2, "amount", type => IsType(type, "Integer")))
        {
            return Violated("NEP-17 Transfer event must declare exactly standard parameters (Hash160 from, Hash160 to, Integer amount).",
                "Transfer(Hash160 from, Hash160 to, Integer amount)");
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
            Reason: "NEP-17 manifest exposes the required methods, safe flags, return types, and Transfer event shape",
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

    private static VerificationPropertyResult BuildNep17SymbolValueResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options) =>
        BuildTokenSymbolValueResult(
            manifest,
            program,
            options,
            standardId: "nep17",
            standardName: "NEP-17");

    private static VerificationPropertyResult BuildNep17DecimalsValueResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options)
    {
        const string id = "security.nep17.decimals_value.decimals";
        const string methodName = "decimals";
        const string description = "NEP-17 decimals() must return one stable C# byte-compatible precision value.";
        const string failedCondition = "0 <= decimals() <= 255 and decimals() is a unique concrete value";

        if (FindAbiMethod(manifest, methodName, IsIntegerSafeNoParameterMethod) is not { } decimals)
        {
            return Incomplete(
                CheckedPaths: 0,
                IgnoredFaultedPaths: 0,
                StoppedPaths: 0,
                ObligationsChecked: 0,
                "NEP-17 manifest has no proof-grade decimals(): Integer safe=true method to prove a stable precision value",
                MethodOffset: null);
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
        var incompleteReasons = IncompleteReasons(execution)
            .Select(reason => "decimals(): " + reason)
            .ToList();
        int obligations = 0;
        var values = new HashSet<BigInteger>();
        foreach (var state in execution.Halted)
        {
            obligations++;
            if (state.EvaluationStack.Count == 0)
            {
                return Violated(
                    counts,
                    obligations,
                    "NEP-17 decimals() halts without returning an Integer value.",
                    BuildStateWitness(null, state),
                    decimals.Offset);
            }

            var returnValue = state.Peek().Expression;
            if (returnValue.Sort != Sort.Int)
            {
                return Violated(
                    counts,
                    obligations,
                    $"NEP-17 decimals() returns a {returnValue.Sort} StackItem instead of Integer.",
                    BuildStateWitness(null, state),
                    decimals.Offset);
            }

            if (Expr.ConcreteInt(returnValue) is not { } concrete)
            {
                incompleteReasons.Add("decimals() return value is symbolic; NEP-17 requires a unique concrete decimals() value");
                continue;
            }

            if (concrete < BigInteger.Zero)
            {
                return Violated(
                    counts,
                    obligations,
                    $"NEP-17 decimals() returns negative precision {concrete}.",
                    BuildStateWitness(null, state),
                    decimals.Offset);
            }

            if (concrete > byte.MaxValue)
            {
                return Violated(
                    counts,
                    obligations,
                    $"NEP-17 decimals() returns {concrete}, exceeding the C# byte-compatible maximum 255.",
                    BuildStateWitness(null, state),
                    decimals.Offset);
            }

            values.Add(concrete);
        }

        if (values.Count == 0)
            incompleteReasons.Add("decimals() produced no successful HALT path");
        if (values.Count > 1)
        {
            return Violated(
                counts,
                obligations,
                $"NEP-17 decimals() can return multiple concrete values ({string.Join(", ", values.OrderBy(value => value))}); NEP-17 requires one stable precision value.",
                null,
                decimals.Offset);
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
            $"NEP-17 decimals() returns stable precision {values.Single()} within 0..255 on every successful path",
            FailedCondition: null,
            Counterexample: null,
            MethodOffset: decimals.Offset);

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

    private static VerificationPropertyResult BuildNep17TransferSuccessFeasibilityResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.transfer_success_feasible.{method.Name}";
        string description = "NEP-17 transfer must have at least one feasible non-self true-return success path.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        if (fromIndex < 0 || toIndex < 0)
        {
            incompleteReasons.Add("NEP-17 transfer method has no recognizable from/to parameters");
        }
        string? fromSymbol = fromIndex >= 0
            ? SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex)
            : null;
        string? toSymbol = toIndex >= 0
            ? SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex)
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

            obligations++;
            if (fromSymbol is null || toSymbol is null)
                continue;

            if (PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
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
                    "at least one NEP-17 non-self transfer path can return true",
                    FailedCondition: null,
                    Counterexample: null);
            }

            if (!PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return NEP-17 transfer path does not prove whether from == to or from != to");
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
            VerificationStatus.Violated,
            counts.CheckedPaths,
            counts.IgnoredFaultedPaths,
            counts.StoppedPaths,
            obligations,
            "NEP-17 transfer has no feasible non-self true-return transfer path.",
            "transfer exposes at least one successful non-self true-return path",
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17SelfTransferSuccessResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.self_transfer_success.{method.Name}";
        string description = "NEP-17 transfer must accept self-transfers, return true, and emit Transfer.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0)
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
                "NEP-17 transfer method has no recognizable from/to/amount parameters",
                FailedCondition: null,
                Counterexample: null);
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        var selfTransfer = Expr.Eq(Expr.Sym(Sort.Bytes, fromSymbol), Expr.Sym(Sort.Bytes, toSymbol));
        var validSelfTransfer = Expr.BoolAnd(
            Expr.BoolAnd(
                selfTransfer,
                Expr.Ne(Hash160NumericExpression(fromSymbol), Expr.Int(0))),
            Expr.Ge(Expr.Sym(Sort.Int, amountSymbol), Expr.Int(0)));

        foreach (var state in execution.Faulted)
        {
            if (!PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol)
                || !PathConditionsExcludeHash160Zero(state.PathConditions, fromSymbol)
                || !PathConditionsProveAmountNonNegative(state.PathConditions, amountSymbol))
            {
                continue;
            }

            var query = BuildReachabilityQuery(ImmutableArray<Expression>.Empty, state.PathConditions, validSelfTransfer);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Unknown)
            {
                incompleteReasons.Add("solver returned unknown for NEP-17 self-transfer fault reachability");
                continue;
            }
            if (outcome == SmtOutcome.Unsat)
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
                $"valid self-transfer can fault instead of returning true: {state.TerminationReason ?? "VM fault"}.",
                "from == to transfer returns true and emits Transfer(from, to, amount)",
                BuildWitness(smtBackend, query));
        }

        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeFalse(method, state, smtBackend, out bool returnMayBeFalse, out _, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeFalse)
                continue;

            var query = BuildFalseReturnReachabilityQuery(method, state, validSelfTransfer);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Unknown)
            {
                incompleteReasons.Add("solver returned unknown for NEP-17 self-transfer false-return reachability");
                continue;
            }
            if (outcome == SmtOutcome.Unsat)
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
                "valid self-transfer can return false instead of true.",
                "from == to transfer returns true and emits Transfer(from, to, amount)",
                BuildWitness(smtBackend, query));
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

            var query = BuildTrueReturnReachabilityQuery(method, state, validSelfTransfer);
            var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
            if (outcome == SmtOutcome.Unknown)
            {
                incompleteReasons.Add("solver returned unknown for NEP-17 self-transfer true-return reachability");
                continue;
            }
            if (outcome == SmtOutcome.Unsat)
                continue;

            obligations++;
            var transferNotifications = CurrentTransferNotifications(state, currentScriptHash).ToList();
            if (transferNotifications.Any(n => TransferNotificationPayloadMatches(state, method, n, currentScriptHash)))
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
                    "every valid NEP-17 self-transfer path returns true and emits Transfer(from, to, amount)",
                    FailedCondition: null,
                    Counterexample: null);
            }

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
                    "self-transfer can return true while emitting Transfer with the wrong payload shape or argument binding.",
                    "from == to transfer returns true and emits Transfer(from, to, amount)",
                    BuildWitness(smtBackend, query));
            }

            if (state.Telemetry.Notifications.Any(n => n.ConcreteName is null))
            {
                incompleteReasons.Add("self-transfer path emits a notification with symbolic or unknown event name");
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
                "self-transfer can return true without emitting a Transfer notification.",
                "from == to transfer returns true and emits Transfer(from, to, amount)",
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
            "NEP-17 transfer has no feasible true-return self-transfer path.",
            "from == to transfer returns true and emits Transfer(from, to, amount)",
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17InsufficientBalanceFalseResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.insufficient_balance_false.{method.Name}";
        string description = "NEP-17 transfer must return false when from balance is below amount.";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0)
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
                "NEP-17 transfer method has no recognizable from/to/amount parameters",
                FailedCondition: null,
                Counterexample: null);
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);

        foreach (var state in execution.Faulted)
        {
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
                continue;
            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
                continue;

            var fromGet = FindStorageGetByAccountKey(state, fromSymbol);
            if (fromGet is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol))
                    incompleteReasons.Add("faulted transfer path uses balance storage keys the account-key proof cannot yet normalize");
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
                $"transfer faults instead of returning false when from balance is insufficient: {state.TerminationReason ?? "VM fault"}.",
                "non-self transfer with from balance < amount returns false",
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
                    incompleteReasons.Add("false-return transfer path does not prove whether from == to or from != to");
                }
                else if (!string.IsNullOrEmpty(selfReturnReason))
                {
                    incompleteReasons.Add(selfReturnReason);
                }
                continue;
            }

            var fromGet = FindStorageGetByAccountKey(state, fromSymbol);
            if (fromGet is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol))
                {
                    incompleteReasons.Add("transfer uses balance storage keys the account-key proof cannot yet normalize");
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
                        "transfer can return false without reading the from balance.",
                        "non-self transfer with from balance < amount returns false",
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
                    incompleteReasons.Add("false-return transfer path does not prove from balance < amount");
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
                    "non-self NEP-17 transfer can return true when from balance < amount.",
                    "non-self transfer with from balance < amount returns false",
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
                    "non-self NEP-17 transfer reaches a proven insufficient-balance path without returning false.",
                    "non-self transfer with from balance < amount returns false",
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
                    "non-self NEP-17 transfer can return false for insufficient balance after observable side effects.",
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
                "every proven non-self NEP-17 insufficient-balance transfer path returns false without side effects",
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
                "NEP-17 transfer has no feasible false-return path for insufficient from balance.",
                "non-self transfer with from balance < amount returns false",
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17SenderAuthorizationResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.sender_authorized.{method.Name}";
        string description = "NEP-17 transfer true-return paths must be authorized by the from account or caller contract.";
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
                "NEP-17 transfer method has no recognizable from Hash160 parameter",
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
                    "from argument authorized before true-return transfer",
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
                : "every true-return NEP-17 transfer path is authorized by Runtime.CallingScriptHash == from or enforced CheckWitness(from)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17TransferEventResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.transfer_event.{method.Name}";
        string description = "NEP-17 transfer success paths must emit a Transfer notification.";
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
            if (transferNotifications.Any(n => TransferNotificationPayloadMatches(state, method, n, currentScriptHash)))
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
                    "transfer can return true while emitting Transfer with the wrong payload shape or argument binding.",
                    "true-return transfer emits Transfer(from, to, amount)",
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
                "true-return transfer emits Transfer(from, to, amount)",
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
                : "every successful true-return NEP-17 transfer emits Transfer(from, to, amount)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17LifecycleEventResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep17MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep17.lifecycle_event.{method.Name}";
        string description = $"NEP-17 {lifecycle} paths that mutate totalSupply() must emit the standard Transfer lifecycle event.";
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
                "NEP-17 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
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
        if (accountIndex < 0 || amountIndex < 0)
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
                $"NEP-17 {lifecycle} method has no recognizable {(isMint ? "to" : "from")} Hash160 and amount Integer parameters",
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
                        incompleteReasons.Add($"successful {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
                    continue;
                }

                if (!supplyKeys.Any(supplyKey => StorageKeysEqual(supplyKey, mutationKey)))
                    continue;

                obligations++;
                var supplyRead = FindStorageGetByCanonicalKey(state, mutationKey, beforeOffset: mutation.Offset);
                if (supplyRead is null)
                {
                    incompleteReasons.Add($"successful {lifecycle} mutates totalSupply() storage without a preceding readable supply value");
                    continue;
                }

                if (mutation.Value is null
                    || !ValueMatchesBalanceDelta(
                        mutation.Value.Expression,
                        state,
                        supplyRead.Offset,
                        amountSymbol,
                        subtract: !isMint))
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
                        $"successful {lifecycle} mutates totalSupply() without updating it by {(isMint ? "+" : "-")}amount.",
                        isMint ? "mint updates totalSupply'=totalSupply+amount" : "burn updates totalSupply'=totalSupply-amount",
                        BuildStateWitness(smtBackend, state));
                }

                if (state.Telemetry.Notifications.Any(n => Nep17LifecycleTransferNotificationPayloadMatches(
                        state,
                        method,
                        n,
                        accountIndex,
                        amountIndex,
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
                        $"successful {lifecycle} mutates totalSupply() while emitting Transfer with the wrong lifecycle payload.",
                        isMint ? "mint emits Transfer(null,to,amount)" : "burn emits Transfer(from,null,amount)",
                        BuildStateWitness(smtBackend, state));
                }

                if (state.Telemetry.Notifications.Any(n => n.ConcreteName is null))
                {
                    incompleteReasons.Add($"successful {lifecycle} emits a notification with symbolic or unknown event name");
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
                    $"successful {lifecycle} mutates totalSupply() without emitting {(isMint ? "Transfer(null, to, amount)" : "Transfer(from, null, amount)")}.",
                    isMint ? "mint emits Transfer(null,to,amount)" : "burn emits Transfer(from,null,amount)",
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
                ? $"property holds vacuously: no successful {lifecycle} path mutates totalSupply() storage"
                : $"every successful {lifecycle} path that mutates totalSupply() emits the standard Transfer lifecycle event",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17LifecycleAmountNonNegativeResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep17MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep17.lifecycle_amount_non_negative.{method.Name}";
        string description = $"NEP-17 {lifecycle} paths that mutate totalSupply() must prove amount is non-negative.";
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
                "NEP-17 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
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
                $"NEP-17 {lifecycle} method has no recognizable amount Integer parameter",
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
                        incompleteReasons.Add($"successful {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
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
                    $"successful {lifecycle} can mutate totalSupply() with amount < 0.",
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
                $"solver could not prove amount is non-negative on a successful {lifecycle} path that mutates totalSupply()",
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
                ? $"property holds vacuously: no successful {lifecycle} path mutates totalSupply() storage"
                : $"every successful {lifecycle} path that mutates totalSupply() proves amount is non-negative",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17LifecycleBalanceResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep17MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string id = $"security.nep17.lifecycle_balance.{method.Name}";
        string description = $"NEP-17 {lifecycle} paths that mutate totalSupply() must maintain balanceOf(account) storage.";
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
                "NEP-17 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
                FailedCondition: null,
                Counterexample: null);
        }

        if (FindAbiMethod(manifest, "balanceOf", IsNep17BalanceOfMethod) is not { } balanceOf)
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
                "NEP-17 manifest has no balanceOf(account) method to infer account balance storage keys from",
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
                $"balanceOf(account) offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        int accountIndex = isMint ? FindToParameter(method) : FindFromParameter(method);
        int amountIndex = FindAmountParameter(method);
        if (accountIndex < 0 || amountIndex < 0)
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
                $"NEP-17 {lifecycle} method has no recognizable {(isMint ? "to" : "from")} Hash160 and amount Integer parameters",
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
            incompleteReasons.Add("balanceOf(account): " + reason);

        var balancePatterns = InferBalanceOfStorageKeyPatterns(balanceOf, balanceExecution, incompleteReasons);
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
                "balanceOf(account) did not expose a supported account balance storage key template",
                FailedCondition: null,
                Counterexample: null);
        }

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
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
                        incompleteReasons.Add($"successful {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
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
            var balanceGet = FindStorageGetByAccountKey(state, accountSymbol, balancePatterns);
            var balancePut = balanceGet is null
                ? null
                : FindStoragePutByAccountKey(state, accountSymbol, balanceGet.Pattern, balanceGet.Op.Offset);
            if (balanceGet is null)
            {
                if (StorageMentionsAccountSymbol(state, accountSymbol))
                {
                    incompleteReasons.Add($"successful {lifecycle} uses account balance storage keys the lifecycle balance proof cannot yet normalize");
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
                    $"successful {lifecycle} mutates totalSupply() without a direct {(isMint ? "recipient" : "sender")} balance read-write pair.",
                    isMint ? "mint credits recipient balance by amount" : "burn debits sender balance by amount",
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
                    $"successful {lifecycle} mutates totalSupply() after reading the {(isMint ? "recipient" : "sender")} balance without writing the updated balance.",
                    isMint ? "mint credits recipient balance by amount" : "burn debits sender balance by amount",
                    BuildStateWitness(smtBackend, state));
            }

            if (!isMint && !PathConditionsProveStorageReadOrMissingZeroAtLeastAmount(state.PathConditions, balanceGet.Op.Offset, amountSymbol))
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
                    "successful burn can return true without proving the sender balance is at least amount before debit.",
                    "sender balance is at least amount before burn debit",
                    BuildStateWitness(smtBackend, state));
            }

            if (!ValueMatchesBalanceDelta(
                    balancePut.Op.Value?.Expression,
                    state,
                    balanceGet.Op.Offset,
                    amountSymbol,
                    subtract: !isMint))
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
                    $"successful {lifecycle} writes the {(isMint ? "recipient" : "sender")} balance at 0x{balancePut.Op.Offset:X4} without {(isMint ? "adding" : "subtracting")} amount.",
                    isMint ? "mint credits recipient balance by amount" : "burn debits sender balance by amount",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageMutationByAccountKey(state, accountSymbol, balanceGet.Pattern, balancePut.Op.Offset) is { } later)
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
                    $"successful {lifecycle} mutates the {(isMint ? "recipient" : "sender")} balance again with {later.Kind} at 0x{later.Offset:X4} after the proved balance update.",
                    isMint ? "final recipient balance remains credited by amount" : "final sender balance remains debited by amount",
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
                ? $"property holds vacuously: no successful {lifecycle} path mutates totalSupply() storage"
                : $"every successful {lifecycle} path that mutates totalSupply() maintains balanceOf(account) storage",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17LifecycleZeroAddressResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        bool isMint = IsNep17MintMethod(manifest, method);
        string lifecycle = isMint ? "mint" : "burn";
        string label = isMint ? "to" : "from";
        string id = $"security.nep17.lifecycle_zero_address.{method.Name}";
        string description = $"NEP-17 {lifecycle} paths that mutate totalSupply() must reject UInt160.Zero {label} accounts.";
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
                "NEP-17 manifest has no totalSupply() method to infer lifecycle supply storage keys from",
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
                $"NEP-17 {lifecycle} method has no recognizable {label} Hash160 parameter",
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
                        incompleteReasons.Add($"successful {lifecycle} mutates a dynamic storage key that may alias totalSupply() storage");
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
                    $"{lifecycle} can mutate totalSupply() with {label} == UInt160.Zero.",
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
                $"solver could not prove {label} is non-zero on a successful {lifecycle} path that mutates totalSupply()",
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
                ? $"property holds vacuously: no successful {lifecycle} path mutates totalSupply() storage"
                : $"every successful {lifecycle} path that mutates totalSupply() proves {label} is not UInt160.Zero",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17CallbackOrderPayloadResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ImmutableArray<byte> currentScriptHash,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.callback_order_payload.{method.Name}";
        string description = "NEP-17 receiver callbacks must target `to`, follow Transfer, and pass (from, amount, data).";
        var counts = CountPaths(execution);
        int obligations = 0;
        int receiverAbsenceObligations = 0;
        var incompleteReasons = new List<string>();

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        int dataIndex = FindDataParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0 || dataIndex < 0)
        {
            incompleteReasons.Add("NEP-17 transfer method does not expose recognizable from/to/amount/data parameters");
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
                        $"true-return transfer path has a dynamic external call selector at 0x{call.Offset:X4} that may be onNEP17Payment");
                    continue;
                }

                if (!IsNep17PaymentCallback(call))
                    continue;

                sawPaymentCallback = true;
                obligations++;
                if (!Nep17CallbackTargetsRecipient(method, call))
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
                        $"onNEP17Payment call at 0x{call.Offset:X4} does not target the transfer `to` argument.",
                        "onNEP17Payment target is transfer.to",
                        BuildStateWitness(smtBackend, state));
                }

                if (!Nep17CallbackPayloadMatches(method, call))
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
                        $"onNEP17Payment call at 0x{call.Offset:X4} has wrong argument binding.",
                        "onNEP17Payment(from, amount, data)",
                        BuildStateWitness(smtBackend, state));
                }

                if (HasPriorMatchingTransferNotification(state, method, currentScriptHash, call.Offset))
                    continue;

                if (state.Telemetry.Notifications.Any(n => n.Offset < call.Offset && n.ConcreteName is null))
                {
                    incompleteReasons.Add(
                        $"onNEP17Payment call at 0x{call.Offset:X4} is preceded by a notification with symbolic or unknown event name");
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
                    $"onNEP17Payment call at 0x{call.Offset:X4} can occur before Transfer(from, to, amount).",
                    "onNEP17Payment occurs after Transfer(from, to, amount)",
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
                    "true-return transfer path does not call onNEP17Payment; verifier cannot prove the receiver is not a contract");
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
                ? "property holds vacuously: no true-return transfer path calls onNEP17Payment"
                : receiverAbsenceObligations > 0
                    ? "every true-return NEP-17 transfer path either proves the receiver is not a contract or calls onNEP17Payment after Transfer with (from, amount, data)"
                : "every observed true-return NEP-17 onNEP17Payment call targets to, follows Transfer, and passes (from, amount, data)",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17ZeroAddressResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.zero_address.{method.Name}";
        string description = "NEP-17 transfer success paths must reject UInt160.Zero from and to accounts.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        var incompleteReasons = new List<string>();
        var targets = ImmutableArray.CreateBuilder<(string Label, string SymbolName)>(2);

        if (fromIndex >= 0)
            targets.Add(("from", SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex)));
        else
            incompleteReasons.Add("NEP-17 transfer method has no recognizable from Hash160 parameter");

        if (toIndex >= 0)
            targets.Add(("to", SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex)));
        else
            incompleteReasons.Add("NEP-17 transfer method has no recognizable to Hash160 parameter");

        if (targets.Count == 0)
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

        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            foreach (var (label, symbolName) in targets)
            {
                obligations++;
                if (PathConditionsExcludeHash160Zero(state.PathConditions, symbolName))
                    continue;

                var query = BuildTrueReturnReachabilityQuery(
                    method,
                    state,
                    Expr.Eq(Hash160NumericExpression(symbolName), Expr.Int(0)));
                var outcome = smtBackend?.IsSatisfiable(query) ?? SmtOutcome.Unknown;
                if (outcome == SmtOutcome.Unsat)
                    continue;

                string zeroCondition = $"{label} != UInt160.Zero before true-return transfer";
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
                        $"transfer can return true with {label} == UInt160.Zero.",
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
                    $"solver could not prove {label} is non-zero on a true-return transfer path",
                    zeroCondition,
                    BuildWitness(smtBackend, query));
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
                : "every successful true-return NEP-17 transfer proves from and to are not UInt160.Zero",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17FailureNoStateChangeResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.failure_no_state_change.{method.Name}";
        string description = "NEP-17 transfer false-return paths must not perform observable side effects.";
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
                : "every false-return NEP-17 transfer path avoids Storage.Put, Storage.Delete, Runtime.Notify, and external side-effect calls",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17BalanceDeltaResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        string id = $"security.nep17.balance_delta.{method.Name}";
        string description = "NEP-17 transfer true-return paths must debit from and credit to balances by amount.";
        var counts = CountPaths(execution);
        int obligations = 0;
        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        var incompleteReasons = new List<string>();

        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0)
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
                "NEP-17 transfer method has no recognizable from/to/amount parameters",
                FailedCondition: null,
                Counterexample: null);
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
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

            obligations++;
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                if (SelfTransferBalanceMutation(state, fromSymbol, toSymbol, out var mutation, out var mutationReason))
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
                        $"self-transfer can return true after {mutation!.Kind} mutates an account balance key at 0x{mutation.Offset:X4}.",
                        "self-transfer leaves account balance storage unchanged",
                        BuildStateWitness(smtBackend, state));
                }

                if (!string.IsNullOrWhiteSpace(mutationReason))
                    incompleteReasons.Add(mutationReason);
                continue;
            }

            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return transfer path does not prove whether from == to or from != to");
                continue;
            }

            var fromGet = FindStorageGetByAccountKey(state, fromSymbol);
            var toGet = FindStorageGetByAccountKey(state, toSymbol);
            var fromPut = fromGet is null ? null : FindStoragePutByAccountKey(state, fromSymbol, fromGet.Pattern, fromGet.Op.Offset);
            var toPut = toGet is null ? null : FindStoragePutByAccountKey(state, toSymbol, toGet.Pattern, toGet.Op.Offset);

            if (fromGet is null || toGet is null || fromPut is null || toPut is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol))
                {
                    incompleteReasons.Add("true-return transfer uses balance storage keys the account-key proof cannot yet normalize");
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
                    "transfer can return true without direct from/to balance read-write pairs.",
                    "true-return transfer writes from'=from-amount and to'=to+amount",
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
                    "transfer reads from/to balances through different storage key templates.",
                    "from and to balances use the same account-key template",
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
                    "transfer can return true without proving the from balance is at least amount before debit.",
                    "from balance is at least amount before debit",
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
                    $"transfer writes the from balance at 0x{fromPut.Op.Offset:X4} without subtracting amount from its prior value.",
                    "from balance write equals previous from balance minus amount",
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
                    $"transfer writes the to balance at 0x{toPut.Op.Offset:X4} without adding amount to its prior value.",
                    "to balance write equals previous to balance plus amount",
                    BuildStateWitness(smtBackend, state));
            }

            if (FindLaterStorageMutationByAccountKey(state, fromSymbol, fromGet.Pattern, fromPut.Op.Offset) is { } laterFrom)
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
                    $"transfer mutates the from balance again with {laterFrom.Kind} at 0x{laterFrom.Offset:X4} after the proved debit.",
                    "final from balance remains previous from balance minus amount",
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
                    $"transfer mutates the to balance again with {laterTo.Kind} at 0x{laterTo.Offset:X4} after the proved credit.",
                    "final to balance remains previous to balance plus amount",
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
                : "every true-return NEP-17 transfer path either leaves self-transfer balance unchanged or debits from and credits to by amount",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17BalanceOfStorageConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep17.balanceof_storage_consistency.balanceOf";
        const string methodName = "balanceOf";
        const string description = "NEP-17 balanceOf(account) must read the account balance storage updated by transfer.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep17BalanceOfMethod) is not { } balanceOf)
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
                "NEP-17 manifest has no balanceOf(account) method to compare against transfer balance storage",
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
                $"balanceOf(account) offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep17TransferBalanceKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
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
                "property holds vacuously: no non-self true-return transfer balance storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var balanceExecution = RunMethodEntry(program, options, balanceOf);
        foreach (var reason in IncompleteReasons(balanceExecution))
            incompleteReasons.Add("balanceOf(account): " + reason);

        var balancePatterns = InferBalanceOfStorageKeyPatterns(balanceOf, balanceExecution, incompleteReasons);
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

        if (balancePatterns.IsDefaultOrEmpty)
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
                "balanceOf(account) does not read transfer balance storage.",
                "balanceOf reads the same account balance key template as transfer",
                Counterexample: null);
        }

        bool allTransferPatternsCovered = transferPatterns.All(transferPattern =>
            balancePatterns.Any(balancePattern => StorageKeysEqual(balancePattern, transferPattern)));
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
                "balanceOf(account) reads a different balance key template than transfer updates.",
                "balanceOf reads the same account balance key template as transfer",
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
            "balanceOf(account) reads the same account balance storage template updated by transfer",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17BalanceOfReturnConsistencyResult(
        ContractManifest manifest,
        ContractMethodDescriptor transfer,
        ExecutionResult transferExecution,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep17.balanceof_return_consistency.balanceOf";
        const string methodName = "balanceOf";
        const string description = "NEP-17 balanceOf(account) must return the account balance storage value it reads.";
        var counts = CountPaths(transferExecution);
        int obligations = 0;
        var incompleteReasons = new List<string>();

        if (FindAbiMethod(manifest, methodName, IsNep17BalanceOfMethod) is not { } balanceOf)
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
                "NEP-17 manifest has no balanceOf(account) method to compare against transfer balance storage",
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
                $"balanceOf(account) offset {balanceOf.Offset} is outside script bytes",
                FailedCondition: null,
                Counterexample: null);
        }

        var transferPatterns = InferNep17TransferBalanceKeyPatterns(transfer, transferExecution, smtBackend, incompleteReasons);
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
                "property holds vacuously: no non-self true-return transfer balance storage template was inferred",
                FailedCondition: null,
                Counterexample: null);
        }

        obligations = transferPatterns.Length;
        var balanceExecution = RunMethodEntry(program, options, balanceOf);
        foreach (var reason in IncompleteReasons(balanceExecution))
            incompleteReasons.Add("balanceOf(account): " + reason);

        var halted = balanceExecution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("balanceOf(account) produced no successful HALT path");
        if (balanceOf.Parameters.Count == 0)
            incompleteReasons.Add("balanceOf(account) has no account parameter");

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

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(balanceOf.Parameters[0].Name, 0);
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
                    "balanceOf(account) halts without returning the account balance.",
                    "balanceOf returns the account balance storage value",
                    BuildStateWitness(smtBackend, state));
            }

            var returnValue = state.Peek().Expression;
            foreach (var transferPattern in transferPatterns)
            {
                var matchingReads = state.Telemetry.StorageOps
                    .Where(op => op.Kind == StorageOpKind.Get)
                    .Where(op => TryAccountStorageKeyPattern(state, op.Key, accountSymbol, out var pattern)
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
                        "balanceOf(account) does not read transfer balance storage before returning.",
                        "balanceOf returns the account balance storage value",
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
                    "balanceOf(account) does not return the storage value it reads.",
                    "balanceOf returns the account balance storage value",
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
            "balanceOf(account) returns the same account balance storage value it reads",
            FailedCondition: null,
            Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep17TotalSupplyConservationResult(
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
            standardId: "nep17",
            standardName: "NEP-17");

    private static VerificationPropertyResult BuildNep17TotalSupplyReturnConsistencyResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options) =>
        BuildTokenTotalSupplyReturnConsistencyResult(
            manifest,
            program,
            options,
            standardId: "nep17",
            standardName: "NEP-17");

    private static VerificationPropertyResult BuildNep17TotalSupplyNonNegativeResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend) =>
        BuildTokenTotalSupplyNonNegativeResult(
            manifest,
            program,
            options,
            smtBackend,
            standardId: "nep17",
            standardName: "NEP-17");

    private static VerificationPropertyResult BuildNep17BalanceOfNonNegativeResult(
        ContractManifest manifest,
        NeoProgram program,
        ExecutionOptions options,
        ISmtBackend? smtBackend) =>
        FindAbiMethod(manifest, "balanceOf", IsNep17BalanceOfMethod) is { } balanceOf
            ? BuildTokenBalanceOfNonNegativeResult(
                balanceOf,
                program,
                options,
                smtBackend,
                standardId: "nep17",
                standardName: "NEP-17",
                methodSignature: "balanceOf(account)")
            : BuildMissingBalanceOfNonNegativeResult(
                standardId: "nep17",
                standardName: "NEP-17",
                methodSignature: "balanceOf(account)");
}
