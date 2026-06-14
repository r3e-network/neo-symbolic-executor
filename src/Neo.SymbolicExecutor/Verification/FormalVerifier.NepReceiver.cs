using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    private static VerificationPropertyResult BuildNep24AbiResult(ContractManifest manifest)
    {
        const string id = "security.nep24.abi.*";
        const string method = "*";
        const string description = "Contracts declaring NEP-24 must expose the standard NFT royalty ABI method and event shape on top of a complete NEP-11 base NFT ABI.";
        const int obligations = 3;

        if (FindAbiMethod(manifest, "royaltyInfo", IsNep24RoyaltyInfoMethod) is null)
        {
            if (FindAbiMethod(manifest, "royaltyInfo") is null)
                return Violated("NEP-24 manifest is missing method royaltyInfo.", "NEP-24 ABI declares royaltyInfo(tokenId,royaltyToken,salePrice)");
            return Violated("NEP-24 method royaltyInfo must be safe=true with standard parameters (ByteString-compatible tokenId, Hash160 royaltyToken, Integer salePrice) and Array return type.",
                "royaltyInfo(ByteString source tokenId / ByteArray manifest tokenId, Hash160 royaltyToken, Integer salePrice): Array safe=true");
        }

        var royaltiesTransferred = manifest.Abi.Events.FirstOrDefault(
            e => string.Equals(e.Name, "RoyaltiesTransferred", StringComparison.Ordinal));
        if (royaltiesTransferred is null)
            return Violated("NEP-24 manifest is missing RoyaltiesTransferred event.", "NEP-24 ABI declares RoyaltiesTransferred event");
        if (royaltiesTransferred.Parameters.Count != 5
            || !HasStandardParameter(royaltiesTransferred.Parameters, 0, "royaltyToken", IsStrictHash160)
            || !HasStandardParameter(royaltiesTransferred.Parameters, 1, "royaltyRecipient", IsStrictHash160)
            || !HasStandardParameter(royaltiesTransferred.Parameters, 2, "buyer", IsStrictHash160)
            || !HasStandardParameter(royaltiesTransferred.Parameters, 3, "tokenId", IsByteStringLike)
            || !HasStandardParameter(royaltiesTransferred.Parameters, 4, "amount", type => IsType(type, "Integer")))
        {
            return Violated("NEP-24 RoyaltiesTransferred event must declare exactly standard parameters (Hash160 royaltyToken, Hash160 royaltyRecipient, Hash160 buyer, ByteString-compatible tokenId, Integer amount).",
                "RoyaltiesTransferred(Hash160 royaltyToken, Hash160 royaltyRecipient, Hash160 buyer, ByteString source tokenId / ByteArray manifest tokenId, Integer amount)");
        }

        if (!manifest.DeclaresStandard("NEP-11") || !HasCompleteNep11AbiShape(manifest))
        {
            return Violated(
                "NEP-24 royalty manifests must also declare NEP-11 and expose a complete NEP-11 base NFT ABI.",
                "NEP-24 manifest declares NEP-11 and complete NEP-11 base NFT ABI");
        }

        string csharpByteArrayNote = UsesManifestByteArrayTokenIdAbi(manifest)
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
            Reason: "NEP-24 manifest declares NEP-11 and exposes the required base NFT ABI, royaltyInfo method, safe flag, return type, and RoyaltiesTransferred event shape" + csharpByteArrayNote,
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

    private static VerificationPropertyResult BuildNep24RoyaltyInfoBehaviorResult(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend)
    {
        const string id = "security.nep24.behavior.royaltyInfo";
        const string description = "NEP-24 royaltyInfo must return a proof-grade royalty entry array.";
        const string failedCondition = "royaltyInfo returns a closed Array of [Hash160 recipient, non-negative Integer amount] royalty entries";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = IncompleteReasons(execution)
            .Select(reason => "royaltyInfo(): " + reason)
            .ToList();
        var unknownReasons = new List<string>();

        foreach (var state in execution.Halted)
        {
            obligations++;
            if (state.EvaluationStack.Count == 0)
            {
                return Violated(
                    counts,
                    obligations,
                    "NEP-24 royaltyInfo halts without returning a royalty entry Array.",
                    BuildStateWitness(smtBackend, state));
            }
            if (state.EvaluationStack.Count != 1)
            {
                return Violated(
                    counts,
                    obligations,
                    $"NEP-24 royaltyInfo leaves {state.EvaluationStack.Count} StackItems on the result stack; expected exactly one royalty entry Array.",
                    BuildStateWitness(smtBackend, state));
            }

            var returned = state.Peek();
            var topLevel = TryGetClosedSequenceItems(state, returned, "royaltyInfo return value");
            if (topLevel.Status == RoyaltySequenceStatus.Mismatch)
            {
                return Violated(
                    counts,
                    obligations,
                    topLevel.Reason,
                    BuildStateWitness(smtBackend, state));
            }
            if (topLevel.Status == RoyaltySequenceStatus.Incomplete)
            {
                incompleteReasons.Add(topLevel.Reason);
                continue;
            }

            foreach (var entry in topLevel.Items)
            {
                obligations++;
                var entryItems = TryGetClosedSequenceItems(state, entry, "royalty entry");
                if (entryItems.Status == RoyaltySequenceStatus.Mismatch)
                {
                    return Violated(
                        counts,
                        obligations,
                        entryItems.Reason,
                        BuildStateWitness(smtBackend, state));
                }
                if (entryItems.Status == RoyaltySequenceStatus.Incomplete)
                {
                    incompleteReasons.Add(entryItems.Reason);
                    continue;
                }
                if (entryItems.Items.Count != 2)
                {
                    return Violated(
                        counts,
                        obligations,
                        $"NEP-24 royalty entry contains {entryItems.Items.Count} item(s); expected [recipient, amount].",
                        BuildStateWitness(smtBackend, state));
                }

                var recipient = entryItems.Items[0];
                if (!IsRuntimeByteStringLike(recipient))
                {
                    return Violated(
                        counts,
                        obligations,
                        $"NEP-24 royalty entry recipient is runtime {DescribeRuntimeArgumentType(state, recipient)}; expected Hash160-compatible ByteString.",
                        BuildStateWitness(smtBackend, state));
                }
                if (!TryGetKnownByteLength(state, recipient, out int recipientLength))
                {
                    incompleteReasons.Add("NEP-24 royalty entry recipient ByteString length cannot be proven");
                    continue;
                }
                if (recipientLength != Hash160ByteLength)
                {
                    return Violated(
                        counts,
                        obligations,
                        $"NEP-24 royalty entry recipient length is {recipientLength} byte(s); expected Hash160 length {Hash160ByteLength}.",
                        BuildStateWitness(smtBackend, state));
                }

                var amount = entryItems.Items[1];
                if (amount.Sort != Sort.Int)
                {
                    return Violated(
                        counts,
                        obligations,
                        $"NEP-24 royalty entry amount is runtime {DescribeRuntimeArgumentType(state, amount)}; expected Integer.",
                        BuildStateWitness(smtBackend, state));
                }
                if (!TryProveNonNegativeRoyaltyAmount(state, amount.Expression, smtBackend, out var amountOutcome))
                {
                    if (amountOutcome == SmtOutcome.Sat)
                    {
                        return Violated(
                            counts,
                            obligations,
                            "NEP-24 royalty entry amount can be negative.",
                            BuildWitness(smtBackend, BuildReachabilityQuery(
                                ImmutableArray<Expression>.Empty,
                                SuccessfulHaltPathConditions(state),
                                Expr.Lt(amount.Expression, Expr.Int(0)))));
                    }

                    unknownReasons.Add("solver returned unknown while proving NEP-24 royalty entry amount is non-negative");
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
        if (unknownReasons.Count > 0)
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
                string.Join("; ", unknownReasons.Distinct(StringComparer.Ordinal)),
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
            "royaltyInfo returns a closed royalty entry array; every royalty entry has a Hash160 recipient and non-negative Integer amount on every successful path",
            FailedCondition: null,
            Counterexample: null);

        VerificationPropertyResult Violated(
            (int CheckedPaths, int IgnoredFaultedPaths, int StoppedPaths) Counts,
            int ObligationsChecked,
            string Reason,
            ImmutableDictionary<string, object>? Counterexample) =>
            new(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                Counts.CheckedPaths,
                Counts.IgnoredFaultedPaths,
                Counts.StoppedPaths,
                ObligationsChecked,
                Reason,
                failedCondition,
        Counterexample);
    }

    private static VerificationPropertyResult BuildNep24SalePriceDependenceResult(
        ContractMethodDescriptor method,
        ExecutionResult execution)
    {
        const string id = "security.nep24.behavior.sale_price.royaltyInfo";
        const string description = "NEP-24 royaltyInfo returned royalty amounts must bind to salePrice.";
        const string failedCondition = "royaltyInfo returned royalty amounts MUST NOT ignore salePrice";
        var counts = CountPaths(execution);
        int obligations = 0;
        int checkedAmounts = 0;
        var incompleteReasons = IncompleteReasons(execution)
            .Select(reason => "royaltyInfo salePrice dependence: " + reason)
            .ToList();

        const int salePriceIndex = 2;
        string salePriceSymbol = SymbolicEngine.MethodEntryArgSymbolName(
            method.Parameters[salePriceIndex].Name,
            salePriceIndex);

        foreach (var state in execution.Halted)
        {
            if (state.EvaluationStack.Count != 1)
            {
                incompleteReasons.Add("royaltyInfo return structure must be proven before salePrice dependence can be evaluated");
                continue;
            }

            var topLevel = TryGetClosedSequenceItems(state, state.Peek(), "royaltyInfo return value");
            if (topLevel.Status != RoyaltySequenceStatus.Match)
            {
                incompleteReasons.Add(topLevel.Reason);
                continue;
            }

            foreach (var entry in topLevel.Items)
            {
                var entryItems = TryGetClosedSequenceItems(state, entry, "royalty entry");
                if (entryItems.Status != RoyaltySequenceStatus.Match || entryItems.Items.Count != 2)
                {
                    incompleteReasons.Add("royalty entry structure must be proven before salePrice dependence can be evaluated");
                    continue;
                }

                var amount = entryItems.Items[1];
                if (amount.Sort != Sort.Int)
                {
                    incompleteReasons.Add("royalty entry amount must be an Integer before salePrice dependence can be evaluated");
                    continue;
                }

                obligations++;
                checkedAmounts++;
                if (!ExpressionOrTaintDependsOn(amount, salePriceSymbol))
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
                        "NEP-24 royaltyInfo returned a royalty amount that ignores salePrice.",
                        failedCondition,
                        Counterexample: null);
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
            checkedAmounts == 0
                ? "royaltyInfo returned no royalty amounts on successful paths; salePrice dependence obligation is vacuously discharged"
                : "every returned NEP-24 royalty amount depends on salePrice",
            FailedCondition: null,
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep24RoyaltiesTransferredConsistencyResult(
        ContractMethodDescriptor method,
        ExecutionResult execution)
    {
        string id = $"security.nep24.behavior.royalties_transferred.{method.Name}";
        const string description = "NEP-24 RoyaltiesTransferred notifications must report the royalty transfer payload bound to method inputs.";
        const string failedCondition = "RoyaltiesTransferred(royaltyToken, royaltyRecipient, buyer, tokenId, amount) matches method inputs";
        var counts = CountPaths(execution);
        int obligations = 0;
        var incompleteReasons = IncompleteReasons(execution)
            .Select(reason => "RoyaltiesTransferred payload consistency: " + reason)
            .ToList();

        if (!TryResolveNep24RoyaltyEventParameterSymbols(method, incompleteReasons, out var symbols))
        {
            return Incomplete(obligations);
        }

        foreach (var state in execution.Halted)
        {
            foreach (var notification in state.Telemetry.Notifications
                         .Where(n => string.Equals(n.ConcreteName, "RoyaltiesTransferred", StringComparison.Ordinal)))
            {
                obligations++;
                if (!TryNotificationArrayArguments(state, notification, out var args))
                {
                    incompleteReasons.Add(
                        $"RoyaltiesTransferred at 0x{notification.Offset:X4} has symbolic state; payload binding cannot be proven");
                    continue;
                }
                if (args.Count != 5)
                {
                    return Violated(
                        obligations,
                        $"RoyaltiesTransferred at 0x{notification.Offset:X4} emits {args.Count} argument(s); expected 5.",
                        Counterexample: null);
                }

                if (!IsMethodArgumentValue(args[0], symbols.RoyaltyToken))
                {
                    return Violated(
                        obligations,
                        $"RoyaltiesTransferred at 0x{notification.Offset:X4} royaltyToken does not match the method royaltyToken input.",
                        Counterexample: null);
                }
                if (!IsMethodArgumentValue(args[1], symbols.RoyaltyRecipient))
                {
                    return Violated(
                        obligations,
                        $"RoyaltiesTransferred at 0x{notification.Offset:X4} royaltyRecipient does not match the method royaltyRecipient input.",
                        Counterexample: null);
                }
                if (!IsMethodArgumentValue(args[2], symbols.Buyer))
                {
                    return Violated(
                        obligations,
                        $"RoyaltiesTransferred at 0x{notification.Offset:X4} buyer does not match the method buyer input.",
                        Counterexample: null);
                }
                if (!IsMethodArgumentValue(args[3], symbols.TokenId))
                {
                    return Violated(
                        obligations,
                        $"RoyaltiesTransferred at 0x{notification.Offset:X4} tokenId does not match the method tokenId input.",
                        Counterexample: null);
                }
                if (!IsMethodArgumentValue(args[4], symbols.Amount))
                {
                    return Violated(
                        obligations,
                        $"RoyaltiesTransferred at 0x{notification.Offset:X4} amount does not match the method amount input.",
                        Counterexample: null);
                }
            }
        }

        if (incompleteReasons.Count > 0)
            return Incomplete(obligations);
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
            "every emitted NEP-24 RoyaltiesTransferred payload reports royaltyToken, royaltyRecipient, buyer, tokenId, and amount from the corresponding method inputs",
            FailedCondition: null,
            Counterexample: null);

        VerificationPropertyResult Violated(
            int ObligationsChecked,
            string Reason,
            ImmutableDictionary<string, object>? Counterexample) =>
            new(
                id,
                method.Name,
                description,
                VerificationStatus.Violated,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                ObligationsChecked,
                Reason,
                failedCondition,
                Counterexample);

        VerificationPropertyResult Incomplete(int ObligationsChecked) =>
            new(
                id,
                method.Name,
                description,
                VerificationStatus.Incomplete,
                counts.CheckedPaths,
                counts.IgnoredFaultedPaths,
                counts.StoppedPaths,
                ObligationsChecked,
                string.Join("; ", incompleteReasons.Distinct(StringComparer.Ordinal)),
                FailedCondition: null,
                Counterexample: null);
    }

    private static VerificationPropertyResult BuildNep27AbiResult(ContractManifest manifest)
    {
        const string id = "security.nep27.abi.*";
        const string method = "*";
        const string description = "Contracts declaring NEP-27 must expose the standard NEP-17 receiver callback ABI.";
        const int obligations = 1;

        if (FindAbiMethod(manifest, "onNEP17Payment", IsNep27PaymentCallbackMethod) is null)
        {
            if (FindAbiMethod(manifest, "onNEP17Payment") is null)
                return Violated("NEP-27 manifest is missing method onNEP17Payment.", "NEP-27 ABI declares onNEP17Payment(from,amount,data)");
            return Violated("NEP-27 method onNEP17Payment must use standard parameters (Hash160 from, Integer amount, Any data) and Void return type.",
                "onNEP17Payment(Hash160 from, Integer amount, Any data): Void");
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
            Reason: "NEP-27 manifest exposes the required onNEP17Payment receiver callback shape",
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

    private static VerificationPropertyResult BuildNep27ReceiverBehaviorResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs) =>
        BuildPassiveReceiverBehaviorResult(
            manifest,
            method,
            execution,
            smtBackend,
            dependencyProofs,
            requireExternalSmtDependencyProofs,
            id: "security.nep27.behavior.onNEP17Payment",
            description: "NEP-27 receiver callback behavior must be passive unless a stronger receiver policy is supplied by custom specs.",
            provedReason: "passive NEP-27 receiver behavior proved: onNEP17Payment is fault-free and has no storage mutation, Runtime.Notify, or external calls on feasible successful paths");

    private static VerificationPropertyResult BuildNep26AbiResult(ContractManifest manifest)
    {
        const string id = "security.nep26.abi.*";
        const string method = "*";
        const string description = "Contracts declaring NEP-26 must expose the standard NEP-11 receiver callback ABI.";
        const int obligations = 1;

        if (FindAbiMethod(manifest, "onNEP11Payment", IsNep26PaymentCallbackMethod) is null)
        {
            if (FindAbiMethod(manifest, "onNEP11Payment") is null)
                return Violated("NEP-26 manifest is missing method onNEP11Payment.", "NEP-26 ABI declares onNEP11Payment(from,amount,tokenId,data)");
            return Violated("NEP-26 method onNEP11Payment must use standard parameters (Hash160 from, Integer amount, ByteString-compatible tokenId, Any data) and Void return type.",
                "onNEP11Payment(Hash160 from, Integer amount, ByteString source tokenId / ByteArray or String manifest tokenId, Any data): Void");
        }

        string csharpTokenIdNote = Nep26TokenIdCompatibilityNote(manifest) ?? "";

        return new VerificationPropertyResult(
            id,
            method,
            description,
            VerificationStatus.Proved,
            CheckedPaths: 0,
            IgnoredFaultedPaths: 0,
            StoppedPaths: 0,
            ObligationsChecked: obligations,
            Reason: "NEP-26 manifest exposes the required onNEP11Payment receiver callback shape" + csharpTokenIdNote,
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

    private static VerificationPropertyResult BuildNep26ReceiverBehaviorResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs) =>
        BuildPassiveReceiverBehaviorResult(
            manifest,
            method,
            execution,
            smtBackend,
            dependencyProofs,
            requireExternalSmtDependencyProofs,
            id: "security.nep26.behavior.onNEP11Payment",
            description: "NEP-26 receiver callback behavior must be passive unless a stronger receiver policy is supplied by custom specs.",
            provedReason: "passive NEP-26 receiver behavior proved: onNEP11Payment is fault-free and has no storage mutation, Runtime.Notify, or external calls on feasible successful paths");

    private static VerificationPropertyResult BuildPassiveReceiverBehaviorResult(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        DependencyProofSummarySet dependencyProofs,
        bool requireExternalSmtDependencyProofs,
        string id,
        string description,
        string provedReason)
    {
        var property = new VerificationProperty(
            Id: id,
            Method: method.Name,
            Description: description,
            ForbidFaults: true,
            Requires: ImmutableArray<VerificationCondition>.Empty,
            Ensures: ImmutableArray<VerificationCondition>.Empty,
            RequireExternalCallCompleteness: false,
            ForbidStorageMutation: true,
            ForbidExternalCalls: true,
            ForbidNotifications: true);

        var result = VerifyPropertyOnExecution(
            manifest,
            method,
            property,
            execution,
            ImmutableArray<byte>.Empty,
            smtBackend,
            dependencyProofs,
            requireExternalSmtDependencyProofs);

        return result.Status == VerificationStatus.Proved
            ? result with { Reason = provedReason }
            : result;
    }

    private static string? Nep26TokenIdCompatibilityNote(ContractManifest manifest)
    {
        var callback = FindAbiMethod(manifest, "onNEP11Payment", IsNep26PaymentCallbackMethod);
        if (callback is null || callback.Parameters.Count < 3)
            return null;

        string type = callback.Parameters[2].Type;
        if (IsType(type, "ByteArray"))
        {
            return "; tokenId ABI field uses ByteArray, accepted for Neo N3 C# manifest compatibility with source-level ByteString token IDs";
        }
        if (IsType(type, "String"))
        {
            return "; tokenId ABI field uses String, accepted for released Neo N3 C# INEP26 interface compatibility";
        }

        return null;
    }

    private static RoyaltySequenceCheck TryGetClosedSequenceItems(
        ExecutionState state,
        SymbolicValue value,
        string display)
    {
        if (value.Expression is not HeapRef { RefSort: Sort.Array or Sort.Struct } href)
        {
            return value.Sort == Sort.Unknown
                ? RoyaltySequenceCheck.Incomplete($"NEP-24 {display} has unknown runtime type")
                : RoyaltySequenceCheck.Mismatch($"NEP-24 {display} is runtime {DescribeRuntimeArgumentType(state, value)}; expected closed Array or Struct");
        }

        if (href.RefSort == Sort.Array)
        {
            var array = state.Heap.Get<ArrayObject>(href.ObjectId);
            if (array.IsSymbolicOpen)
                return RoyaltySequenceCheck.Incomplete($"NEP-24 {display} is an open symbolic Array; royalty entry coverage is not exhaustive");

            return RoyaltySequenceCheck.Match(array.Items);
        }

        var @struct = state.Heap.Get<StructObject>(href.ObjectId);
        if (@struct.IsSymbolicOpen)
            return RoyaltySequenceCheck.Incomplete($"NEP-24 {display} is an open symbolic Struct; royalty entry coverage is not exhaustive");

        return RoyaltySequenceCheck.Match(@struct.Fields);
    }

    private static bool TryProveNonNegativeRoyaltyAmount(
        ExecutionState state,
        Expression amount,
        ISmtBackend? smtBackend,
        out SmtOutcome outcome)
    {
        if (IsObviouslyNonNegativeIntegerExpression(amount))
        {
            outcome = SmtOutcome.Unsat;
            return true;
        }

        if (Expr.ConcreteInt(amount) is { } concrete)
        {
            outcome = concrete < BigInteger.Zero ? SmtOutcome.Sat : SmtOutcome.Unsat;
            return concrete >= BigInteger.Zero;
        }

        outcome = smtBackend?.IsSatisfiable(
            SuccessfulHaltPathConditions(state),
            Expr.Lt(amount, Expr.Int(0))) ?? SmtOutcome.Unknown;
        return outcome == SmtOutcome.Unsat;
    }

    private static bool IsObviouslyNonNegativeIntegerExpression(Expression expression)
    {
        if (Expr.ConcreteInt(expression) is { } concrete)
            return concrete >= BigInteger.Zero;

        if (expression is UnaryExpr { Sort: Sort.Int, Op: "abs" })
            return true;

        if (expression is BinaryExpr { Sort: Sort.Int, Op: "max", Left: var left, Right: var right })
            return Expr.ConcreteInt(left) is { } leftConcrete && leftConcrete >= BigInteger.Zero
                || Expr.ConcreteInt(right) is { } rightConcrete && rightConcrete >= BigInteger.Zero;

        return false;
    }

    private static bool TryResolveNep24RoyaltyEventParameterSymbols(
        ContractMethodDescriptor method,
        List<string> incompleteReasons,
        out Nep24RoyaltyEventParameterSymbols symbols)
    {
        symbols = new Nep24RoyaltyEventParameterSymbols("", "", "", "", "");
        bool hasTokenId = TryFindNamedParameterSymbol(method, "tokenId", IsByteStringLike, out var tokenId);
        bool hasRoyaltyToken = TryFindNamedParameterSymbol(method, "royaltyToken", IsStrictHash160, out var royaltyToken);
        bool hasRoyaltyRecipient = TryFindNamedParameterSymbol(method, "royaltyRecipient", IsStrictHash160, out var royaltyRecipient);
        bool hasBuyer = TryFindNamedParameterSymbol(method, "buyer", IsStrictHash160, out var buyer);
        bool hasAmount = TryFindNamedParameterSymbol(method, "amount", type => IsType(type, "Integer"), out var amount);

        if (!hasTokenId)
            incompleteReasons.Add("method emits RoyaltiesTransferred but has no bindable ByteString tokenId parameter");
        if (!hasRoyaltyToken)
            incompleteReasons.Add("method emits RoyaltiesTransferred but has no bindable Hash160 royaltyToken parameter");
        if (!hasRoyaltyRecipient)
            incompleteReasons.Add("method emits RoyaltiesTransferred but has no bindable Hash160 royaltyRecipient parameter");
        if (!hasBuyer)
            incompleteReasons.Add("method emits RoyaltiesTransferred but has no bindable Hash160 buyer parameter");
        if (!hasAmount)
            incompleteReasons.Add("method emits RoyaltiesTransferred but has no bindable Integer amount parameter");

        if (!hasTokenId || !hasRoyaltyToken || !hasRoyaltyRecipient || !hasBuyer || !hasAmount)
            return false;

        symbols = new Nep24RoyaltyEventParameterSymbols(tokenId, royaltyToken, royaltyRecipient, buyer, amount);
        return true;
    }
}
