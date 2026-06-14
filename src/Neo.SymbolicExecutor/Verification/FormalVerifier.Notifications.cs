using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    private static VerificationPropertyResult? CheckRuntimeNotificationManifest(
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
        var notifications = state.Telemetry.Notifications
            .Where(notification => ShouldCheckNotificationAgainstManifest(notification, currentScriptHash))
            .ToArray();
        if (notifications.Length == 0)
            return null;
        if (!ShouldCheckHaltedPathUnderRequires(
                "Runtime.Notify manifest checks",
                state,
                requires,
                smtBackend,
                ref obligations,
                unknownReasons))
        {
            return null;
        }

        foreach (var notification in notifications)
        {
            obligations++;
            if (notification.ConcreteName is not { } name)
            {
                incompleteReasons.Add(
                    $"Runtime.Notify at 0x{notification.Offset:X4} has symbolic event name; manifest event existence cannot be proven");
                continue;
            }

            var manifestEvent = manifest.Abi.Events.FirstOrDefault(e =>
                string.Equals(e.Name, name, StringComparison.Ordinal));
            if (manifestEvent is null)
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
                    $"Runtime.Notify event '{name}' is not declared in the manifest.",
                    "Runtime.Notify event is declared in manifest",
                    Counterexample: null);
            }

            if (!TryNotificationArrayArguments(state, notification, out var args))
            {
                incompleteReasons.Add(
                    $"Runtime.Notify event '{name}' at 0x{notification.Offset:X4} has symbolic state; manifest event arity cannot be proven");
                continue;
            }

            if (args.Count != manifestEvent.Parameters.Count)
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
                    $"Runtime.Notify event '{name}' expects {manifestEvent.Parameters.Count} argument(s), got {args.Count}.",
                    "Runtime.Notify event argument count matches manifest",
                    Counterexample: null);
            }

            for (int i = 0; i < args.Count; i++)
            {
                var parameter = manifestEvent.Parameters[i];
                var check = CheckRuntimeNotificationArgumentType(state, args[i], parameter);
                if (check.Kind == NotificationArgumentTypeCheckKind.Match)
                    continue;

                string argumentName = string.IsNullOrWhiteSpace(parameter.Name)
                    ? $"#{i}"
                    : parameter.Name;
                if (check.Kind == NotificationArgumentTypeCheckKind.Incomplete)
                {
                    incompleteReasons.Add(
                        $"Runtime.Notify event '{name}' argument '{argumentName}' at 0x{notification.Offset:X4}: {check.Reason}");
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
                    $"Runtime.Notify event '{name}' argument '{argumentName}' {check.Reason}.",
                    "Runtime.Notify event argument types match manifest",
                    Counterexample: null);
            }
        }

        return null;
    }

    private static bool ShouldCheckNotificationAgainstManifest(
        RuntimeNotification notification,
        ImmutableArray<byte> currentScriptHash) =>
        currentScriptHash.IsDefaultOrEmpty
        || IsCurrentExecutingScriptHash(notification.ScriptHash, currentScriptHash);

    private static NotificationArgumentTypeCheck CheckRuntimeNotificationArgumentType(
        ExecutionState state,
        SymbolicValue argument,
        ContractParameterDefinition parameter,
        bool allowStructForArray = true)
    {
        string expectedType = string.IsNullOrWhiteSpace(parameter.Type) ? "Any" : parameter.Type;
        if (IsAbiType(expectedType, "Any"))
            return NotificationArgumentTypeCheck.Match();

        if (IsAbiType(expectedType, "PublicKey"))
            return CheckPublicKeyArgument(state, argument);

        if (TryGetManifestFixedByteLength(expectedType, out int fixedLength))
            return CheckFixedByteLengthArgument(state, argument, expectedType, fixedLength);

        if (IsAbiType(expectedType, "String"))
            return CheckStringArgument(state, argument);

        if (IsManifestByteStringLike(expectedType))
            return RequireNotificationSort(argument, expectedType, IsRuntimeByteStringLike(argument), "ByteString");

        if (IsAbiType(expectedType, "Integer"))
            return RequireNotificationSort(argument, expectedType, argument.Sort == Sort.Int, "Integer");

        if (IsAbiType(expectedType, "Boolean"))
            return RequireNotificationSort(argument, expectedType, argument.Sort == Sort.Bool, "Boolean");

        if (IsAbiType(expectedType, "Array"))
            return RequireNotificationSort(
                argument,
                expectedType,
                argument.Sort == Sort.Array || allowStructForArray && argument.Sort == Sort.Struct,
                allowStructForArray ? "Array or Struct" : "Array");

        if (IsAbiType(expectedType, "Map"))
            return RequireNotificationSort(argument, expectedType, argument.Sort == Sort.Map, "Map");

        if (IsAbiType(expectedType, "Struct"))
            return RequireNotificationSort(argument, expectedType, argument.Sort == Sort.Struct, "Struct");

        if (IsAbiType(expectedType, "InteropInterface"))
            return RequireNotificationSort(
                argument,
                expectedType,
                argument.Sort == Sort.InteropInterface,
                "InteropInterface");

        return NotificationArgumentTypeCheck.Incomplete(
            $"uses unsupported manifest ABI type '{expectedType}', so the emitted argument type cannot be proven");
    }

    private static NotificationArgumentTypeCheck CheckStringArgument(
        ExecutionState state,
        SymbolicValue argument)
    {
        if (!IsRuntimeByteStringLike(argument))
        {
            if (argument.Sort == Sort.Unknown)
            {
                return NotificationArgumentTypeCheck.Incomplete(
                    "expects String, but the emitted argument has unknown runtime type");
            }

            return NotificationArgumentTypeCheck.Mismatch(
                $"expects String, got {DescribeRuntimeArgumentType(state, argument)}");
        }

        if (TryGetConcreteRuntimeBytes(state, argument, out byte[] bytes))
        {
            return IsStrictUtf8(bytes)
                ? NotificationArgumentTypeCheck.Match()
                : NotificationArgumentTypeCheck.Mismatch(
                    "expects String, got ByteString that is not valid strict UTF-8");
        }

        if (TryGetRuntimeByteStringExpression(state, argument, out var argumentBytes)
            && HasStrictUtf8Constraint(state, argumentBytes))
            return NotificationArgumentTypeCheck.Match();

        return NotificationArgumentTypeCheck.Incomplete(
            "expects String, but emitted ByteString UTF-8 validity cannot be proven");
    }

    private static NotificationArgumentTypeCheck CheckFixedByteLengthArgument(
        ExecutionState state,
        SymbolicValue argument,
        string expectedType,
        int expectedLength)
    {
        if (!IsRuntimeByteStringLike(argument))
        {
            if (argument.Sort == Sort.Unknown)
            {
                return NotificationArgumentTypeCheck.Incomplete(
                    $"expects {expectedType}, but the emitted argument has unknown runtime type");
            }

            return NotificationArgumentTypeCheck.Mismatch(
                $"expects {expectedType}, got {DescribeRuntimeArgumentType(state, argument)}");
        }

        if (TryGetKnownByteLength(state, argument, out int knownLength))
        {
            return knownLength == expectedLength
                ? NotificationArgumentTypeCheck.Match()
                : NotificationArgumentTypeCheck.Mismatch(
                    $"expects {expectedType} with length {expectedLength} bytes, got ByteString with length {knownLength} bytes");
        }

        if (TryGetRuntimeByteStringExpression(state, argument, out var argumentBytes)
            && HasByteLengthConstraint(state, argumentBytes, expectedLength))
            return NotificationArgumentTypeCheck.Match();

        return NotificationArgumentTypeCheck.Incomplete(
            $"expects {expectedType} with length {expectedLength} bytes, but emitted ByteString length cannot be proven");
    }

    private static NotificationArgumentTypeCheck CheckPublicKeyArgument(
        ExecutionState state,
        SymbolicValue argument)
    {
        if (!IsRuntimeByteStringLike(argument))
        {
            if (argument.Sort == Sort.Unknown)
            {
                return NotificationArgumentTypeCheck.Incomplete(
                    "expects PublicKey, but the emitted argument has unknown runtime type");
            }

            return NotificationArgumentTypeCheck.Mismatch(
                $"expects PublicKey, got {DescribeRuntimeArgumentType(state, argument)}");
        }

        if (TryGetConcreteRuntimeBytes(state, argument, out byte[] bytes))
        {
            if (bytes.Length != CompressedPublicKeyByteLength)
            {
                return NotificationArgumentTypeCheck.Mismatch(
                    $"expects PublicKey with length {CompressedPublicKeyByteLength} bytes, got ByteString with length {bytes.Length} bytes");
            }

            return NeoEcPoint.IsValidEncoding(bytes)
                ? NotificationArgumentTypeCheck.Match()
                : NotificationArgumentTypeCheck.Mismatch(
                    "expects PublicKey, got ByteString that is not a valid ECPoint encoding");
        }

        if (!TryGetRuntimeByteStringExpression(state, argument, out var argumentBytes)
            || !HasByteLengthConstraint(state, argumentBytes, CompressedPublicKeyByteLength))
        {
            return NotificationArgumentTypeCheck.Incomplete(
                $"expects PublicKey with length {CompressedPublicKeyByteLength} bytes, but emitted ByteString length cannot be proven");
        }

        if (HasValidEcPointConstraint(state, argumentBytes))
            return NotificationArgumentTypeCheck.Match();

        return NotificationArgumentTypeCheck.Incomplete(
            "expects PublicKey, but emitted ByteString ECPoint validity cannot be proven");
    }

    private static NotificationArgumentTypeCheck RequireNotificationSort(
        SymbolicValue argument,
        string expectedType,
        bool matches,
        string expectedRuntimeType)
    {
        if (matches)
            return NotificationArgumentTypeCheck.Match();
        if (argument.Sort == Sort.Unknown)
        {
            return NotificationArgumentTypeCheck.Incomplete(
                $"expects {expectedType}, but the emitted argument has unknown runtime type");
        }

        return NotificationArgumentTypeCheck.Mismatch(
            $"expects {expectedType}, got {DescribeRuntimeArgumentType(argument)}; expected runtime type {expectedRuntimeType}");
    }

    private static bool HasConcreteRuntimeNotification(ExecutionResult execution, string name) =>
        execution.Halted.Any(state =>
            state.Telemetry.Notifications.Any(notification =>
                string.Equals(notification.ConcreteName, name, StringComparison.Ordinal)));

    private static IEnumerable<RuntimeNotification> CurrentTransferNotifications(
        ExecutionState state,
        ImmutableArray<byte> currentScriptHash) =>
        state.Telemetry.Notifications.Where(n => IsCurrentTransferNotification(n, currentScriptHash));

    private static bool IsCurrentTransferNotification(
        RuntimeNotification notification,
        ImmutableArray<byte> currentScriptHash) =>
        string.Equals(notification.ConcreteName, "Transfer", StringComparison.Ordinal)
        && IsCurrentExecutingScriptHash(notification.ScriptHash, currentScriptHash);

    private static bool TransferNotificationPayloadMatches(
        ExecutionState state,
        ContractMethodDescriptor method,
        RuntimeNotification notification,
        ImmutableArray<byte> currentScriptHash)
    {
        if (!IsCurrentTransferNotification(notification, currentScriptHash))
            return false;
        if (!TryNotificationArrayArguments(state, notification, out var args) || args.Count != 3)
            return false;

        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int amountIndex = FindAmountParameter(method);
        if (fromIndex < 0 || toIndex < 0 || amountIndex < 0)
            return false;

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        return IsMethodArgumentValue(args[0], fromSymbol)
            && IsMethodArgumentValue(args[1], toSymbol)
            && IsMethodArgumentValue(args[2], amountSymbol);
    }

    private static bool Nep17LifecycleTransferNotificationPayloadMatches(
        ExecutionState state,
        ContractMethodDescriptor method,
        RuntimeNotification notification,
        int accountIndex,
        int amountIndex,
        bool isMint,
        ImmutableArray<byte> currentScriptHash)
    {
        if (!IsCurrentTransferNotification(notification, currentScriptHash))
            return false;
        if (!TryNotificationArrayArguments(state, notification, out var args) || args.Count != 3)
            return false;

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        return isMint
            ? args[0].Expression is NullConst
              && IsMethodArgumentValue(args[1], accountSymbol)
              && IsMethodArgumentValue(args[2], amountSymbol)
            : IsMethodArgumentValue(args[0], accountSymbol)
              && args[1].Expression is NullConst
              && IsMethodArgumentValue(args[2], amountSymbol);
    }

    private static bool Nep11TransferNotificationPayloadMatches(
        ExecutionState state,
        ContractMethodDescriptor method,
        RuntimeNotification notification,
        ImmutableArray<byte> currentScriptHash)
    {
        if (!IsCurrentTransferNotification(notification, currentScriptHash))
            return false;
        if (!TryNotificationArrayArguments(state, notification, out var args) || args.Count != 4)
            return false;

        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        if (toIndex < 0 || tokenIdIndex < 0)
            return false;

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
        return ownerRead is not null
            && IsStorageReadExpression(args[0].Expression, ownerRead.Op.Offset)
            && IsMethodArgumentValue(args[1], toSymbol)
            && Expr.ConcreteInt(args[2].Expression) is { } amount
            && amount == 1
            && IsMethodArgumentValue(args[3], tokenIdSymbol);
    }

    private static bool Nep11LifecycleTransferNotificationPayloadMatches(
        ExecutionState state,
        ContractMethodDescriptor method,
        RuntimeNotification notification,
        int accountIndex,
        int amountIndex,
        int tokenIdIndex,
        bool isMint,
        ImmutableArray<byte> currentScriptHash)
    {
        if (!IsCurrentTransferNotification(notification, currentScriptHash))
            return false;
        if (!TryNotificationArrayArguments(state, notification, out var args) || args.Count != 4)
            return false;

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        bool amountMatches = amountIndex >= 0
            ? IsMethodArgumentValue(
                args[2],
                SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex))
            : Expr.ConcreteInt(args[2].Expression) is { } amount && amount == 1;

        if (!amountMatches || !IsMethodArgumentValue(args[3], tokenIdSymbol))
            return false;

        if (isMint)
        {
            if (accountIndex < 0)
                return false;
            string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
            return args[0].Expression is NullConst
                && IsMethodArgumentValue(args[1], toSymbol);
        }

        if (accountIndex < 0)
            return false;
        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[accountIndex].Name, accountIndex);
        return IsMethodArgumentValue(args[0], fromSymbol)
            && args[1].Expression is NullConst;
    }

    private static bool Nep11DivisibleTransferNotificationPayloadMatches(
        ExecutionState state,
        ContractMethodDescriptor method,
        RuntimeNotification notification,
        ImmutableArray<byte> currentScriptHash)
    {
        if (!IsCurrentTransferNotification(notification, currentScriptHash))
            return false;
        if (!TryNotificationArrayArguments(state, notification, out var args) || args.Count != 4)
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
        return IsMethodArgumentValue(args[0], fromSymbol)
            && IsMethodArgumentValue(args[1], toSymbol)
            && IsMethodArgumentValue(args[2], amountSymbol)
            && IsMethodArgumentValue(args[3], tokenIdSymbol);
    }

    private static bool TryNotificationArrayArguments(
        ExecutionState state,
        RuntimeNotification notification,
        out IReadOnlyList<SymbolicValue> args)
    {
        if (notification.State.Expression is HeapRef href
            && state.Heap.Get(href.ObjectId) is ArrayObject array)
        {
            args = array.Items;
            return true;
        }

        args = Array.Empty<SymbolicValue>();
        return false;
    }

    private static bool IsNep17PaymentCallback(ExternalCall call) =>
        string.Equals(call.Method, "onNEP17Payment", StringComparison.Ordinal);

    private static bool IsNep11PaymentCallback(ExternalCall call) =>
        string.Equals(call.Method, "onNEP11Payment", StringComparison.Ordinal);

    private static bool IsStandardReceiverCallbackVoidCall(
        ContractManifest manifest,
        ContractMethodDescriptor method,
        ExternalCall call) =>
        !call.ReturnValueDeclaredByMethodToken
        && ((IsNep17TransferMethod(manifest, method) && IsNep17PaymentCallback(call))
        || (IsNep11TransferMethod(manifest, method) && IsNep11PaymentCallback(call)));

    private static bool Nep17CallbackTargetsRecipient(
        ContractMethodDescriptor method,
        ExternalCall call)
    {
        int toIndex = FindToParameter(method);
        if (toIndex < 0 || call.TargetHash is null)
            return false;

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        return IsMethodArgumentValue(call.TargetHash, toSymbol);
    }

    private static bool Nep11CallbackTargetsRecipient(
        ContractMethodDescriptor method,
        ExternalCall call) =>
        Nep17CallbackTargetsRecipient(method, call);

    private static bool Nep17CallbackPayloadMatches(
        ContractMethodDescriptor method,
        ExternalCall call)
    {
        int fromIndex = FindFromParameter(method);
        int amountIndex = FindAmountParameter(method);
        int dataIndex = FindDataParameter(method);
        if (fromIndex < 0 || amountIndex < 0 || dataIndex < 0 || call.Args.Count != 3)
            return false;

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        string dataSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[dataIndex].Name, dataIndex);
        return IsMethodArgumentValue(call.Args[0], fromSymbol)
            && IsMethodArgumentValue(call.Args[1], amountSymbol)
            && IsMethodArgumentValue(call.Args[2], dataSymbol);
    }

    private static bool Nep11CallbackPayloadMatches(
        ExecutionState state,
        ContractMethodDescriptor method,
        ExternalCall call)
    {
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        int dataIndex = FindDataParameter(method);
        if (tokenIdIndex < 0 || dataIndex < 0 || call.Args.Count != 4)
            return false;

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        string dataSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[dataIndex].Name, dataIndex);
        var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
        return ownerRead is not null
            && IsStorageReadExpression(call.Args[0].Expression, ownerRead.Op.Offset)
            && Expr.ConcreteInt(call.Args[1].Expression) is { } amount
            && amount == 1
            && IsMethodArgumentValue(call.Args[2], tokenIdSymbol)
            && IsMethodArgumentValue(call.Args[3], dataSymbol);
    }

    private static bool Nep11DivisibleCallbackPayloadMatches(
        ContractMethodDescriptor method,
        ExternalCall call)
    {
        int fromIndex = FindFromParameter(method);
        int amountIndex = FindAmountParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        int dataIndex = FindDataParameter(method);
        if (fromIndex < 0 || amountIndex < 0 || tokenIdIndex < 0 || dataIndex < 0 || call.Args.Count != 4)
            return false;

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string amountSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[amountIndex].Name, amountIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        string dataSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[dataIndex].Name, dataIndex);
        return IsMethodArgumentValue(call.Args[0], fromSymbol)
            && IsMethodArgumentValue(call.Args[1], amountSymbol)
            && IsMethodArgumentValue(call.Args[2], tokenIdSymbol)
            && IsMethodArgumentValue(call.Args[3], dataSymbol);
    }

    private static bool HasPriorMatchingTransferNotification(
        ExecutionState state,
        ContractMethodDescriptor method,
        ImmutableArray<byte> currentScriptHash,
        int beforeOffset) =>
        state.Telemetry.Notifications.Any(n =>
            n.Offset < beforeOffset
            && TransferNotificationPayloadMatches(state, method, n, currentScriptHash));

    private static bool HasPriorMatchingNep11TransferNotification(
        ExecutionState state,
        ContractMethodDescriptor method,
        ImmutableArray<byte> currentScriptHash,
        int beforeOffset) =>
        state.Telemetry.Notifications.Any(n =>
            n.Offset < beforeOffset
            && Nep11TransferNotificationPayloadMatches(state, method, n, currentScriptHash));

    private static bool HasPriorMatchingNep11DivisibleTransferNotification(
        ExecutionState state,
        ContractMethodDescriptor method,
        ImmutableArray<byte> currentScriptHash,
        int beforeOffset) =>
        state.Telemetry.Notifications.Any(n =>
            n.Offset < beforeOffset
            && Nep11DivisibleTransferNotificationPayloadMatches(state, method, n, currentScriptHash));
}
