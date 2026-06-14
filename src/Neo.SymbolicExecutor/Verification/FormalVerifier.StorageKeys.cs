using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    private static AccountKeyMatch? FindStorageGetByAccountKey(ExecutionState state, string keySymbol) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Get)
            .Select(op => TryAccountStorageKeyPattern(state, op.Key, keySymbol, out var pattern)
                ? new AccountKeyMatch(op, pattern)
                : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageGetByAccountKey(
        ExecutionState state,
        string keySymbol,
        ImmutableArray<Expression> expectedPatterns) =>
        expectedPatterns
            .Select(pattern => FindStorageGetByAccountKey(state, keySymbol, pattern))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageGetByAccountKey(
        ExecutionState state,
        string keySymbol,
        Expression expectedPattern) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Get)
            .Select(op => TryAccountStorageKeyPattern(state, op.Key, keySymbol, out var pattern)
                && StorageKeysEqual(pattern, expectedPattern)
                    ? new AccountKeyMatch(op, pattern)
                    : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static StorageOp? FindStorageGetByCanonicalKey(
        ExecutionState state,
        Expression expectedKey,
        int beforeOffset) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Get && op.Offset < beforeOffset)
            .Where(op => TryCanonicalConcreteStorageKey(state, op.Key, out var key)
                && StorageKeysEqual(key, expectedKey))
            .OrderByDescending(op => op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageGetByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Get)
            .Select(op => TryAccountTokenStorageKeyPattern(state, op.Key, accountSymbol, tokenIdSymbol, out var pattern)
                ? new AccountKeyMatch(op, pattern)
                : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageGetByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns) =>
        expectedPatterns
            .Select(pattern => FindStorageGetByAccountTokenKey(state, accountSymbol, tokenIdSymbol, pattern))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageGetByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        Expression expectedPattern) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Get)
            .Select(op => TryAccountTokenStorageKeyPattern(state, op.Key, accountSymbol, tokenIdSymbol, out var pattern)
                && StorageKeysEqual(pattern, expectedPattern)
                    ? new AccountKeyMatch(op, pattern)
                    : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static ImmutableArray<Expression> InferNep17TransferBalanceKeyPatterns(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        List<string> incompleteReasons)
    {
        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        AddTransferExecutionSurfaceIncompleteReasons(execution, incompleteReasons);
        if (fromIndex < 0 || toIndex < 0)
        {
            incompleteReasons.Add("NEP-17 transfer method has no recognizable from/to parameters");
            return ImmutableArray<Expression>.Empty;
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
                continue;
            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return transfer path does not prove whether from == to or from != to");
                continue;
            }

            var fromGet = FindStorageGetByAccountKey(state, fromSymbol);
            var toGet = FindStorageGetByAccountKey(state, toSymbol);
            if (fromGet is null || toGet is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol))
                    incompleteReasons.Add("true-return transfer uses balance storage keys the account-key proof cannot yet normalize");
                continue;
            }
            if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            {
                incompleteReasons.Add("transfer reads from/to balances through different storage key templates");
                continue;
            }
            patterns.Add(fromGet.Pattern);
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferNep11DivisibleTransferBalanceKeyPatterns(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        List<string> incompleteReasons)
    {
        int fromIndex = FindFromParameter(method);
        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        AddTransferExecutionSurfaceIncompleteReasons(execution, incompleteReasons);
        if (fromIndex < 0 || toIndex < 0 || tokenIdIndex < 0)
        {
            incompleteReasons.Add("divisible NEP-11 transfer method has no recognizable from/to/tokenId parameters");
            return ImmutableArray<Expression>.Empty;
        }

        string fromSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[fromIndex].Name, fromIndex);
        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;
            if (PathConditionsProveSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
                continue;
            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, fromSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return divisible NEP-11 transfer path does not prove whether from == to or from != to");
                continue;
            }

            var fromGet = FindStorageGetByAccountTokenKey(state, fromSymbol, tokenIdSymbol);
            var toGet = FindStorageGetByAccountTokenKey(state, toSymbol, tokenIdSymbol);
            if (fromGet is null || toGet is null)
            {
                if (StorageMentionsBalanceSymbols(state, fromSymbol, toSymbol, tokenIdSymbol))
                    incompleteReasons.Add("true-return divisible NEP-11 transfer uses token balance storage keys the proof cannot yet normalize");
                continue;
            }
            if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            {
                incompleteReasons.Add("divisible NEP-11 transfer reads from/to token balances through different storage key templates");
                continue;
            }

            patterns.Add(fromGet.Pattern);
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferNep11OwnerBalanceKeyPatterns(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        List<string> incompleteReasons)
    {
        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        AddTransferExecutionSurfaceIncompleteReasons(execution, incompleteReasons);
        if (toIndex < 0 || tokenIdIndex < 0)
        {
            incompleteReasons.Add("NEP-11 transfer method has no recognizable to/tokenId parameters");
            return ImmutableArray<Expression>.Empty;
        }

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
            if (ownerRead is null)
            {
                if (StorageMentionsTokenSymbol(state, tokenIdSymbol))
                    incompleteReasons.Add("true-return NEP-11 transfer uses owner storage keys the token-key proof cannot yet normalize");
                continue;
            }

            string ownerSymbol = StorageReadSymbolName(ownerRead.Op.Offset);
            if (PathConditionsProveSymbolEquality(state.PathConditions, ownerSymbol, toSymbol))
                continue;
            if (!PathConditionsExcludeSymbolEquality(state.PathConditions, ownerSymbol, toSymbol))
            {
                incompleteReasons.Add("true-return NEP-11 transfer path does not prove whether owner == to or owner != to");
                continue;
            }

            var fromGet = FindStorageGetByAccountKey(state, ownerSymbol);
            var toGet = FindStorageGetByAccountKey(state, toSymbol);
            if (fromGet is null || toGet is null)
            {
                if (StorageMentionsOwnerBalanceSymbols(state, ownerSymbol, toSymbol, tokenIdSymbol))
                    incompleteReasons.Add("true-return NEP-11 transfer uses owner balance storage keys the proof cannot yet normalize");
                continue;
            }
            if (!StorageKeysEqual(fromGet.Pattern, toGet.Pattern))
            {
                incompleteReasons.Add("NEP-11 transfer reads owner/to balances through different storage key templates");
                continue;
            }

            patterns.Add(fromGet.Pattern);
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferNep11TransferOwnerKeyPatterns(
        ContractMethodDescriptor method,
        ExecutionResult execution,
        ISmtBackend? smtBackend,
        List<string> incompleteReasons)
    {
        int toIndex = FindToParameter(method);
        int tokenIdIndex = FindNep11TokenIdParameter(method);
        AddTransferExecutionSurfaceIncompleteReasons(execution, incompleteReasons);
        if (toIndex < 0 || tokenIdIndex < 0)
        {
            incompleteReasons.Add("NEP-11 transfer method has no recognizable to/tokenId parameters");
            return ImmutableArray<Expression>.Empty;
        }

        string toSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[toIndex].Name, toIndex);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(method.Parameters[tokenIdIndex].Name, tokenIdIndex);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in execution.Halted)
        {
            if (!TryReturnMayBeTrue(method, state, smtBackend, out bool returnMayBeTrue, out var returnReason))
            {
                incompleteReasons.Add(returnReason);
                continue;
            }
            if (!returnMayBeTrue)
                continue;

            var ownerRead = FindStorageGetByAccountKey(state, tokenIdSymbol);
            var ownerPut = ownerRead is null ? null : FindStoragePutByAccountKey(state, tokenIdSymbol, ownerRead.Pattern, ownerRead.Op.Offset);
            if (ownerRead is null || ownerPut is null || ownerPut.Op.Value is null || !IsSymbol(ownerPut.Op.Value.Expression, toSymbol))
            {
                if (StorageMentionsTokenSymbol(state, tokenIdSymbol))
                    incompleteReasons.Add("true-return transfer uses owner storage keys the token-key proof cannot yet normalize");
                continue;
            }

            patterns.Add(ownerRead.Pattern);
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferNep11TokensOfIndexKeyPatterns(
        ContractMethodDescriptor tokensOf,
        ExecutionResult execution,
        List<string> incompleteReasons)
    {
        var halted = execution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("tokensOf(owner) produced no successful HALT path");
        if (tokensOf.Parameters.Count == 0)
        {
            incompleteReasons.Add("tokensOf(owner) has no owner parameter");
            return ImmutableArray<Expression>.Empty;
        }

        string ownerSymbol = SymbolicEngine.MethodEntryArgSymbolName(tokensOf.Parameters[0].Name, 0);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in halted)
        {
            if (state.EvaluationStack.Count == 0)
            {
                incompleteReasons.Add("tokensOf(owner) halts without returning an iterator");
                continue;
            }

            var returned = state.Peek();
            if (returned.Sort != Sort.InteropInterface)
            {
                incompleteReasons.Add("tokensOf(owner) does not return an InteropInterface iterator");
                continue;
            }

            if (!TryGetNep11IteratorFindProvenance(
                    "tokensOf(owner)",
                    state,
                    returned,
                    out var prefix,
                    out _,
                    out var incompleteReason))
            {
                incompleteReasons.Add(incompleteReason!);
                continue;
            }

            if (!TryNormalizeAccountStorageKeyPattern(prefix.Expression, ownerSymbol, out var prefixPattern, out bool containsOwner)
                || !containsOwner)
            {
                incompleteReasons.Add("tokensOf(owner) Storage.Find prefix cannot be normalized as an owner-scoped index key template");
                continue;
            }

            patterns.Add(ByteCat(prefixPattern, TokenIdKeyPlaceholder()));
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferNep11TokensIndexKeyPatterns(
        ContractMethodDescriptor tokens,
        ExecutionResult execution,
        List<string> incompleteReasons)
    {
        var halted = execution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("tokens() produced no successful HALT path");

        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in halted)
        {
            if (state.EvaluationStack.Count == 0)
            {
                incompleteReasons.Add("tokens() halts without returning an iterator");
                continue;
            }

            var returned = state.Peek();
            if (returned.Sort != Sort.InteropInterface)
            {
                incompleteReasons.Add("tokens() does not return an InteropInterface iterator");
                continue;
            }

            if (!TryGetNep11IteratorFindProvenance(
                    "tokens()",
                    state,
                    returned,
                    out var prefix,
                    out _,
                    out var incompleteReason))
            {
                incompleteReasons.Add(incompleteReason!);
                continue;
            }

            if (Expr.CanonicalBytes(prefix.Expression) is not { Length: > 0 })
            {
                incompleteReasons.Add("tokens() Storage.Find prefix is not a non-empty concrete token index namespace");
                continue;
            }

            patterns.Add(ByteCat(prefix.Expression, TokenIdKeyPlaceholder()));
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferNep11DivisibleOwnerOfIndexKeyPatterns(
        ContractMethodDescriptor ownerOf,
        ExecutionResult execution,
        List<string> incompleteReasons)
    {
        var halted = execution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("ownerOf(tokenId) produced no successful HALT path");
        if (ownerOf.Parameters.Count == 0)
        {
            incompleteReasons.Add("ownerOf(tokenId) has no tokenId parameter");
            return ImmutableArray<Expression>.Empty;
        }

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(ownerOf.Parameters[0].Name, 0);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in halted)
        {
            if (state.EvaluationStack.Count == 0)
            {
                incompleteReasons.Add("ownerOf(tokenId) halts without returning an iterator");
                continue;
            }

            var returned = state.Peek();
            if (returned.Sort != Sort.InteropInterface)
            {
                incompleteReasons.Add("ownerOf(tokenId) does not return an InteropInterface iterator");
                continue;
            }

            if (!TryGetNep11IteratorFindProvenance(
                    "ownerOf(tokenId)",
                    state,
                    returned,
                    out var prefix,
                    out _,
                    out var incompleteReason))
            {
                incompleteReasons.Add(incompleteReason!);
                continue;
            }

            if (!TryNormalizeTokenIdStorageKeyPattern(prefix.Expression, tokenIdSymbol, out var prefixPattern, out bool containsTokenId)
                || !containsTokenId)
            {
                incompleteReasons.Add("ownerOf(tokenId) Storage.Find prefix cannot be normalized as a tokenId-scoped owner index key template");
                continue;
            }

            patterns.Add(ByteCat(prefixPattern, AccountKeyPlaceholder()));
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferBalanceOfStorageKeyPatterns(
        ContractMethodDescriptor balanceOf,
        ExecutionResult execution,
        List<string> incompleteReasons)
    {
        var halted = execution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("balanceOf(account) produced no successful HALT path");
        if (balanceOf.Parameters.Count == 0)
        {
            incompleteReasons.Add("balanceOf(account) has no account parameter");
            return ImmutableArray<Expression>.Empty;
        }

        string accountSymbol = SymbolicEngine.MethodEntryArgSymbolName(balanceOf.Parameters[0].Name, 0);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in halted)
        {
            foreach (var get in state.Telemetry.StorageOps.Where(op => op.Kind == StorageOpKind.Get))
            {
                if (TryAccountStorageKeyPattern(state, get.Key, accountSymbol, out var pattern))
                    patterns.Add(pattern);
                else if (get.Key.Expression.FreeSymbols().Contains(accountSymbol, StringComparer.Ordinal))
                    incompleteReasons.Add("balanceOf(account) reads a balance-shaped storage key the account-key proof cannot yet normalize");
            }
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferDivisibleBalanceOfStorageKeyPatterns(
        ContractMethodDescriptor balanceOf,
        ExecutionResult execution,
        List<string> incompleteReasons)
    {
        var halted = execution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("balanceOf(owner, tokenId) produced no successful HALT path");
        if (balanceOf.Parameters.Count < 2)
        {
            incompleteReasons.Add("balanceOf(owner, tokenId) has no owner/tokenId parameters");
            return ImmutableArray<Expression>.Empty;
        }

        string ownerSymbol = SymbolicEngine.MethodEntryArgSymbolName(balanceOf.Parameters[0].Name, 0);
        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(balanceOf.Parameters[1].Name, 1);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in halted)
        {
            foreach (var get in state.Telemetry.StorageOps.Where(op => op.Kind == StorageOpKind.Get))
            {
                if (TryAccountTokenStorageKeyPattern(state, get.Key, ownerSymbol, tokenIdSymbol, out var pattern))
                    patterns.Add(pattern);
                else if (get.Key.Expression.FreeSymbols().Any(symbol =>
                             string.Equals(symbol, ownerSymbol, StringComparison.Ordinal)
                             || string.Equals(symbol, tokenIdSymbol, StringComparison.Ordinal)))
                {
                    incompleteReasons.Add("balanceOf(owner, tokenId) reads a token balance-shaped storage key the proof cannot yet normalize");
                }
            }
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static ImmutableArray<Expression> InferOwnerOfStorageKeyPatterns(
        ContractMethodDescriptor ownerOf,
        ExecutionResult execution,
        List<string> incompleteReasons)
    {
        var halted = execution.Halted.ToList();
        if (halted.Count == 0)
            incompleteReasons.Add("ownerOf(tokenId) produced no successful HALT path");
        if (ownerOf.Parameters.Count == 0)
        {
            incompleteReasons.Add("ownerOf(tokenId) has no tokenId parameter");
            return ImmutableArray<Expression>.Empty;
        }

        string tokenIdSymbol = SymbolicEngine.MethodEntryArgSymbolName(ownerOf.Parameters[0].Name, 0);
        var patterns = ImmutableArray.CreateBuilder<Expression>();
        foreach (var state in halted)
        {
            foreach (var get in state.Telemetry.StorageOps.Where(op => op.Kind == StorageOpKind.Get))
            {
                if (TryAccountStorageKeyPattern(state, get.Key, tokenIdSymbol, out var pattern))
                    patterns.Add(pattern);
                else if (get.Key.Expression.FreeSymbols().Contains(tokenIdSymbol, StringComparer.Ordinal))
                    incompleteReasons.Add("ownerOf(tokenId) reads an owner-shaped storage key the token-key proof cannot yet normalize");
            }
        }

        return patterns.Distinct().ToImmutableArray();
    }

    private static AccountKeyMatch? FindStoragePutByAccountKey(
        ExecutionState state,
        string keySymbol,
        Expression expectedPattern,
        int afterOffset) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Put && op.Offset > afterOffset)
            .Select(op => TryAccountStorageKeyPattern(state, op.Key, keySymbol, out var pattern)
                && StorageKeysEqual(pattern, expectedPattern)
                    ? new AccountKeyMatch(op, pattern)
                    : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStoragePutByAccountKey(
        ExecutionState state,
        string keySymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStoragePutByAccountKey(state, keySymbol, pattern, afterOffset))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageDeleteByAccountKey(
        ExecutionState state,
        string keySymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageDeleteByAccountKey(state, keySymbol, pattern, afterOffset))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageDeleteByAccountKey(
        ExecutionState state,
        string keySymbol,
        Expression expectedPattern,
        int afterOffset) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Delete && op.Offset > afterOffset)
            .Select(op => TryAccountStorageKeyPattern(state, op.Key, keySymbol, out var pattern)
                && StorageKeysEqual(pattern, expectedPattern)
                    ? new AccountKeyMatch(op, pattern)
                    : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static StorageOp? FindLaterStorageMutationByAccountKey(
        ExecutionState state,
        string keySymbol,
        Expression expectedPattern,
        int afterOffset) =>
        state.Telemetry.StorageOps
            .Where(op => (op.Kind is StorageOpKind.Put or StorageOpKind.Delete) && op.Offset > afterOffset)
            .Where(op => TryAccountStorageKeyPattern(state, op.Key, keySymbol, out var pattern)
                         && StorageKeysEqual(pattern, expectedPattern))
            .OrderBy(op => op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStoragePutByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        Expression expectedPattern,
        int afterOffset) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == StorageOpKind.Put && op.Offset > afterOffset)
            .Select(op => TryAccountTokenStorageKeyPattern(state, op.Key, accountSymbol, tokenIdSymbol, out var pattern)
                && StorageKeysEqual(pattern, expectedPattern)
                    ? new AccountKeyMatch(op, pattern)
                    : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStoragePutByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStoragePutByAccountTokenKey(state, accountSymbol, tokenIdSymbol, pattern, afterOffset))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageDeleteByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByAccountTokenKey(
                state,
                StorageOpKind.Delete,
                accountSymbol,
                tokenIdSymbol,
                pattern,
                afterOffset))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStoragePutByTokenIdKey(
        ExecutionState state,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByTokenIdKey(
                state,
                StorageOpKind.Put,
                tokenIdSymbol,
                pattern,
                afterOffset))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageDeleteByTokenIdKey(
        ExecutionState state,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByTokenIdKey(
                state,
                StorageOpKind.Delete,
                tokenIdSymbol,
                pattern,
                afterOffset))
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static StorageOp? FindLaterStoragePutByTokenIdKey(
        ExecutionState state,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByTokenIdKey(
                state,
                StorageOpKind.Put,
                tokenIdSymbol,
                pattern,
                afterOffset)?.Op)
            .Where(op => op is not null)
            .OrderBy(op => op!.Offset)
            .FirstOrDefault();

    private static StorageOp? FindLaterStorageDeleteByTokenIdKey(
        ExecutionState state,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByTokenIdKey(
                state,
                StorageOpKind.Delete,
                tokenIdSymbol,
                pattern,
                afterOffset)?.Op)
            .Where(op => op is not null)
            .OrderBy(op => op!.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageMutationByTokenIdKey(
        ExecutionState state,
        StorageOpKind kind,
        string tokenIdSymbol,
        Expression expectedPattern,
        int afterOffset) =>
        state.Telemetry.StorageOps
            .Where(op => op.Kind == kind && op.Offset > afterOffset)
            .Select(op => TryTokenIdStorageKeyPattern(state, op.Key, tokenIdSymbol, out var pattern)
                && StorageKeysEqual(pattern, expectedPattern)
                    ? new AccountKeyMatch(op, pattern)
                    : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static StorageOp? FindAnyStorageMutationByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByAccountTokenKey(
                state,
                kind: null,
                accountSymbol,
                tokenIdSymbol,
                pattern,
                afterOffset)?.Op)
            .Where(op => op is not null)
            .OrderBy(op => op!.Offset)
            .FirstOrDefault();

    private static StorageOp? FindLaterStoragePutByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByAccountTokenKey(
                state,
                StorageOpKind.Put,
                accountSymbol,
                tokenIdSymbol,
                pattern,
                afterOffset)?.Op)
            .Where(op => op is not null)
            .OrderBy(op => op!.Offset)
            .FirstOrDefault();

    private static StorageOp? FindLaterStorageDeleteByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        ImmutableArray<Expression> expectedPatterns,
        int afterOffset) =>
        expectedPatterns
            .Select(pattern => FindStorageMutationByAccountTokenKey(
                state,
                StorageOpKind.Delete,
                accountSymbol,
                tokenIdSymbol,
                pattern,
                afterOffset)?.Op)
            .Where(op => op is not null)
            .OrderBy(op => op!.Offset)
            .FirstOrDefault();

    private static AccountKeyMatch? FindStorageMutationByAccountTokenKey(
        ExecutionState state,
        StorageOpKind? kind,
        string accountSymbol,
        string tokenIdSymbol,
        Expression expectedPattern,
        int afterOffset) =>
        state.Telemetry.StorageOps
            .Where(op => (kind is null
                    ? op.Kind is StorageOpKind.Put or StorageOpKind.Delete
                    : op.Kind == kind)
                && op.Offset > afterOffset)
            .Select(op => TryAccountTokenStorageKeyPattern(state, op.Key, accountSymbol, tokenIdSymbol, out var pattern)
                && StorageKeysEqual(pattern, expectedPattern)
                    ? new AccountKeyMatch(op, pattern)
                    : null)
            .Where(match => match is not null)
            .OrderBy(match => match!.Op.Offset)
            .FirstOrDefault();

    private static StorageOp? FindLaterStorageMutationByAccountTokenKey(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol,
        Expression expectedPattern,
        int afterOffset) =>
        state.Telemetry.StorageOps
            .Where(op => (op.Kind is StorageOpKind.Put or StorageOpKind.Delete) && op.Offset > afterOffset)
            .Where(op => TryAccountTokenStorageKeyPattern(state, op.Key, accountSymbol, tokenIdSymbol, out var pattern)
                         && StorageKeysEqual(pattern, expectedPattern))
            .OrderBy(op => op.Offset)
            .FirstOrDefault();

    private static bool StorageMentionsBalanceSymbols(
        ExecutionState state,
        string fromSymbol,
        string toSymbol) =>
        state.Telemetry.StorageOps.Any(op =>
            RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().Any(s =>
                string.Equals(s, fromSymbol, StringComparison.Ordinal)
                || string.Equals(s, toSymbol, StringComparison.Ordinal)));

    private static bool StorageMentionsOwnerBalanceSymbols(
        ExecutionState state,
        string fromSymbol,
        string toSymbol,
        string tokenIdSymbol) =>
        state.Telemetry.StorageOps.Any(op =>
        {
            var symbols = RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().ToArray();
            bool mentionsOwner = symbols.Any(s =>
                string.Equals(s, fromSymbol, StringComparison.Ordinal)
                || string.Equals(s, toSymbol, StringComparison.Ordinal));
            bool mentionsTokenId = symbols.Any(s => string.Equals(s, tokenIdSymbol, StringComparison.Ordinal));
            return mentionsOwner && !mentionsTokenId;
        });

    private static bool StorageMentionsTokenSymbol(
        ExecutionState state,
        string tokenIdSymbol) =>
        state.Telemetry.StorageOps.Any(op =>
            RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().Any(s =>
                string.Equals(s, tokenIdSymbol, StringComparison.Ordinal)));

    private static bool StorageMentionsAccountSymbol(
        ExecutionState state,
        string accountSymbol) =>
        state.Telemetry.StorageOps.Any(op =>
            RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().Any(s =>
                string.Equals(s, accountSymbol, StringComparison.Ordinal)));

    private static bool StorageMentionsBalanceSymbols(
        ExecutionState state,
        string fromSymbol,
        string toSymbol,
        string tokenIdSymbol) =>
        state.Telemetry.StorageOps.Any(op =>
            RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().Any(s =>
                string.Equals(s, fromSymbol, StringComparison.Ordinal)
                || string.Equals(s, toSymbol, StringComparison.Ordinal)
                || string.Equals(s, tokenIdSymbol, StringComparison.Ordinal)));

    private static bool StorageMentionsAccountTokenSymbols(
        ExecutionState state,
        string accountSymbol,
        string tokenIdSymbol) =>
        state.Telemetry.StorageOps.Any(op =>
        {
            var symbols = RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().ToArray();
            return symbols.Contains(accountSymbol, StringComparer.Ordinal)
                && symbols.Contains(tokenIdSymbol, StringComparer.Ordinal);
        });

    private static bool SelfTransferBalanceMutation(
        ExecutionState state,
        string fromSymbol,
        string toSymbol,
        out StorageOp? mutation,
        out string incompleteReason)
    {
        mutation = null;
        incompleteReason = "";
        foreach (var op in state.Telemetry.StorageOps
                     .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                     .OrderBy(op => op.Offset))
        {
            if (TryAccountStorageKeyPattern(state, op.Key, fromSymbol, out _)
                || TryAccountStorageKeyPattern(state, op.Key, toSymbol, out _))
            {
                mutation = op;
                return true;
            }

            if (RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().Any(s =>
                    string.Equals(s, fromSymbol, StringComparison.Ordinal)
                    || string.Equals(s, toSymbol, StringComparison.Ordinal)))
            {
                incompleteReason = "self-transfer mutates a balance-shaped storage key the account-key proof cannot yet normalize";
            }
        }

        return false;
    }

    private static bool SelfTransferTokenBalanceMutation(
        ExecutionState state,
        string fromSymbol,
        string toSymbol,
        string tokenIdSymbol,
        out StorageOp? mutation,
        out string incompleteReason)
    {
        mutation = null;
        incompleteReason = "";
        foreach (var op in state.Telemetry.StorageOps
                     .Where(op => op.Kind is StorageOpKind.Put or StorageOpKind.Delete)
                     .OrderBy(op => op.Offset))
        {
            if (TryAccountTokenStorageKeyPattern(state, op.Key, fromSymbol, tokenIdSymbol, out _)
                || TryAccountTokenStorageKeyPattern(state, op.Key, toSymbol, tokenIdSymbol, out _))
            {
                mutation = op;
                return true;
            }

            if (RuntimeStorageKeyExpressionOrOriginal(state, op.Key).FreeSymbols().Any(s =>
                    string.Equals(s, fromSymbol, StringComparison.Ordinal)
                    || string.Equals(s, toSymbol, StringComparison.Ordinal)
                    || string.Equals(s, tokenIdSymbol, StringComparison.Ordinal)))
            {
                incompleteReason = "self-transfer mutates a token balance-shaped storage key the proof cannot yet normalize";
            }
        }

        return false;
    }

    private static bool TryAccountStorageKeyPattern(
        ExecutionState state,
        SymbolicValue key,
        string accountSymbol,
        out Expression pattern)
    {
        pattern = key.Expression;
        var expression = RuntimeStorageKeyExpressionOrOriginal(state, key);
        return TryNormalizeAccountStorageKeyPattern(expression, accountSymbol, out pattern, out bool containsAccount)
            && containsAccount;
    }

    private static bool TryAccountTokenStorageKeyPattern(
        ExecutionState state,
        SymbolicValue key,
        string accountSymbol,
        string tokenIdSymbol,
        out Expression pattern)
    {
        pattern = key.Expression;
        var expression = RuntimeStorageKeyExpressionOrOriginal(state, key);
        return TryNormalizeAccountTokenStorageKeyPattern(
                expression,
                accountSymbol,
                tokenIdSymbol,
                out pattern,
                out bool containsAccount,
                out bool containsTokenId)
            && containsAccount
            && containsTokenId;
    }

    private static bool TryTokenIdStorageKeyPattern(
        ExecutionState state,
        SymbolicValue key,
        string tokenIdSymbol,
        out Expression pattern)
    {
        pattern = key.Expression;
        var expression = RuntimeStorageKeyExpressionOrOriginal(state, key);
        return TryNormalizeTokenIdStorageKeyPattern(expression, tokenIdSymbol, out pattern, out bool containsTokenId)
            && containsTokenId;
    }

    private static bool TryNormalizeAccountStorageKeyPattern(
        Expression expression,
        string accountSymbol,
        out Expression pattern,
        out bool containsAccount)
    {
        containsAccount = false;
        if (IsFullHash160AccountKeyExpression(expression, accountSymbol))
        {
            pattern = AccountKeyPlaceholder();
            containsAccount = true;
            return true;
        }

        if (expression is Symbol)
        {
            pattern = expression;
            return false;
        }

        if (expression.IsConcrete)
        {
            pattern = expression;
            return true;
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } binary
            && TryNormalizeAccountStorageKeyPattern(binary.Left, accountSymbol, out var left, out bool leftContains)
            && TryNormalizeAccountStorageKeyPattern(binary.Right, accountSymbol, out var right, out bool rightContains))
        {
            pattern = new BinaryExpr(Sort.Bytes, "cat", left, right);
            containsAccount = leftContains || rightContains;
            return true;
        }

        pattern = expression;
        return false;
    }

    private static bool TryNormalizeTokenIdStorageKeyPattern(
        Expression expression,
        string tokenIdSymbol,
        out Expression pattern,
        out bool containsTokenId)
    {
        containsTokenId = false;
        if (IsSymbol(expression, tokenIdSymbol))
        {
            pattern = TokenIdKeyPlaceholder();
            containsTokenId = true;
            return true;
        }

        if (expression is Symbol)
        {
            pattern = expression;
            return false;
        }

        if (expression.IsConcrete)
        {
            pattern = expression;
            return true;
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } binary
            && TryNormalizeTokenIdStorageKeyPattern(binary.Left, tokenIdSymbol, out var left, out bool leftContains)
            && TryNormalizeTokenIdStorageKeyPattern(binary.Right, tokenIdSymbol, out var right, out bool rightContains))
        {
            pattern = ByteCat(left, right);
            containsTokenId = leftContains || rightContains;
            return true;
        }

        pattern = expression;
        return false;
    }

    private static bool TryNormalizeAccountTokenStorageKeyPattern(
        Expression expression,
        string accountSymbol,
        string tokenIdSymbol,
        out Expression pattern,
        out bool containsAccount,
        out bool containsTokenId)
    {
        containsAccount = false;
        containsTokenId = false;
        if (IsFullHash160AccountKeyExpression(expression, accountSymbol))
        {
            pattern = AccountKeyPlaceholder();
            containsAccount = true;
            return true;
        }

        if (IsSymbol(expression, tokenIdSymbol))
        {
            pattern = TokenIdKeyPlaceholder();
            containsTokenId = true;
            return true;
        }

        if (expression is Symbol)
        {
            pattern = expression;
            return false;
        }

        if (expression.IsConcrete)
        {
            pattern = expression;
            return true;
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } binary
            && TryNormalizeAccountTokenStorageKeyPattern(
                binary.Left,
                accountSymbol,
                tokenIdSymbol,
                out var left,
                out bool leftContainsAccount,
                out bool leftContainsTokenId)
            && TryNormalizeAccountTokenStorageKeyPattern(
                binary.Right,
                accountSymbol,
                tokenIdSymbol,
                out var right,
                out bool rightContainsAccount,
                out bool rightContainsTokenId))
        {
            pattern = new BinaryExpr(Sort.Bytes, "cat", left, right);
            containsAccount = leftContainsAccount || rightContainsAccount;
            containsTokenId = leftContainsTokenId || rightContainsTokenId;
            return true;
        }

        pattern = expression;
        return false;
    }

    private static ImmutableArray<Expression> InferTotalSupplyStorageKeys(
        ExecutionResult supplyExecution,
        out List<string> reasons)
    {
        reasons = new List<string>();
        var keys = ImmutableArray.CreateBuilder<Expression>();
        var halted = supplyExecution.Halted.ToList();

        if (halted.Count == 0)
            reasons.Add("totalSupply() produced no successful HALT path");

        foreach (var reason in IncompleteReasons(supplyExecution))
            reasons.Add("totalSupply(): " + reason);

        foreach (var state in halted)
        {
            foreach (var get in state.Telemetry.StorageOps.Where(op => op.Kind == StorageOpKind.Get))
            {
                if (TryCanonicalConcreteStorageKey(state, get.Key, out var key))
                    keys.Add(key);
                else
                    reasons.Add("totalSupply() reads storage through a dynamic or unsupported key");
            }
        }

        return keys.Distinct().ToImmutableArray();
    }
}
