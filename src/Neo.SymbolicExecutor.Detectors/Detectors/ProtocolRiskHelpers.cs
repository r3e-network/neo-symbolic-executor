using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Neo.SymbolicExecutor.Nef;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

internal static class ProtocolRiskHelpers
{
    private static readonly string[] PrivilegedNames =
    {
        "mint", "burn", "pause", "unpause", "setFee", "setFees", "setOracle", "setOwner",
        "setAdmin", "withdraw", "sweep", "upgrade", "update", "destroy", "claim", "rescue"
    };

    private static readonly string[] SwapNames =
    {
        "swap", "exchange", "trade", "buy", "sell", "addLiquidity", "removeLiquidity",
        "deposit", "withdraw", "mint", "redeem"
    };

    private static readonly string[] SlippageHints =
    {
        "minout", "amountoutmin", "amountmin", "minimumout", "slippage", "limit", "deadline"
    };

    private static readonly string[] OracleHints =
    {
        "oracle", "price", "twap", "round", "feed", "rate"
    };

    private static readonly string[] FreshnessHints =
    {
        "timestamp", "updated", "updatedat", "height", "round", "deadline", "ttl", "expiry"
    };

    private static readonly string[] DefiStateHints =
    {
        "pool", "reserve", "vault", "share", "liquidity", "amm", "route", "pair", "lp"
    };

    private static readonly string[] NftKeyHints =
    {
        "owner", "approval", "approved", "token", "nft", "nep11"
    };

    public static ContractMethodDescriptor? MethodForState(AnalysisContext context, ExecutionState state)
    {
        var methods = context.Manifest?.Abi.Methods;
        if (methods is null || methods.Count == 0 || state.Path.Count == 0) return null;

        // Prefer the entry method: under per-method analysis, state.Path[0] is the offset we
        // jumped to via CreateMethodEntryState. Without this short-circuit we'd attribute the
        // state to whichever manifest method has the highest Offset reached (e.g. a CALL into
        // a higher-offset manifest method), which mis-classifies privileged/swap/NFT-shaped
        // entry methods that happen to dispatch to other manifest entries.
        int entryOffset = state.Path[0];
        var entry = methods.FirstOrDefault(m => m.Offset == entryOffset);
        if (entry is not null) return entry;

        // Fallback for states that did NOT enter via per-method seeding (e.g. legacy run from
        // offset 0): pick the highest-offset manifest method visited along the path.
        var exactVisited = methods
            .Where(m => state.Path.Contains(m.Offset))
            .OrderByDescending(m => m.Offset)
            .FirstOrDefault();
        if (exactVisited is not null) return exactVisited;

        int lastVisited = state.Path.Max();
        return methods
            .Where(m => m.Offset <= lastVisited)
            .OrderByDescending(m => m.Offset)
            .FirstOrDefault();
    }

    public static bool IsPrivilegedMethodName(string name) =>
        PrivilegedNames.Any(h => ContainsFolded(name, h));

    public static bool IsSwapLikeMethodName(string name) =>
        SwapNames.Any(h => ContainsFolded(name, h));

    public static bool HasAuthBefore(ExecutionState state, int offset) =>
        state.Telemetry.WitnessChecksEnforced.Any(o => o < offset)
        || state.Telemetry.CallerHashChecks.Any(o => o < offset)
        || state.Telemetry.SignatureChecks.Any(o => o < offset);

    /// <summary>
    /// Resolve the symbol name the engine seeded for argument <paramref name="index"/> of
    /// <paramref name="method"/>. Mirrors <see cref="SymbolicEngine.MethodEntryArgSymbolName"/>
    /// so a manifest-named parameter becomes <c>arg_&lt;name&gt;</c>; positional becomes
    /// <c>arg&lt;i&gt;</c>; missing parameter at that index falls back to
    /// <paramref name="defaultIfMissing"/>. Used by detectors that scan a state's
    /// PathConditions for branches on a specific argument (amount validation, deploy update
    /// flag, oracle response code, etc.).
    /// </summary>
    public static string MethodArgSymbolName(
        Nef.ContractMethodDescriptor method,
        int index,
        string defaultIfMissing)
    {
        if (index < 0 || index >= method.Parameters.Count) return defaultIfMissing;
        var p = method.Parameters[index];
        return SymbolicEngine.MethodEntryArgSymbolName(p.Name, index);
    }

    /// <summary>
    /// True iff <paramref name="state"/> is a per-method analysis entry state for
    /// <paramref name="method"/> — i.e. <c>state.Path[0]</c> is the method's offset. Detectors
    /// that only fire on per-method-seeded explorations use this guard to skip states that
    /// reached the method via an internal CALL.
    /// </summary>
    public static bool IsEntryStateFor(ExecutionState state, Nef.ContractMethodDescriptor method) =>
        state.Path.Count > 0 && state.Path[0] == method.Offset;

    /// <summary>
    /// True iff the state has any enforced authorization signal on this path: a witness check
    /// whose result gates the path (<see cref="Telemetry.WitnessChecksEnforced"/>), a caller-hash
    /// check (<see cref="Telemetry.CallerHashChecks"/>), or a signature verification
    /// (<see cref="Telemetry.SignatureChecks"/>). Detectors use this to downgrade severity when
    /// a sensitive operation is gated by *some* form of authentication, even if the specific
    /// detector only cares about one type of risk. Note that
    /// <see cref="ReplayAttackDetector"/> intentionally uses a narrower predicate
    /// (signature/caller only) because witness checks are per-transaction bound and not
    /// off-chain replayable.
    /// </summary>
    public static bool HasAnyEnforcedAuth(ExecutionState state) =>
        state.Telemetry.WitnessChecksEnforced.Count > 0
        || state.Telemetry.CallerHashChecks.Count > 0
        || state.Telemetry.SignatureChecks.Count > 0;

    public static IEnumerable<(int Offset, string Kind)> SensitiveOps(ExecutionState state)
    {
        foreach (var op in state.Telemetry.StorageOps)
        {
            if (IsStateWrite(op))
                yield return (op.Offset, "storage-write");
        }

        foreach (var call in state.Telemetry.ExternalCalls)
            yield return (call.Offset, "external-call");
    }

    public static bool IsStateWrite(StorageOp op) =>
        op.Kind is StorageOpKind.Put or StorageOpKind.Delete;

    public static bool IsTokenTransferCall(ExternalCall call) =>
        string.Equals(call.Method, "transfer", StringComparison.OrdinalIgnoreCase)
        && call.TargetHash?.AsConcreteBytes() is { Length: 20 };

    public static bool HasSlippageSignal(ExecutionState state)
    {
        if (AnySymbolContains(state, SlippageHints)) return true;
        return state.Telemetry.StorageOps.Any(op => KeyContainsAny(op, SlippageHints));
    }

    public static bool HasOracleFreshnessSignal(ExecutionState state)
    {
        if (state.Telemetry.TimeAccesses.Count > 0) return true;
        if (AnySymbolContains(state, FreshnessHints)) return true;
        if (state.Telemetry.StorageOps.Any(op => KeyContainsAny(op, OracleHints) || KeyContainsAny(op, FreshnessHints)))
            return true;
        return state.Telemetry.ExternalCalls.Any(call =>
            OracleHints.Any(h => ContainsFolded(call.Method, h))
            || FreshnessHints.Any(h => ContainsFolded(call.Method, h)));
    }

    public static bool HasDefiStateSignal(ExecutionState state)
    {
        if (AnySymbolContains(state, DefiStateHints)) return true;
        return state.Telemetry.StorageOps.Any(op => KeyContainsAny(op, DefiStateHints));
    }

    public static bool HasDefiSourceSignal(AnalysisContext context, ExecutionState state)
    {
        var method = MethodForState(context, state);
        return context.SourceHints?.MethodContainsAny(
            method?.Name,
            method?.Parameters.Count,
            SwapNames.Concat(DefiStateHints).Concat(OracleHints)) == true;
    }

    public static bool HasSourceSlippageSignal(AnalysisContext context, ExecutionState state)
    {
        var method = MethodForState(context, state);
        return context.SourceHints?.MethodContainsAny(
            method?.Name,
            method?.Parameters.Count,
            SlippageHints,
            includeStringLiterals: false) == true;
    }

    public static bool HasSourceFreshnessSignal(AnalysisContext context, ExecutionState state)
    {
        var method = MethodForState(context, state);
        return context.SourceHints?.MethodContainsAny(
            method?.Name,
            method?.Parameters.Count,
            FreshnessHints.Concat(OracleHints),
            includeStringLiterals: false) == true;
    }

    public static bool HasNftSourceSignal(AnalysisContext context, ExecutionState state)
    {
        var method = MethodForState(context, state);
        return context.SourceHints?.MethodContainsAny(
            method?.Name,
            method?.Parameters.Count,
            NftKeyHints) == true;
    }

    public static bool HasDynamicStateWrite(ExecutionState state) =>
        state.Telemetry.StorageOps.Any(IsDynamicStateWrite);

    public static bool IsDynamicStateWrite(StorageOp op) =>
        IsStateWrite(op) && op.Key.AsConcreteBytes() is null;

    public static bool IsNftOwnershipWrite(StorageOp op) =>
        IsStateWrite(op) && KeyContainsAny(op, NftKeyHints);

    public static bool KeyContainsAny(StorageOp op, IReadOnlyList<string> hints)
    {
        string? text = StorageKeyText(op);
        return text is not null && hints.Any(h => ContainsFolded(text, h));
    }

    private static bool AnySymbolContains(ExecutionState state, IReadOnlyList<string> hints) =>
        state.PathConditions
            .SelectMany(c => c.FreeSymbols())
            .Any(symbol => hints.Any(h => ContainsFolded(symbol, h)));

    private static string? StorageKeyText(StorageOp op)
    {
        var bytes = op.Key.AsConcreteBytes();
        if (bytes is null || bytes.Length == 0) return null;
        if (bytes.Any(b => b < 0x20 || b > 0x7E)) return null;
        return Encoding.UTF8.GetString(bytes);
    }

    private static bool ContainsFolded(string value, string hint) =>
        Fold(value).Contains(Fold(hint), StringComparison.OrdinalIgnoreCase);

    private static string Fold(string value) =>
        value.Replace("_", "", StringComparison.Ordinal).Replace("-", "", StringComparison.Ordinal);
}
