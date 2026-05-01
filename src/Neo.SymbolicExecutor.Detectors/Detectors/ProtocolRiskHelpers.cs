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
            SwapNames.Concat(DefiStateHints).Concat(OracleHints)) == true;
    }

    public static bool HasSourceSlippageSignal(AnalysisContext context, ExecutionState state)
    {
        var method = MethodForState(context, state);
        return context.SourceHints?.MethodContainsAny(method?.Name, SlippageHints, includeStringLiterals: false) == true;
    }

    public static bool HasSourceFreshnessSignal(AnalysisContext context, ExecutionState state)
    {
        var method = MethodForState(context, state);
        return context.SourceHints?.MethodContainsAny(
            method?.Name,
            FreshnessHints.Concat(OracleHints),
            includeStringLiterals: false) == true;
    }

    public static bool HasNftSourceSignal(AnalysisContext context, ExecutionState state)
    {
        var method = MethodForState(context, state);
        return context.SourceHints?.MethodContainsAny(method?.Name, NftKeyHints) == true;
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
