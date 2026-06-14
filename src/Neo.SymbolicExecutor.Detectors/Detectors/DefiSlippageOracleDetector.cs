using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// DeFi slippage/oracle heuristic. Neo contracts do not expose high-level source semantics here,
/// so this detector looks for swap-like manifest methods that call external token/router contracts
/// and mutate pool/vault state without observable min-out/slippage and freshness signals.
/// </summary>
public sealed class DefiSlippageOracleDetector : BaseDetector
{
    public override string Name => "defi_slippage_oracle";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.62;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            var method = ProtocolRiskHelpers.MethodForState(context, state);
            bool swapLike = method is not null && ProtocolRiskHelpers.IsSwapLikeMethodName(method.Name);
            bool defiStateSignal = ProtocolRiskHelpers.HasDefiStateSignal(state);
            bool sourceDefiSignal = ProtocolRiskHelpers.HasDefiSourceSignal(context, state);
            if (!swapLike && !defiStateSignal && !sourceDefiSignal) continue;

            bool concreteTransfer = state.Telemetry.ExternalCalls.Any(call =>
                !call.ModeledSelfCall && ProtocolRiskHelpers.IsTokenTransferCall(call));
            // Review fix (#59): also recognize transfer-named calls with a symbolic/dynamic target
            // (router-style) as a token-transfer signal so the slippage/freshness obligation still
            // applies. Combined here with the swap/defi signal already required above; surfaced at
            // reduced confidence because a dynamic target is a weaker indicator than a concrete hash.
            bool dynamicTransfer = !concreteTransfer && state.Telemetry.ExternalCalls.Any(call =>
                !call.ModeledSelfCall && ProtocolRiskHelpers.IsDynamicTokenTransferCall(call));
            bool externalTransfer = concreteTransfer || dynamicTransfer;
            bool writesState = state.Telemetry.StorageOps.Any(ProtocolRiskHelpers.IsStateWrite);
            if (!externalTransfer || !writesState) continue;

            bool hasSlippageSignal = ProtocolRiskHelpers.HasSlippageSignal(state)
                                     || ProtocolRiskHelpers.HasSourceSlippageSignal(context, state);
            bool hasFreshnessSignal = ProtocolRiskHelpers.HasOracleFreshnessSignal(state)
                                      || ProtocolRiskHelpers.HasSourceFreshnessSignal(context, state);
            if (hasSlippageSignal && hasFreshnessSignal) continue;

            int offset = state.Telemetry.ExternalCalls
                .Where(call => !call.ModeledSelfCall)
                .Where(call => ProtocolRiskHelpers.IsTokenTransferCall(call)
                            || ProtocolRiskHelpers.IsDynamicTokenTransferCall(call))
                .Select(c => c.Offset)
                .DefaultIfEmpty(0)
                .Min();

            var missing = new List<string>();
            if (!hasSlippageSignal) missing.Add("min-out/slippage guard");
            if (!hasFreshnessSignal) missing.Add("oracle freshness/deadline signal");

            string methodName = method?.Name ?? "protocol path";
            var tags = new List<string> { "defi", "slippage", "oracle-freshness" };
            if (defiStateSignal) tags.Add("defi-state");
            if (ProtocolRiskHelpers.HasDynamicStateWrite(state)) tags.Add("dynamic-storage-key");
            if (sourceDefiSignal) tags.Add("source-hint");
            if (dynamicTransfer) tags.Add("dynamic-transfer-target");

            yield return MakeFinding(
                title: $"DeFi-like method `{methodName}` lacks price-safety signals",
                description: $"DeFi-like method `{methodName}` performs token transfer(s) and mutates state, "
                           + $"but this path lacks {string.Join(" and ", missing)}. DeFi flows should bound "
                           + "received amount and avoid stale or manipulable price inputs before updating reserves, "
                           + "vault shares, or balances."
                           + (dynamicTransfer
                                ? " The token transfer targets a dynamic/symbolic address (router-style), so this is "
                                  + "surfaced at reduced confidence."
                                : ""),
                offset: offset,
                severity: Severity.High,
                state: state,
                tags: tags,
                // Review fix (#59): dynamic-target transfers are a weaker signal than a concrete
                // token hash, so reduce confidence when only the dynamic path matched.
                confidenceOverride: dynamicTransfer ? DefaultConfidence * 0.75 : null);
        }
    }
}
