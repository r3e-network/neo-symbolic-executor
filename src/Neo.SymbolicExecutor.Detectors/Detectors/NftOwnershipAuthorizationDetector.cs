using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-11 ownership/approval authorization detector. Generic missing-auth findings are useful,
/// but NFT transfer/burn/approval paths deserve a domain-specific signal because an ownership
/// write can directly move or destroy a unique asset.
/// </summary>
public sealed class NftOwnershipAuthorizationDetector : BaseDetector
{
    public override string Name => "nft_ownership_authorization";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.72;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;
        bool declaresNep11 = context.Manifest.SupportedStandards
            .Any(s => string.Equals(s, "NEP-11", System.StringComparison.OrdinalIgnoreCase));
        if (!declaresNep11) yield break;

        foreach (var state in context.States)
        {
            var method = ProtocolRiskHelpers.MethodForState(context, state);
            bool ownershipMethod = method is not null
                && (method.Name.Equals("transfer", System.StringComparison.OrdinalIgnoreCase)
                    || method.Name.Equals("burn", System.StringComparison.OrdinalIgnoreCase)
                    || method.Name.Contains("approve", System.StringComparison.OrdinalIgnoreCase));

            var firstOwnershipWrite = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsNftOwnershipWrite)
                .OrderBy(op => op.Offset)
                .FirstOrDefault();
            if (firstOwnershipWrite is not { } ownershipWrite) continue;
            if (!ownershipMethod && method is not null && !ProtocolRiskHelpers.IsPrivilegedMethodName(method.Name)) continue;
            if (ProtocolRiskHelpers.HasAuthBefore(state, ownershipWrite.Offset)) continue;

            yield return MakeFinding(
                title: "NEP-11 ownership or approval write lacks early authorization",
                description: $"NEP-11 path writes an ownership/approval-like storage key at "
                           + $"0x{ownershipWrite.Offset:X4} before an enforced witness, caller-hash, or signature check. "
                           + "NFT transfer, burn, and approval flows should prove owner/operator authority before changing "
                           + "token ownership or approvals.",
                offset: ownershipWrite.Offset,
                severity: Severity.High,
                state: state,
                tags: new[] { "nft", "nep11", "ownership-auth" });
        }
    }
}
