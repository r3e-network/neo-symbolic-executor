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
        if (!context.Manifest.DeclaresStandard("NEP-11")) yield break;

        foreach (var state in context.States)
        {
            bool sourceOwnershipSignal = ProtocolRiskHelpers.HasNftSourceSignal(context, state);

            var firstOwnershipWrite = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsNftOwnershipWrite)
                .OrderBy(op => op.Offset)
                .FirstOrDefault();
            var ownershipWrite = firstOwnershipWrite
                ?? state.Telemetry.StorageOps
                    .Where(ProtocolRiskHelpers.IsDynamicStateWrite)
                    .OrderBy(op => op.Offset)
                    .FirstOrDefault()
                ?? state.Telemetry.StorageOps
                    .Where(op => sourceOwnershipSignal && ProtocolRiskHelpers.IsStateWrite(op))
                    .OrderBy(op => op.Offset)
                    .FirstOrDefault();
            if (ownershipWrite is null) continue;
            if (ProtocolRiskHelpers.HasAuthBefore(state, ownershipWrite.Offset)) continue;

            bool dynamicKey = ProtocolRiskHelpers.IsDynamicStateWrite(ownershipWrite);
            var tags = new List<string> { "nft", "nep11", "ownership-auth" };
            if (dynamicKey) tags.Add("dynamic-storage-key");
            if (sourceOwnershipSignal) tags.Add("source-hint");

            yield return MakeFinding(
                title: "NEP-11 ownership or approval write lacks early authorization",
                description: $"NEP-11 path writes an ownership/approval-like, source-indicated, or dynamic storage key at "
                           + $"0x{ownershipWrite.Offset:X4} before an enforced witness, caller-hash, or signature check. "
                           + "NFT transfer, burn, and approval flows should prove owner/operator authority before changing "
                           + "token ownership or approvals.",
                offset: ownershipWrite.Offset,
                severity: Severity.High,
                state: state,
                tags: tags);
        }
    }
}
