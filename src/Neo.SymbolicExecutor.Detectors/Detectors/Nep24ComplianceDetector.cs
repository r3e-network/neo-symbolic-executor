using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-24 NFT royalty ABI compliance:
///   method: royaltyInfo(ByteString-compatible tokenId, Hash160 royaltyToken, Integer salePrice): Array safe=true
///   event:  RoyaltiesTransferred(Hash160 royaltyToken, Hash160 royaltyRecipient, Hash160 buyer,
///                                ByteString-compatible tokenId, Integer amount)
///   base:   NEP-24 is a royalty extension layered on NEP-11; the verifier requires a NEP-24
///           manifest to also declare NEP-11 and expose the base NFT ABI (Review fix #58).
///
/// Only fires when the manifest declares NEP-24 in supportedstandards.
/// </summary>
public sealed class Nep24ComplianceDetector : BaseDetector
{
    public override string Name => "nep24_compliance";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.95;

    // Base NEP-11 NFT ABI that NEP-24 royalty manifests build on. Matches the required-method set
    // the verifier's HasCompleteNep11AbiShape enforces.
    private static readonly string[] BaseNep11Methods =
    {
        "symbol", "decimals", "totalSupply", "balanceOf", "ownerOf", "tokensOf", "transfer",
    };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var manifest = context.Manifest;
        if (manifest is null) yield break;
        if (!manifest.DeclaresStandard("NEP-24")) yield break;

        // Review fix (#58): a NEP-24 royalty manifest must also declare NEP-11 and expose the base
        // NFT ABI, matching the verifier. Report the missing base layer so analyze parity with the
        // verifier's NEP-24 obligation is preserved.
        if (!manifest.DeclaresStandard("NEP-11"))
        {
            yield return MakeFinding(
                title: "NEP-24 manifest does not declare the required NEP-11 base standard",
                description: "Contract declares NEP-24 (NFT royalties) but does not declare NEP-11 in supportedstandards. "
                           + "NEP-24 is a royalty extension on top of the NEP-11 NFT standard; marketplaces expect the full "
                           + "NEP-11 base ABI to be present and declared.",
                offset: 0,
                severity: Severity.Medium,
                state: null,
                tags: new[] { "nep24", "missing-base-standard", "nep11" });
        }

        var missingBase = BaseNep11Methods
            .Where(name => manifest.FindMethod(name) is null)
            .ToList();
        if (missingBase.Count > 0)
        {
            yield return MakeFinding(
                title: "NEP-24 manifest is missing required NEP-11 base NFT ABI methods",
                description: "Contract declares NEP-24 but does not expose the complete NEP-11 base NFT ABI; missing method(s): "
                           + string.Join(", ", missingBase) + ". The royalty layer is only meaningful on a complete NEP-11 NFT.",
                offset: 0,
                severity: Severity.Medium,
                state: null,
                tags: new[] { "nep24", "missing-base-abi", "nep11" });
        }

        var royaltyInfo = FindMethod(manifest, "royaltyInfo", IsRoyaltyInfoShape);
        if (royaltyInfo is null)
        {
            var firstRoyaltyInfo = FindMethod(manifest, "royaltyInfo");
            if (firstRoyaltyInfo is null)
            {
                yield return MakeFinding(
                    title: "NEP-24 missing required method: royaltyInfo",
                    description: "Contract declares NEP-24 but does not define `royaltyInfo(ByteString-compatible tokenId, Hash160 royaltyToken, Integer salePrice): Array`.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep24", "missing-method" });
            }
            else
            {
                if (MethodsNamed(manifest, "royaltyInfo").Any(method => !method.Safe))
                {
                    yield return MakeFinding(
                        title: "NEP-24 method `royaltyInfo` should be safe=true",
                        description: "`royaltyInfo` must declare safe=true so marketplaces can query royalty terms without approval prompts.",
                        offset: firstRoyaltyInfo.Offset,
                        severity: Severity.Medium,
                        state: null,
                        tags: new[] { "nep24", "safe-flag" });
                }

                yield return MakeFinding(
                    title: "NEP-24 royaltyInfo method has wrong parameter or return shape",
                    description: "royaltyInfo must declare (ByteString-compatible tokenId, Hash160 royaltyToken, Integer salePrice): Array safe=true.",
                    offset: firstRoyaltyInfo.Offset,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep24", "method-shape" });
            }
        }

        var royaltiesTransferred = manifest.Abi.Events.FirstOrDefault(e => e.Name == "RoyaltiesTransferred");
        if (royaltiesTransferred is null)
        {
            yield return MakeFinding(
                title: "NEP-24 missing RoyaltiesTransferred event",
                description: "Contract declares NEP-24 but the RoyaltiesTransferred event is not declared in the manifest.",
                offset: 0,
                severity: Severity.High,
                state: null,
                tags: new[] { "nep24", "missing-event" });
        }
        else if (!IsRoyaltiesTransferredShape(royaltiesTransferred))
        {
            yield return MakeFinding(
                title: "NEP-24 RoyaltiesTransferred event has wrong parameter shape",
                description: "RoyaltiesTransferred must declare (Hash160 royaltyToken, Hash160 royaltyRecipient, Hash160 buyer, ByteString-compatible tokenId, Integer amount).",
                offset: 0,
                severity: Severity.High,
                state: null,
                tags: new[] { "nep24", "event-shape" });
        }
    }

    private static bool IsRoyaltyInfoShape(Nef.ContractMethodDescriptor method)
    {
        var parameters = method.Parameters;
        return parameters.Count == 3
            && method.Safe
            && HasParameter(parameters, 0, "tokenId", IsByteString)
            && HasParameter(parameters, 1, "royaltyToken", type => IsType(type, "Hash160"))
            && HasParameter(parameters, 2, "salePrice", type => IsType(type, "Integer"))
            && IsType(method.ReturnType, "Array");
    }

    private static bool IsRoyaltiesTransferredShape(Nef.ContractEventDescriptor evt)
    {
        var parameters = evt.Parameters;
        return parameters.Count == 5
            && HasParameter(parameters, 0, "royaltyToken", type => IsType(type, "Hash160"))
            && HasParameter(parameters, 1, "royaltyRecipient", type => IsType(type, "Hash160"))
            && HasParameter(parameters, 2, "buyer", type => IsType(type, "Hash160"))
            && HasParameter(parameters, 3, "tokenId", IsByteString)
            && HasParameter(parameters, 4, "amount", type => IsType(type, "Integer"));
    }

    private static bool IsByteString(string type) =>
        IsType(type, "ByteString") || IsType(type, "ByteArray");

    // Round-2 fix (#20): validate parameter TYPE and arity only — NOT the author's parameter
    // identifier. NEP-24 fixes the method name, parameter types, arity, return type, and the Safe
    // flag, but not the spelling of parameter names; comparing parameters[index].Name produced false
    // positives on spec-compliant contracts that renamed a parameter. The `name` argument is retained
    // for call-site documentation of the canonical NEP name.
    private static bool HasParameter(
        IReadOnlyList<Nef.ContractParameterDefinition> parameters,
        int index,
        string name,
        System.Func<string, bool> typeMatches) =>
        parameters.Count > index
        && typeMatches(parameters[index].Type);

    // Review fix (#74): shared Nef.AbiTypeMatching source of truth (was a per-detector copy).
    private static bool IsType(string actual, string expected) =>
        Nef.AbiTypeMatching.IsType(actual, expected);

    private static Nef.ContractMethodDescriptor? FindMethod(
        Nef.ContractManifest manifest,
        string name,
        System.Func<Nef.ContractMethodDescriptor, bool>? predicate = null) =>
        MethodsNamed(manifest, name).FirstOrDefault(method => predicate?.Invoke(method) ?? true);

    private static IEnumerable<Nef.ContractMethodDescriptor> MethodsNamed(
        Nef.ContractManifest manifest,
        string name) =>
        manifest.Abi.Methods.Where(method => string.Equals(method.Name, name, System.StringComparison.Ordinal));
}
