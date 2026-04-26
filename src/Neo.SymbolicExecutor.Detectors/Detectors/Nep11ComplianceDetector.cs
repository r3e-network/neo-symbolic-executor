using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-11 NFT ABI compliance — new detector per audit coverage gap #1 (zero coverage despite
/// identical structural risk to NEP-17).
///
/// NEP-11 required methods: symbol, decimals, totalSupply, balanceOf, tokensOf, transfer.
/// Divisible NFTs additionally provide: ownerOf, tokens, properties.
/// Events: Transfer(from: Hash160, to: Hash160, amount: Integer, tokenId: ByteString).
/// </summary>
public sealed class Nep11ComplianceDetector : BaseDetector
{
    public override string Name => "nep11_compliance";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.95;

    private static readonly string[] RequiredMethods = { "symbol", "decimals", "totalSupply", "balanceOf", "tokensOf", "transfer" };
    private static readonly string[] RequiredViewMethods = { "symbol", "decimals", "totalSupply", "balanceOf", "tokensOf" };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var m = context.Manifest;
        if (m is null) yield break;
        if (!m.SupportedStandards.Any(s => string.Equals(s, "NEP-11", System.StringComparison.OrdinalIgnoreCase))) yield break;

        foreach (var name in RequiredMethods)
        {
            if (m.FindMethod(name) is null)
            {
                yield return MakeFinding(
                    title: $"NEP-11 missing required method: {name}",
                    description: $"Contract declares NEP-11 but does not define a `{name}` method.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep11", "missing-method" });
            }
        }
        foreach (var name in RequiredViewMethods)
        {
            var method = m.FindMethod(name);
            if (method is { Safe: false })
            {
                yield return MakeFinding(
                    title: $"NEP-11 view method `{name}` should be safe=true",
                    description: $"Method `{name}` must declare safe=true so wallets can call it without approval prompts.",
                    offset: method.Offset,
                    severity: Severity.Medium,
                    state: null,
                    tags: new[] { "nep11", "safe-flag" });
            }
        }

        var transferEvent = m.Abi.Events.FirstOrDefault(e => e.Name == "Transfer");
        if (transferEvent is null)
        {
            yield return MakeFinding(
                title: "NEP-11 missing Transfer event",
                description: "NEP-11 contract must declare the Transfer event for explorer/wallet compatibility.",
                offset: 0,
                severity: Severity.High,
                state: null,
                tags: new[] { "nep11", "missing-event" });
        }
        else
        {
            var p = transferEvent.Parameters;
            bool ok = p.Count >= 4
                && string.Equals(p[0].Type, "Hash160", System.StringComparison.OrdinalIgnoreCase)
                && string.Equals(p[1].Type, "Hash160", System.StringComparison.OrdinalIgnoreCase)
                && string.Equals(p[2].Type, "Integer", System.StringComparison.OrdinalIgnoreCase)
                && (string.Equals(p[3].Type, "ByteString", System.StringComparison.OrdinalIgnoreCase)
                    || string.Equals(p[3].Type, "ByteArray", System.StringComparison.OrdinalIgnoreCase));
            if (!ok)
            {
                yield return MakeFinding(
                    title: "NEP-11 Transfer event has wrong parameter shape",
                    description: "Transfer event must declare (Hash160 from, Hash160 to, Integer amount, ByteString tokenId).",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep11", "event-shape" });
            }
        }
    }
}
