using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-17 fungible-token ABI compliance:
///   methods: symbol, decimals, totalSupply, balanceOf, transfer
///   events:  Transfer(from: Hash160, to: Hash160, amount: Integer)
///   safe flag: balanceOf, decimals, symbol, totalSupply must be safe=true
///
/// Only fires when the manifest declares NEP-17 in supportedstandards.
/// </summary>
public sealed class Nep17ComplianceDetector : BaseDetector
{
    public override string Name => "nep17_compliance";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.95;

    private static readonly string[] RequiredMethods = { "symbol", "decimals", "totalSupply", "balanceOf", "transfer" };
    private static readonly string[] RequiredViewMethods = { "symbol", "decimals", "totalSupply", "balanceOf" };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var m = context.Manifest;
        if (m is null) yield break;
        if (!m.DeclaresStandard("NEP-17")) yield break;

        foreach (var name in RequiredMethods)
        {
            if (m.FindMethod(name) is null)
            {
                yield return MakeFinding(
                    title: $"NEP-17 missing required method: {name}",
                    description: $"Contract declares NEP-17 but does not define a `{name}` method.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep17", "missing-method" });
            }
        }
        foreach (var name in RequiredViewMethods)
        {
            var method = m.FindMethod(name);
            if (method is { Safe: false })
            {
                yield return MakeFinding(
                    title: $"NEP-17 view method `{name}` should be safe=true",
                    description: $"Method `{name}` must declare safe=true so wallets can call it without approval prompts.",
                    offset: method.Offset,
                    severity: Severity.Medium,
                    state: null,
                    tags: new[] { "nep17", "safe-flag" });
            }
        }

        // Transfer event presence + parameter shape.
        var transferEvent = m.Abi.Events.FirstOrDefault(e => e.Name == "Transfer");
        if (transferEvent is null)
        {
            yield return MakeFinding(
                title: "NEP-17 missing Transfer event",
                description: "Contract declares NEP-17 but the Transfer event is not declared in the manifest.",
                offset: 0,
                severity: Severity.High,
                state: null,
                tags: new[] { "nep17", "missing-event" });
        }
        else
        {
            var p = transferEvent.Parameters;
            bool ok = p.Count == 3
                && string.Equals(p[0].Type, "Hash160", System.StringComparison.OrdinalIgnoreCase)
                && string.Equals(p[1].Type, "Hash160", System.StringComparison.OrdinalIgnoreCase)
                && string.Equals(p[2].Type, "Integer", System.StringComparison.OrdinalIgnoreCase);
            if (!ok)
            {
                yield return MakeFinding(
                    title: "NEP-17 Transfer event has wrong parameter shape",
                    description: "Transfer event must declare exactly 3 parameters: Hash160 from, Hash160 to, Integer amount.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep17", "event-shape" });
            }
        }

        // transfer signature shape.
        var transfer = m.FindMethod("transfer");
        if (transfer is not null)
        {
            var p = transfer.Parameters;
            bool ok = p.Count == 4
                && string.Equals(p[0].Type, "Hash160", System.StringComparison.OrdinalIgnoreCase)
                && string.Equals(p[1].Type, "Hash160", System.StringComparison.OrdinalIgnoreCase)
                && string.Equals(p[2].Type, "Integer", System.StringComparison.OrdinalIgnoreCase);
            if (!ok)
            {
                yield return MakeFinding(
                    title: "NEP-17 transfer parameter shape is wrong",
                    description: "transfer must declare (Hash160 from, Hash160 to, Integer amount, Any data).",
                    offset: transfer.Offset,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep17", "method-shape" });
            }
        }
    }
}
