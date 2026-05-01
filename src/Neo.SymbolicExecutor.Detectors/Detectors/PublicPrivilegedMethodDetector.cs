using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// DApp privileged-method surface detector. Generic access-control findings are useful, but
/// manifest-exposed methods named mint/burn/withdraw/upgrade/etc. need a domain-specific signal
/// because these functions are common attacker entrypoints in DApps, DeFi vaults, and NFT contracts.
/// </summary>
public sealed class PublicPrivilegedMethodDetector : BaseDetector
{
    public override string Name => "public_privileged_method";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.75;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;

        foreach (var state in context.States)
        {
            var method = ProtocolRiskHelpers.MethodForState(context, state);
            if (method is null || method.Safe) continue;
            if (!ProtocolRiskHelpers.IsPrivilegedMethodName(method.Name)) continue;

            var sensitiveOps = ProtocolRiskHelpers.SensitiveOps(state).OrderBy(op => op.Offset).ToList();
            if (sensitiveOps.Count == 0) continue;

            var firstSensitive = sensitiveOps[0];
            if (ProtocolRiskHelpers.HasAuthBefore(state, firstSensitive.Offset)) continue;

            yield return MakeFinding(
                title: $"Public privileged method `{method.Name}` reaches sensitive operation without early auth",
                description: $"Manifest-exposed method `{method.Name}` reaches {firstSensitive.Kind} at "
                           + $"0x{firstSensitive.Offset:X4} before an enforced witness, caller-hash, or signature check. "
                           + "Privileged DApp entrypoints such as mint, burn, withdraw, sweep, oracle, fee, and upgrade "
                           + "methods should authorize before touching state or calling out.",
                offset: firstSensitive.Offset,
                severity: Severity.High,
                state: state,
                tags: new[] { "dapp", "privileged-method", "missing-auth" });
        }
    }
}
