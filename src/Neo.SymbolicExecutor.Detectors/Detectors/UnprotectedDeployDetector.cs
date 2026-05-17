using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects a Neo <c>_deploy(data, update)</c> method that does not differentiate between the
/// initial deployment (<c>update == false</c>) and a subsequent upgrade (<c>update == true</c>).
/// The Neo runtime invokes <c>_deploy</c> from both <c>ContractManagement.deploy</c> and
/// <c>ContractManagement.update</c>; a body that ignores the <c>update</c> flag will re-run
/// initialization (e.g. resetting an owner slot, re-minting an initial supply) on every upgrade,
/// which lets an attacker who can trigger an upgrade hijack admin state.
///
/// Detection: the analyzer enters <c>_deploy</c> via the per-method entrypoint, so the
/// <c>update</c> argument is pushed as a symbol named <c>arg_update</c> (manifest-named) or
/// <c>arg1</c> (positional). A protected <c>_deploy</c> conditions sensitive operations on that
/// symbol via a branch — i.e. the symbol appears in the state's path conditions. A state that
/// reaches a storage write while the <c>update</c> symbol never participated in any branch
/// indicates an unprotected init path.
/// </summary>
public sealed class UnprotectedDeployDetector : BaseDetector
{
    public override string Name => "unprotected_deploy";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.75;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;
        var deploy = context.Manifest.FindMethod("_deploy");
        if (deploy is null) yield break;

        // Identify the symbol name used for the `update` (second) parameter. NEP-compliant
        // _deploy(data, update) has update at index 1.
        string updateSym = ParameterSymbolName(deploy.Parameters, index: 1, defaultIfMissing: "arg1");

        foreach (var state in context.States)
        {
            if (state.Path.Count == 0 || state.Path[0] != deploy.Offset) continue;
            // Empty path-conditions means no branching ever occurred — the state walked _deploy
            // straight through, never gating on `update`.
            bool sawUpdateInBranch = state.PathConditions
                .SelectMany(c => c.FreeSymbols())
                .Any(n => n == updateSym);
            if (sawUpdateInBranch) continue;

            // Only fire when there's an actual sensitive op to be gated. A _deploy that does
            // nothing on initial setup is not interesting (and would be unusual).
            var sensitive = ProtocolRiskHelpers.SensitiveOps(state)
                .OrderBy(op => op.Offset)
                .FirstOrDefault();
            if (sensitive == default) continue;

            yield return MakeFinding(
                title: "_deploy does not differentiate initial deploy from upgrade",
                description: $"`_deploy` reaches {sensitive.Kind} at 0x{sensitive.Offset:X4} without branching on the "
                           + "`update` argument. Both first-time deploy and every subsequent ContractManagement.Update "
                           + "will re-run this initialization, allowing an attacker who can trigger an upgrade to "
                           + "reset admin state or re-mint balances. Guard initialization with `if (!update) { ... }`.",
                offset: sensitive.Offset,
                severity: Severity.High,
                state: state,
                tags: new[] { "deploy", "reinitialization", "upgrade-hijack" });
        }
    }

    private static string ParameterSymbolName(
        IReadOnlyList<Nef.ContractParameterDefinition> parameters,
        int index,
        string defaultIfMissing)
    {
        if (index < 0 || index >= parameters.Count) return defaultIfMissing;
        var p = parameters[index];
        return string.IsNullOrEmpty(p.Name) ? $"arg{index}" : $"arg_{p.Name}";
    }
}
