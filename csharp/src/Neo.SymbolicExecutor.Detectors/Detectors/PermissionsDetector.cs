using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Audits the manifest's permissions, trusts, and groups for over-broad grants.
///
/// Audit precision lessons:
/// - Distinguish full wildcard (`"*"`) from partial wildcards (per-field-with-method-wildcard).
/// - Cover <c>trusts</c> (audit detector audit #9 finding: parsed but never checked).
/// - Cover <c>groups</c> with empty / wildcard pubkey.
/// </summary>
public sealed class PermissionsDetector : BaseDetector
{
    public override string Name => "permissions";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.95;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var manifest = context.Manifest;
        if (manifest is null) yield break;

        if (manifest.Permissions.Count == 0)
        {
            // No permissions at all = empty allowlist, which is actually safe (callee restriction).
        }
        else
        {
            foreach (var perm in manifest.Permissions)
            {
                if (perm.Contract == "*" && perm.Methods.IsWildcard)
                {
                    yield return MakeFinding(
                        title: "Manifest grants permission to call any contract / method",
                        description: "manifest.permissions includes a fully-wildcarded entry (contract=\"*\" methods=\"*\"). "
                                   + "The contract can call any other contract with any method.",
                        offset: 0,
                        severity: Severity.High,
                        state: null,
                        tags: new[] { "permissions-wildcard" });
                }
                else if (perm.Contract == "*" || perm.Methods.IsWildcard)
                {
                    yield return MakeFinding(
                        title: "Manifest permission contains a partial wildcard",
                        description: $"Permission entry contract={perm.Contract} methods={(perm.Methods.IsWildcard ? "*" : string.Join(",", perm.Methods.Items))} "
                                   + "uses a wildcard component. Tighten to specific contracts/methods where possible.",
                        offset: 0,
                        severity: Severity.Medium,
                        state: null,
                        tags: new[] { "permissions-partial-wildcard" });
                }
            }
        }

        if (manifest.TrustsWildcard)
        {
            yield return MakeFinding(
                title: "Manifest trusts all contracts",
                description: "manifest.trusts is \"*\". Any contract can be called from this contract's UI flows without consent prompts.",
                offset: 0,
                severity: Severity.Medium,
                state: null,
                tags: new[] { "trusts-wildcard" });
        }

        // Groups with empty / suspicious pubkeys.
        foreach (var g in manifest.Groups)
        {
            if (string.IsNullOrEmpty(g.PubKey) || g.PubKey == "*")
            {
                yield return MakeFinding(
                    title: "Contract group has empty/wildcard public key",
                    description: "A manifest group entry has missing or wildcard pubkey. Group memberships should be cryptographically pinned.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "group-misconfigured" });
            }
        }
    }
}
