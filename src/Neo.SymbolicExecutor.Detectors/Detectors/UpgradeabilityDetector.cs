using System;
using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Flags ContractManagement.Update / Destroy invocations and their authorization posture.
/// Severity ladders to CRITICAL when the call lacks any authorization check on its path.
///
/// Audit C5 / detector audit #5: cover both legacy upgrade syscalls and native CallNative
/// dispatches. Engine emits both as <see cref="ExternalCall"/> entries; we filter by method.
/// </summary>
public sealed class UpgradeabilityDetector : BaseDetector
{
    public override string Name => "upgradeability";
    public override Severity DefaultSeverity => Severity.Critical;
    public override double DefaultConfidence => 0.85;

    private static readonly HashSet<string> SensitiveMethods =
        new(StringComparer.OrdinalIgnoreCase) { "update", "destroy" };

    private static bool IsContractManagement(NativeContractRegistry natives, byte[] hash) =>
        // Registry's ByHashBytes enforces the 20-byte width that rejects malformed PUSHDATAs
        // (see audit comment on NativeContractRegistry.ByHashBytes).
        natives.ByHashBytes(hash)?.Name.Equals("ContractManagement", StringComparison.OrdinalIgnoreCase) ?? false;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var natives = context.Natives;
        foreach (var state in context.States)
        {
            // Audit C# #12 fix: was matching 'update'/'destroy' as substrings, which fired on
            // userland methods like updateBalance / propertyUpdater. Tighten to: exact name AND
            // (a) target is concrete ContractManagement, OR (b) no concrete target (raw `update`/
            // `destroy` invocation, which only resolves to ContractManagement at runtime). This
            // eliminates the false-positive class while keeping coverage of native-call dispatch.
            var sensitive = state.Telemetry.ExternalCalls
                .Where(c => SensitiveMethods.Contains(c.Method)
                            && (c.TargetHash is null
                                || (c.TargetHash.AsConcreteBytes() is byte[] hb
                                    && IsContractManagement(natives, hb))))
                .ToList();
            if (sensitive.Count == 0) continue;

            // Precision fix: the prior predicate omitted CallerHashChecks, so a contract that
            // gates `update` with `GetCallingScriptHash() == ADMIN` was flagged Critical
            // instead of High. Caller-hash auth is a legitimate Neo upgrade-gating pattern.
            bool authEnforced = ProtocolRiskHelpers.HasAnyEnforcedAuth(state);

            foreach (var call in sensitive)
            {
                Severity severity = authEnforced ? Severity.High : Severity.Critical;
                yield return MakeFinding(
                    title: $"Sensitive ContractManagement.{call.Method} reachable",
                    description: $"Path reaches {call.Method} at 0x{call.Offset:X4}. "
                               + (authEnforced
                                  ? "Authorization is enforced on this path; verify the gating principal cannot be impersonated."
                                  : "No witness/signature enforcement on this path — the upgrade/destroy can be triggered by any caller."),
                    offset: call.Offset,
                    severity: severity,
                    state: state,
                    tags: new[] { call.Method.ToLowerInvariant(), "upgradeability" });
            }
        }
    }
}
