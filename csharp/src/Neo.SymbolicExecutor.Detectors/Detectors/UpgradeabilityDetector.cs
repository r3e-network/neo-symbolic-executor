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

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            var sensitive = state.Telemetry.ExternalCalls
                .Where(c => SensitiveMethods.Contains(c.Method)
                            || c.Method.Contains("update", StringComparison.OrdinalIgnoreCase)
                            || c.Method.Contains("destroy", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (sensitive.Count == 0) continue;

            bool authEnforced = state.Telemetry.WitnessChecksEnforced.Count > 0
                                 || state.Telemetry.SignatureChecks.Count > 0;

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
