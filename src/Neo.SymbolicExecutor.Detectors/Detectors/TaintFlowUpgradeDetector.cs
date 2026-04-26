using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// New detector per audit coverage gap #5: ContractManagement.Update receiving attacker-supplied
/// NEF and/or manifest arguments.
///
/// Heuristic: when a Contract.Update / native ContractManagement.update call is reached AND
/// the call's arguments include a SymbolicValue tainted with `arg<i>` (a parameter to the
/// analyzed entry method), the upgrade payload is attacker-controlled. Critical regardless of
/// auth: even with auth, if the auth principal is the attacker, they can replace the contract
/// with arbitrary code.
/// </summary>
public sealed class TaintFlowUpgradeDetector : BaseDetector
{
    public override string Name => "taint_flow_upgrade";
    public override Severity DefaultSeverity => Severity.Critical;
    public override double DefaultConfidence => 0.85;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            foreach (var call in state.Telemetry.ExternalCalls)
            {
                bool isUpdate = call.Method.Equals("update", System.StringComparison.OrdinalIgnoreCase);
                if (!isUpdate) continue;
                bool tainted = call.Args.Any(a => a.Taints.Any(t => t.StartsWith("arg", System.StringComparison.Ordinal)));
                if (!tainted) continue;

                yield return MakeFinding(
                    title: "ContractManagement.Update payload flows from caller-supplied input",
                    description: $"update() invocation at 0x{call.Offset:X4} is reached with a NEF/manifest "
                               + "argument that depends on a method parameter. A malicious caller (or compromised "
                               + "admin key) can replace the contract with arbitrary code.",
                    offset: call.Offset,
                    severity: Severity.Critical,
                    state: state,
                    tags: new[] { "taint-flow", "upgradeability", "untrusted-input" });
            }
        }
    }
}
