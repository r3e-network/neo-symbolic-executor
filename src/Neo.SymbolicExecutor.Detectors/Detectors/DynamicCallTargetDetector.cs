using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// External calls where the target hash and/or method selector come from runtime-computed values
/// (storage reads, syscalls, attacker-controlled args). These represent dispatch-time injection
/// risk: a malicious caller can redirect the call to an arbitrary contract.
///
/// Severity ladder:
/// - CRITICAL when both target hash AND method are dynamic.
/// - HIGH when target hash is dynamic but method is concrete.
/// - MEDIUM when method is dynamic but target hash is concrete (less severe — the contract is at
///   least pinned).
/// </summary>
public sealed class DynamicCallTargetDetector : BaseDetector
{
    public override string Name => "dynamic_call_target";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.9;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            foreach (var call in state.Telemetry.ExternalCalls)
            {
                if (call.ModeledSelfCall) continue;
                if (!call.TargetHashDynamic && !call.MethodDynamic) continue;

                Severity sev = (call.TargetHashDynamic, call.MethodDynamic) switch
                {
                    (true, true) => Severity.Critical,
                    (true, false) => Severity.High,
                    (false, true) => Severity.Medium,
                    _ => Severity.Medium,
                };

                string title = (call.TargetHashDynamic, call.MethodDynamic) switch
                {
                    (true, true) => "External call to fully dynamic target",
                    (true, false) => "External call hash is dynamic",
                    (false, true) => "External call method selector is dynamic",
                    _ => "Dynamic external call",
                };

                yield return MakeFinding(
                    title: title,
                    description: $"Contract.Call at 0x{call.Offset:X4}: " +
                                 $"target_hash={(call.TargetHashDynamic ? "DYNAMIC" : "concrete")}, " +
                                 $"method={(call.MethodDynamic ? "DYNAMIC" : call.Method)}.",
                    offset: call.Offset,
                    severity: sev,
                    state: state,
                    tags: new[] { "dynamic-dispatch" });
            }
        }
    }
}
