using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// External calls invoked with broad or runtime-selected call flags.
///
/// Audit precision fix: Don't only catch the literal `0x0F` (CallFlags.All). Use bit-count
/// thresholds so combinations like 0x05 (WriteStates|AllowCall) and 0x07 (States|AllowCall|
/// AllowNotify) also surface.
/// </summary>
public sealed class DangerousCallFlagsDetector : BaseDetector
{
    public override string Name => "dangerous_call_flags";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.85;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            foreach (var call in state.Telemetry.ExternalCalls)
            {
                if (call.CallFlagsDynamic)
                {
                    yield return MakeFinding(
                        title: "Call flags determined at runtime",
                        description: $"Contract.Call at 0x{call.Offset:X4} uses runtime-computed call flags. "
                                   + "Attacker-controlled flag selection can grant unintended capabilities to the callee.",
                        offset: call.Offset,
                        severity: Severity.Medium,
                        state: state,
                        tags: new[] { "dynamic-call-flags" });
                    continue;
                }
                if (call.CallFlags == CallFlags.All)
                {
                    yield return MakeFinding(
                        title: "External call grants CallFlags.All",
                        description: $"Contract.Call at 0x{call.Offset:X4} passes CallFlags.All (0x0F). "
                                   + "The callee receives full write/notify/call/states permission.",
                        offset: call.Offset,
                        severity: Severity.High,
                        state: state,
                        tags: new[] { "callflags-all" });
                }
                else if (CallFlags.IsBroad(call.CallFlags))
                {
                    int bitCount = System.Numerics.BitOperations.PopCount((uint)(call.CallFlags & CallFlags.All));
                    yield return MakeFinding(
                        title: "External call grants over-broad call flags",
                        description: $"Contract.Call at 0x{call.Offset:X4} grants {bitCount} call-flag bits "
                                   + $"(0x{call.CallFlags:X2}). Tighten to the minimum capabilities needed.",
                        offset: call.Offset,
                        severity: Severity.Medium,
                        state: state,
                        tags: new[] { "broad-call-flags" });
                }
            }
        }
    }
}
