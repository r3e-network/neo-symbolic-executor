using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// External call whose return value is never consumed by an ASSERT or a branch instruction.
///
/// Audit precision lessons:
/// - The engine tags external-call return values with a Symbol named `ext_ret_<offset>`. When that
///   symbol flows into a comparison consumed by ASSERT/JMPIF/JMPCMP, the engine sets
///   <see cref="ExternalCall.ReturnChecked"/> via MarkExternalCallReturnChecked.
/// - Calls that don't return a value (Storage.Put-style) skip this detector via HasReturnValue.
/// - Native read-only calls don't carry impactful return values for our purposes; we still flag
///   them at LOW severity to surface ignored-return patterns.
/// </summary>
public sealed class UncheckedReturnDetector : BaseDetector
{
    public override string Name => "unchecked_return";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.75;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            foreach (var call in state.Telemetry.ExternalCalls)
            {
                if (call.ModeledSelfCall) continue;
                if (!call.HasReturnValue) continue;
                if (call.ReturnChecked) continue;

                yield return MakeFinding(
                    title: "External call return value not validated",
                    description: $"Call to {call.Method} at 0x{call.Offset:X4} returns a value that " +
                                 "is not subsequently checked via ASSERT, equality, or a conditional branch. " +
                                 "Failure of the callee can go unnoticed.",
                    offset: call.Offset,
                    severity: call.ReturnModeledNative ? Severity.Low : Severity.Medium,
                    state: state,
                    tags: call.ReturnModeledNative
                        ? new[] { "unchecked-return", "modeled-native-return" }
                        : new[] { "unchecked-return" });
            }
        }
    }
}
