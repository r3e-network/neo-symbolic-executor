using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects sensitive operations (storage writes / non-native external calls) that execute
/// without an enforced authorization check.
///
/// Audit-derived precision rules:
/// - <see cref="NativeContractRegistry"/>: native read-only calls (Ledger.GetBlock, StdLib.*, etc.)
///   are NOT sensitive (audit detector audit #1, biggest precision win across detectors).
/// - <see cref="Nef.ContractMethodDescriptor.Safe"/>: when the analyzed method is declared `safe=true`
///   in the manifest, the contract author has asserted no state changes; downgrade to INFO.
/// - Distinguish three failure modes: missing (no witness check at all), unenforced (witness
///   checked but not consumed by control flow), and late (witness check after the sensitive op).
/// </summary>
public sealed class AccessControlDetector : BaseDetector
{
    public override string Name => "access_control";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.85;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            var sensitiveOps = CollectSensitiveOps(context, state);
            if (sensitiveOps.Count == 0) continue;

            // A `safe=true` manifest assertion is useful precision evidence, but it is still
            // attacker-/author-controlled metadata. If bytecode telemetry shows a sensitive write
            // or call, keep a visible INFO finding instead of fully suppressing it.
            bool manifestSafe = ProtocolRiskHelpers.MethodForState(context, state)?.Safe == true;

            int firstSensitive = sensitiveOps.Min(op => op.Offset);
            var witnessChecks = state.Telemetry.WitnessChecks;
            var enforced = state.Telemetry.WitnessChecksEnforced;
            var callerChecks = state.Telemetry.CallerHashChecks;
            var sigChecks = state.Telemetry.SignatureChecks;

            bool noAuthAtAll = witnessChecks.Count == 0 && callerChecks.Count == 0 && sigChecks.Count == 0;
            // Audit C# #11 fix: previously suppressed when callerChecks/sigChecks were present —
            // but those are independent auth signals, not "rescues" for an unenforced witness.
            // The unenforced-witness finding fires when witness was invoked but never consumed,
            // regardless of what other auth signals exist; the deduper merges with related findings.
            bool witnessUnenforced = witnessChecks.Count > 0 && enforced.Count == 0;
            // Review fix (#56): the "auth precedes the sensitive op" inference compares raw bytecode
            // offsets, which only tracks execution order on a path with no back-edges. On a state
            // with a detected loop a lower-offset check may run after the op (or be skipped on some
            // iterations), so we do not let offset order clear the late-auth finding there. Loop-free
            // states keep the original behavior.
            bool offsetOrderTrustworthy = state.Telemetry.LoopsDetected.Count == 0;
            bool authBeforeSensitive = offsetOrderTrustworthy
                && (enforced.Any(o => o < firstSensitive)
                    || callerChecks.Any(o => o < firstSensitive)
                    || sigChecks.Any(o => o < firstSensitive));

            if (noAuthAtAll)
            {
                yield return MakeFinding(
                    title: "Sensitive operation lacks authorization check",
                    description: $"Sensitive operation at 0x{firstSensitive:X4} executes without any "
                               + "Runtime.CheckWitness, GetCallingScriptHash, or signature verification."
                               + ManifestSafeSuffix(manifestSafe),
                    offset: firstSensitive,
                    severity: manifestSafe ? Severity.Info : Severity.High,
                    state: state,
                    tags: Tags("missing-auth", manifestSafe));
            }
            else if (witnessUnenforced)
            {
                yield return MakeFinding(
                    title: "Authorization check is unenforced (fail-open)",
                    description: $"Runtime.CheckWitness invoked at 0x{witnessChecks[0]:X4} but its "
                               + "result is not consumed by ASSERT or a branch instruction. The check is fail-open."
                               + ManifestSafeSuffix(manifestSafe),
                    offset: witnessChecks[0],
                    severity: manifestSafe ? Severity.Info : Severity.High,
                    state: state,
                    tags: Tags("unenforced-witness", manifestSafe));
            }
            else if (!authBeforeSensitive)
            {
                yield return MakeFinding(
                    title: "Authorization check happens after sensitive operation",
                    description: $"Sensitive operation at 0x{firstSensitive:X4} runs before any "
                               + "enforced authorization check."
                               + ManifestSafeSuffix(manifestSafe),
                    offset: firstSensitive,
                    severity: manifestSafe ? Severity.Info : Severity.Medium,
                    state: state,
                    tags: Tags("late-auth", manifestSafe));
            }
        }
    }

    private static List<SensitiveOp> CollectSensitiveOps(AnalysisContext context, ExecutionState state)
    {
        var ops = new List<SensitiveOp>();
        foreach (var s in state.Telemetry.StorageOps)
            if (ProtocolRiskHelpers.IsStateWrite(s))
                ops.Add(new SensitiveOp(s.Offset, "storage-write"));
        foreach (var c in state.Telemetry.ExternalCalls)
            if (!c.ModeledSelfCall && !context.Natives.IsBenignReadOnlyCall(c))
                ops.Add(new SensitiveOp(c.Offset, "external-call"));
        return ops;
    }

    private sealed record SensitiveOp(int Offset, string Kind);

    private static string ManifestSafeSuffix(bool manifestSafe) =>
        manifestSafe
            ? " Manifest marks the entrypoint safe=true, so this is downgraded but kept visible because telemetry reached a sensitive operation."
            : "";

    private static string[] Tags(string primary, bool manifestSafe) =>
        manifestSafe
            ? new[] { primary, "manifest-safe-assertion" }
            : new[] { primary };
}
