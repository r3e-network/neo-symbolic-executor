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
        // Build a view of safe methods from the manifest, if available.
        var safeOffsets = context.Manifest?.Abi.Methods
            .Where(m => m.Safe)
            .Select(m => m.Offset)
            .ToHashSet() ?? new HashSet<int>();

        foreach (var state in context.States)
        {
            var sensitiveOps = CollectSensitiveOps(context, state);
            if (sensitiveOps.Count == 0) continue;

            int firstSensitive = sensitiveOps.Min(op => op.Offset);
            var witnessChecks = state.Telemetry.WitnessChecks;
            var enforced = state.Telemetry.WitnessChecksEnforced;
            var callerChecks = state.Telemetry.CallerHashChecks;
            var sigChecks = state.Telemetry.SignatureChecks;

            bool noAuthAtAll = witnessChecks.Count == 0 && callerChecks.Count == 0 && sigChecks.Count == 0;
            bool noEnforcement = witnessChecks.Count > 0 && enforced.Count == 0
                                 && callerChecks.Count == 0 && sigChecks.Count == 0;
            bool authBeforeSensitive = enforced.Any(o => o < firstSensitive)
                                        || callerChecks.Any(o => o < firstSensitive)
                                        || sigChecks.Any(o => o < firstSensitive);

            // If the analyzed method is `safe=true`, drop severity (the contract author claims no
            // state changes; if it's wrong we'd surface elsewhere as a contract-spec mismatch).
            int? entryOffset = state.Path.Count > 0 ? state.Path[0] : null;
            bool isSafeView = entryOffset.HasValue && safeOffsets.Contains(entryOffset.Value);

            if (noAuthAtAll && !isSafeView)
            {
                yield return MakeFinding(
                    title: "Sensitive operation lacks authorization check",
                    description: $"Sensitive operation at 0x{firstSensitive:X4} executes without any "
                               + "Runtime.CheckWitness, GetCallingScriptHash, or signature verification.",
                    offset: firstSensitive,
                    severity: Severity.High,
                    state: state,
                    tags: new[] { "missing-auth" });
            }
            else if (noEnforcement && !isSafeView)
            {
                yield return MakeFinding(
                    title: "Authorization check is unenforced (fail-open)",
                    description: $"Runtime.CheckWitness invoked at 0x{witnessChecks[0]:X4} but its "
                               + "result is not consumed by ASSERT or a branch instruction. The check is fail-open.",
                    offset: witnessChecks[0],
                    severity: Severity.High,
                    state: state,
                    tags: new[] { "unenforced-witness" });
            }
            else if (!authBeforeSensitive && !isSafeView)
            {
                yield return MakeFinding(
                    title: "Authorization check happens after sensitive operation",
                    description: $"Sensitive operation at 0x{firstSensitive:X4} runs before any "
                               + "enforced authorization check.",
                    offset: firstSensitive,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "late-auth" });
            }
        }
    }

    private static List<SensitiveOp> CollectSensitiveOps(AnalysisContext context, ExecutionState state)
    {
        var ops = new List<SensitiveOp>();
        foreach (var s in state.Telemetry.StorageOps)
            if (s.Kind == StorageOpKind.Put || s.Kind == StorageOpKind.Delete)
                ops.Add(new SensitiveOp(s.Offset, "storage-write"));
        foreach (var c in state.Telemetry.ExternalCalls)
            if (!IsBenignNativeCall(context, c))
                ops.Add(new SensitiveOp(c.Offset, "external-call"));
        return ops;
    }

    private static bool IsBenignNativeCall(AnalysisContext context, ExternalCall call)
    {
        var hash = call.TargetHash?.AsConcreteBytes();
        if (hash is null) return false;
        string hex = System.Convert.ToHexString(hash).ToLowerInvariant();
        var native = context.Natives.ByHash(hex);
        if (native is null) return false;
        return native.ReadOnlyMethods.Contains(call.Method, System.StringComparer.OrdinalIgnoreCase);
    }

    private sealed record SensitiveOp(int Offset, string Kind);
}
