using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects a time-of-check-time-of-use (TOCTOU) pattern: a <c>Storage.Get</c> at offset G,
/// followed by an external call at offset E (G &lt; E), followed by a <c>Storage.Put</c> at
/// offset W (E &lt; W) whose written value derives from the storage value read at G. Between
/// G and W the external callee can re-enter and mutate the same storage slot — the subsequent
/// write at W blindly overwrites with stale data, losing the re-entry's update.
///
/// This is a superset of the classic checks-effects-interactions pattern (which the
/// <c>reentrancy</c> detector flags by external-call-before-write). The TOCTOU variant is
/// narrower and higher-confidence: the read-modify-write loop on the same value is the
/// signature, and the external call need not be reentrant for the bug to fire — any caller
/// that mutates the slot between the read and the write triggers the same lost-update.
///
/// Detection signal: the read's emitted symbol (<c>storage_value_&lt;G&gt;</c>) appears in the
/// write's value expression. The engine already tags every <c>Storage.Get</c> with a unique
/// symbol, so the data-dependency check reduces to a free-symbol containment query.
/// </summary>
public sealed class ToctouStorageDetector : BaseDetector
{
    public override string Name => "toctou_storage";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.75;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            var calls = state.Telemetry.ExternalCalls;
            if (calls.Count == 0) continue;
            // Filter to non-benign external calls — benign native read-only calls (Ledger.GetBlock,
            // StdLib.*, CryptoLib.*) cannot mutate any contract's storage and therefore cannot
            // create the TOCTOU window we're warning about.
            var nonBenignCalls = calls
                .Where(c => !context.Natives.IsBenignReadOnlyCall(c))
                .ToList();
            if (nonBenignCalls.Count == 0) continue;

            foreach (var write in state.Telemetry.StorageOps)
            {
                if (!ProtocolRiskHelpers.IsStateWrite(write)) continue;
                if (write.Value is null) continue;

                // Symbol carried by every Storage.Get result is `storage_value_<offset>`.
                foreach (var sym in write.Value.Expression.FreeSymbols())
                {
                    if (!sym.StartsWith("storage_value_", System.StringComparison.Ordinal)) continue;
                    if (!int.TryParse(sym.AsSpan("storage_value_".Length), out int readOffset)) continue;

                    // Look for an external call strictly between the read and the write.
                    var interposingCall = nonBenignCalls
                        .Where(c => c.Offset > readOffset && c.Offset < write.Offset)
                        .OrderBy(c => c.Offset)
                        .FirstOrDefault();
                    if (interposingCall is null) continue;

                    yield return MakeFinding(
                        title: "Storage read-modify-write spans an external call (TOCTOU)",
                        description: $"Storage.Get at 0x{readOffset:X4} feeds Storage.Put at 0x{write.Offset:X4}, "
                                   + $"but an external call ({interposingCall.Method}) at 0x{interposingCall.Offset:X4} "
                                   + "executes between the read and the write. Any caller that mutates this slot "
                                   + "during the external call has their update silently overwritten. Cache the "
                                   + "read into a local, perform all external calls last, or re-read the slot "
                                   + "after the call before computing the new value.",
                        offset: interposingCall.Offset,
                        severity: Severity.High,
                        state: state,
                        tags: new[] { "toctou", "checks-effects-interactions", "lost-update" });
                    break;
                }
            }
        }
    }
}
