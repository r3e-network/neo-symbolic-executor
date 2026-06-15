using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// New detector per audit coverage gap #2: token-callback re-entry. NEP-17 transfers can invoke
/// the recipient's `onNEP17Payment` callback; if the caller hasn't finished updating its state
/// yet, the callback can re-enter into a partially-updated state.
///
/// Heuristic: if a state contains a token transfer (Method == "transfer" on a Hash160 target)
/// AND the caller writes storage AFTER the transfer call, surface a finding. This is the
/// callback-reentry pattern: recipient gets control before the sender's state is consistent.
/// </summary>
public sealed class CallbackReentryDetector : BaseDetector
{
    public override string Name => "callback_reentry";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.85;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            // Audit C# #10 fix: tighten "transfer" matching. Userland helpers named "transfer"
            // shouldn't fire — only external calls to a CONCRETE non-self contract qualify
            // as a NEP-17/11 transfer that can trigger the recipient's onPayment callback.
            // Dynamic-target transfers are flagged separately by DynamicCallTargetDetector.
            var transfers = state.Telemetry.ExternalCalls
                .Where(c =>
                    !c.ModeledSelfCall
                    &&
                    string.Equals(c.Method, "transfer", System.StringComparison.OrdinalIgnoreCase)
                    && c.TargetHash?.AsConcreteBytes() is byte[] hb
                    && hb.Length == 20)
                .ToList();
            if (transfers.Count == 0) continue;

            // Round-2 fix (#56 parity): the `o.Offset > t.Offset` post-transfer filter is only a
            // sound proxy for execution order on a path with NO back-edges. Under a loop, a write at
            // a lower offset than the transfer can still execute AFTER it (or on a later iteration),
            // so when loops are present we drop the offset filter and treat every state write —
            // pre- or post-transfer — as a callback-reentry candidate. Loop-free behavior is
            // unchanged: the offset filter still applies. Mirrors the ReentrancyDetector /
            // AccessControlDetector / HasAuthBefore round-1 ordering fix.
            bool hasLoops = state.Telemetry.LoopsDetected.Count > 0;

            foreach (var t in transfers)
            {
                bool postWriteExists = state.Telemetry.StorageOps.Any(o =>
                    ProtocolRiskHelpers.IsStateWrite(o) && (hasLoops || o.Offset > t.Offset));
                if (!postWriteExists) continue;

                yield return MakeFinding(
                    title: "Token transfer precedes own-state writes (callback re-entry risk)",
                    description: $"`transfer` call at 0x{t.Offset:X4} can trigger recipient's `onNEP17Payment` "
                               + "or `onNEP11Payment` callback while subsequent storage writes (after the call) "
                               + "have not yet executed. The recipient could re-enter and observe inconsistent state.",
                    offset: t.Offset,
                    severity: Severity.High,
                    state: state,
                    tags: new[] { "callback-reentry", "nep17", "nep11" });
            }
        }
    }
}
