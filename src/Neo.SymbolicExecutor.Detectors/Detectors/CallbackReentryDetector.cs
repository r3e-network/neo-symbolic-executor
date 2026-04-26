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
            // Find token transfers (treat any external call to method "transfer" as a candidate).
            var transfers = state.Telemetry.ExternalCalls
                .Where(c => string.Equals(c.Method, "transfer", System.StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (transfers.Count == 0) continue;

            foreach (var t in transfers)
            {
                bool postWriteExists = state.Telemetry.StorageOps.Any(o =>
                    (o.Kind == StorageOpKind.Put || o.Kind == StorageOpKind.Delete)
                    && o.Offset > t.Offset);
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
