using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects NEP-17 <c>transfer(from, to, amount, data)</c> implementations that do not
/// short-circuit when <c>from == to</c>. The canonical implementation reads, debits, writes
/// the from-balance, then reads, credits, writes the to-balance. When the two are the same
/// account, the second read happens against the post-debit value, the credit operates on a
/// stale value, and (depending on order) the account ends with either a partial debit or a
/// double credit. Several real Neo contracts have shipped this bug.
///
/// Detection: the engine seeds <c>from</c> / <c>to</c> as symbols. A protected implementation
/// constrains the relationship between them — either equality (<c>from == to</c> → early
/// return) or inequality (<c>from != to</c> → continue). A state that reaches a state-mutating
/// storage write with neither symbol appearing in a relational path condition involving the
/// other is the buggy case.
///
/// The check is conservative: we only fire when both <c>from</c> and <c>to</c> symbols flow
/// into storage keys on this path (i.e. the body is actually doing a per-account balance
/// update). Pure mint-style methods that take a single recipient and an amount don't trip
/// this detector.
/// </summary>
public sealed class Nep17TransferToSelfDetector : BaseDetector
{
    public override string Name => "nep17_transfer_to_self";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.6;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;
        if (!context.Manifest.DeclaresStandard("NEP-17")) yield break;
        var transfer = ProtocolRiskHelpers.FindStandardNep17TransferMethod(context.Manifest);
        if (transfer is null) yield break;

        string fromSym = ProtocolRiskHelpers.MethodArgSymbolName(transfer, index: 0, defaultIfMissing: "arg0");
        string toSym = ProtocolRiskHelpers.MethodArgSymbolName(transfer, index: 1, defaultIfMissing: "arg1");

        foreach (var state in context.States)
        {
            if (!ProtocolRiskHelpers.IsEntryStateFor(state, transfer)) continue;
            // Require evidence that the body actually does per-account balance writes: both
            // symbols must flow into storage keys on this path.
            bool fromInWrite = false, toInWrite = false;
            foreach (var op in state.Telemetry.StorageOps)
            {
                if (!ProtocolRiskHelpers.IsStateWrite(op)) continue;
                foreach (var sym in op.Key.Expression.FreeSymbols())
                {
                    if (sym == fromSym) fromInWrite = true;
                    else if (sym == toSym) toInWrite = true;
                }
                if (fromInWrite && toInWrite) break;
            }
            if (!fromInWrite || !toInWrite) continue;

            // Look for a path condition that relates from to to (either symbol mentioning the
            // other's name as a free variable in the same expression). Any branch on the
            // relationship satisfies the guard.
            bool selfGuarded = state.PathConditions.Any(cond =>
            {
                var syms = cond.FreeSymbols().ToHashSet(System.StringComparer.Ordinal);
                return syms.Contains(fromSym) && syms.Contains(toSym);
            });
            if (selfGuarded) continue;

            int firstWrite = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsStateWrite)
                .Min(op => op.Offset);

            yield return MakeFinding(
                title: "NEP-17 transfer does not short-circuit when from == to",
                description: $"`transfer` performs per-account balance writes at 0x{firstWrite:X4} without any "
                           + "branch on the `from`/`to` relationship. When the caller passes from == to, the "
                           + "debit-then-credit sequence operates on stale state — the account ends with either "
                           + "a partial debit or a double credit depending on operation order. Add an early "
                           + "`if (from == to) return true;` (after amount validation).",
                offset: firstWrite,
                severity: Severity.Medium,
                state: state,
                tags: new[] { "nep17", "transfer-to-self" });
        }
    }

}
