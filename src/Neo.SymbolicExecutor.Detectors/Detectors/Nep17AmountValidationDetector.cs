using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects NEP-17 <c>transfer(from, to, amount, data)</c> method bodies that mutate state
/// without first constraining the <c>amount</c> argument against zero. A negative amount that
/// reaches the standard <c>balance[from] -= amount; balance[to] += amount</c> implementation
/// drains an arbitrary balance from <c>from</c> and credits it to <c>to</c> — the canonical
/// NEP-17 minting bug.
///
/// Detection: the engine seeds <c>amount</c> as a symbol (manifest-named <c>arg_amount</c>, or
/// positional <c>arg2</c> if unnamed). A guarded path constrains that symbol via a branch
/// condition (`amount &gt;= 0` / `amount &gt; 0`) and the symbol appears in the state's
/// PathConditions. A state that reaches a storage write while the amount symbol never appeared
/// in any branch indicates a missing validation gate.
/// </summary>
public sealed class Nep17AmountValidationDetector : BaseDetector
{
    public override string Name => "nep17_amount_validation";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.85;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;
        if (!context.Manifest.DeclaresStandard("NEP-17")) yield break;
        var transfer = context.Manifest.FindMethod("transfer");
        if (transfer is null) yield break;
        // Spec layout: (from: Hash160, to: Hash160, amount: Integer, data: Any). Index 2 is the
        // amount; honour the manifest-declared parameter name if present.
        string amountSym = ProtocolRiskHelpers.MethodArgSymbolName(transfer, index: 2, defaultIfMissing: "arg2");

        foreach (var state in context.States)
        {
            if (!ProtocolRiskHelpers.IsEntryStateFor(state, transfer)) continue;
            // No state-mutating storage write on this path => nothing to drain. Pure-revert
            // paths (e.g. the amount==0 early-return) need not be flagged.
            if (!state.Telemetry.StorageOps.Any(ProtocolRiskHelpers.IsStateWrite)) continue;

            bool amountGated = state.PathConditions
                .SelectMany(c => c.FreeSymbols())
                .Any(n => n == amountSym);
            if (amountGated) continue;

            int firstWrite = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsStateWrite)
                .Min(op => op.Offset);

            yield return MakeFinding(
                title: "NEP-17 transfer mutates state without validating amount",
                description: $"`transfer` reaches a storage write at 0x{firstWrite:X4} without any branch on the "
                           + $"`{amountSym}` symbol. A negative amount can flip the from/to debit-credit roles, "
                           + "minting tokens at `to` and underflowing `from`'s balance. Require `amount >= 0` before "
                           + "any balance update; per NEP-17 best practice, also fault when from == to.",
                offset: firstWrite,
                severity: Severity.High,
                state: state,
                tags: new[] { "nep17", "amount-validation", "underflow" });
        }
    }

}
