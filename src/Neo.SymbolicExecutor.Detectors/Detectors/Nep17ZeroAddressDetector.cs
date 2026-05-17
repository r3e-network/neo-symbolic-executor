using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects NEP-17 <c>transfer(from, to, amount, data)</c> method bodies that mutate state
/// without constraining either the <c>from</c> or <c>to</c> argument against the zero address.
/// The NEP-17 specification recommends rejecting transfers from or to <c>UInt160.Zero</c>:
///
///   - Transfers <i>from</i> the zero address are typically used as a synonym for minting; a
///     contract that doesn't gate this allows anyone to credit themselves arbitrary balance.
///   - Transfers <i>to</i> the zero address permanently burn tokens; if the implementation
///     doesn't intend a burn semantic, accidentally accepting such a transfer breaks the
///     invariant that totalSupply equals the sum of all balances.
///
/// Detection: the engine seeds <c>from</c> / <c>to</c> as symbols (manifest-named
/// <c>arg_from</c> / <c>arg_to</c>, or positional <c>arg0</c> / <c>arg1</c>). A guarded path
/// constrains those symbols via a branch (typically a length-or-equality check vs the zero
/// address). A state that reaches a storage write while neither symbol appeared in any branch
/// indicates an unprotected from/to.
/// </summary>
public sealed class Nep17ZeroAddressDetector : BaseDetector
{
    public override string Name => "nep17_zero_address";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.75;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;
        if (!context.Manifest.DeclaresStandard("NEP-17")) yield break;
        var transfer = context.Manifest.FindMethod("transfer");
        if (transfer is null) yield break;

        string fromSym = ProtocolRiskHelpers.MethodArgSymbolName(transfer, index: 0, defaultIfMissing: "arg0");
        string toSym = ProtocolRiskHelpers.MethodArgSymbolName(transfer, index: 1, defaultIfMissing: "arg1");

        foreach (var state in context.States)
        {
            if (!ProtocolRiskHelpers.IsEntryStateFor(state, transfer)) continue;
            if (!state.Telemetry.StorageOps.Any(ProtocolRiskHelpers.IsStateWrite)) continue;

            var pathSymbols = new HashSet<string>(
                state.PathConditions.SelectMany(c => c.FreeSymbols()),
                System.StringComparer.Ordinal);

            var missing = new List<string>();
            if (!pathSymbols.Contains(fromSym)) missing.Add("from");
            if (!pathSymbols.Contains(toSym)) missing.Add("to");
            if (missing.Count == 0) continue;

            int firstWrite = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsStateWrite)
                .Min(op => op.Offset);

            yield return MakeFinding(
                title: $"NEP-17 transfer mutates state without validating {string.Join(" / ", missing)} against zero",
                description: $"`transfer` reaches a storage write at 0x{firstWrite:X4} without branching on "
                           + $"the {string.Join(" or ", missing.Select(m => "`" + m + "`"))} argument. NEP-17 "
                           + "recommends rejecting transfers from/to UInt160.Zero — from-zero is typically a mint "
                           + "alias and accepting it lets anyone credit themselves; to-zero permanently burns and "
                           + "breaks totalSupply invariants if unintended.",
                offset: firstWrite,
                severity: Severity.Medium,
                state: state,
                tags: new[] { "nep17", "zero-address" });
        }
    }

}
