using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects use of <c>Runtime.GetEntryScriptHash()</c> in authorization decisions — the Neo
/// analogue of the Ethereum "tx.origin" bug. The entry script hash identifies the first
/// contract in the invocation chain, not the immediate caller. Gating sensitive operations on
/// equality with the entry script hash lets a malicious intermediary contract spoof an
/// authorized identity by being invoked through the trusted entry point.
///
/// The recommended Neo pattern is <c>Runtime.CheckWitness</c> (which validates a transaction
/// signature) or <c>Runtime.GetCallingScriptHash</c> (which identifies the direct caller).
///
/// Detection: the engine pushes a stable <c>entry_script_hash</c> symbol for each invocation.
/// Older traces used <c>System.Runtime.GetEntryScriptHash_&lt;offset&gt;</c>. When either symbol
/// appears in any path condition AND the state reaches a sensitive operation, flag.
///
/// Review fix (#55): the offset-based detection cannot prove the entry-hash branch actually GATES
/// the sensitive op, and a contract may legitimately read the entry hash for telemetry while
/// gating writes with a proper witness/caller/signature check. When such an enforced auth signal
/// coexists on the path, we downgrade the severity (HIGH → Medium) and reword to surface the
/// entry-hash usage for review rather than asserting a missing-auth bug.
/// </summary>
public sealed class EntryScriptAuthDetector : BaseDetector
{
    public override string Name => "entry_script_auth";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.85;

    private const string SymbolPrefix = "System.Runtime.GetEntryScriptHash_";
    private const string StableSymbol = "entry_script_hash";

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            int? gatedAt = null;
            foreach (var cond in state.PathConditions)
            {
                var entrySymbol = cond.FreeSymbols().FirstOrDefault(IsEntryScriptHashSymbol);
                if (entrySymbol is not null)
                {
                    gatedAt = ExtractOffset(entrySymbol);
                    break;
                }
            }
            if (gatedAt is null) continue;

            var sensitiveOps = ProtocolRiskHelpers.SensitiveOps(state)
                .OrderBy(op => op.Offset)
                .ToList();
            if (sensitiveOps.Count == 0) continue;

            // Review fix (#55): when the path also carries an enforced witness/caller/signature
            // check, the entry-hash branch is unlikely to be the sole authorization gate — downgrade
            // and reword to a review surface instead of a missing-auth assertion.
            bool authCoexists = ProtocolRiskHelpers.HasAnyEnforcedAuth(state);
            if (authCoexists)
            {
                yield return MakeFinding(
                    title: "Entry script hash used in a branch alongside enforced authorization",
                    description: $"Runtime.GetEntryScriptHash at 0x{gatedAt.Value:X4} flows into a branch condition on a path "
                               + $"that reaches {sensitiveOps[0].Kind} at 0x{sensitiveOps[0].Offset:X4}. The path also carries an "
                               + "enforced witness/caller/signature check, so the entry hash may not be the sole authorization "
                               + "gate. Surfaced for review: confirm the entry hash is not relied on for authorization, since it "
                               + "identifies the first script in the call chain, not the direct caller.",
                    offset: gatedAt.Value,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "entry-script-auth", "tx-origin-equivalent", "auth-coexists" });
            }
            else
            {
                yield return MakeFinding(
                    title: "Authorization based on entry script hash (tx.origin-style)",
                    description: $"Runtime.GetEntryScriptHash at 0x{gatedAt.Value:X4} flows into a branch condition on a path "
                               + $"that reaches {sensitiveOps[0].Kind} at 0x{sensitiveOps[0].Offset:X4}. The entry hash identifies "
                               + "the first script in the call chain, not the direct caller — a malicious intermediary contract "
                               + "invoked through the trusted entry point can spoof the gated identity. Use Runtime.CheckWitness "
                               + "or Runtime.GetCallingScriptHash for authorization.",
                    offset: gatedAt.Value,
                    severity: Severity.High,
                    state: state,
                    tags: new[] { "entry-script-auth", "tx-origin-equivalent", "missing-auth" });
            }
        }
    }

    private static int? ExtractOffset(string symbolName)
    {
        if (string.Equals(symbolName, StableSymbol, System.StringComparison.Ordinal))
            return 0;

        var suffix = symbolName.AsSpan(SymbolPrefix.Length);
        return int.TryParse(suffix, out int n) ? n : null;
    }

    private static bool IsEntryScriptHashSymbol(string symbolName) =>
        string.Equals(symbolName, StableSymbol, System.StringComparison.Ordinal)
        || symbolName.StartsWith(SymbolPrefix, System.StringComparison.Ordinal);
}
