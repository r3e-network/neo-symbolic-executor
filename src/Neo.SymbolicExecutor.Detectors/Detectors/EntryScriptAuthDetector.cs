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
/// Detection: the engine pushes a symbol named <c>System.Runtime.GetEntryScriptHash_&lt;offset&gt;</c>
/// for each invocation. When that symbol appears in any path condition AND the state reaches a
/// sensitive operation, flag.
/// </summary>
public sealed class EntryScriptAuthDetector : BaseDetector
{
    public override string Name => "entry_script_auth";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.85;

    private const string SymbolPrefix = "System.Runtime.GetEntryScriptHash_";

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            int? gatedAt = null;
            foreach (var cond in state.PathConditions)
            {
                if (cond.FreeSymbols().Any(n => n.StartsWith(SymbolPrefix, System.StringComparison.Ordinal)))
                {
                    gatedAt = ExtractOffset(cond.FreeSymbols()
                        .First(n => n.StartsWith(SymbolPrefix, System.StringComparison.Ordinal)));
                    break;
                }
            }
            if (gatedAt is null) continue;

            var sensitiveOps = ProtocolRiskHelpers.SensitiveOps(state)
                .OrderBy(op => op.Offset)
                .ToList();
            if (sensitiveOps.Count == 0) continue;

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

    private static int? ExtractOffset(string symbolName)
    {
        var suffix = symbolName.AsSpan(SymbolPrefix.Length);
        return int.TryParse(suffix, out int n) ? n : null;
    }
}
