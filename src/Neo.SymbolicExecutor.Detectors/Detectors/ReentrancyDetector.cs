using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// External call before the last storage write — the classic checks-effects-interactions
/// violation. Carries amplification scoring per audit Phase 9:
/// - multiple external calls before state effects
/// - dynamic target hash before state effects
/// - dynamic or All call flags before state effects
/// - deep internal call chain before state effects
///
/// Severity policy (audit Phase 12): downgrade from CRITICAL to HIGH only when witness checks
/// are *enforced* (not merely invoked but unused / fail-open).
///
/// Suppression (audit C1 finding): `reentrancy_guard` wired by the engine when a contract
/// implements a Get-then-Assert-then-Put lock pattern. We honor the flag here.
///
/// Precision: native-contract read-only methods (Ledger, StdLib, CryptoLib, etc.) do NOT
/// constitute "external calls" for reentrancy purposes — these can't re-enter the caller's
/// storage. We filter via <see cref="NativeContractRegistry"/>.
/// </summary>
public sealed class ReentrancyDetector : BaseDetector
{
    public override string Name => "reentrancy";
    public override Severity DefaultSeverity => Severity.Critical;
    public override double DefaultConfidence => 0.9;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            if (state.Telemetry.ReentrancyGuard) continue;
            var calls = state.Telemetry.ExternalCalls;
            if (calls.Count == 0) continue;
            var writes = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsStateWrite)
                .ToList();
            if (writes.Count == 0) continue;

            int lastWriteOffset = writes.Max(w => w.Offset);
            // Review fix (#56): `c.Offset < lastWriteOffset` is only a sound "call precedes write"
            // proxy on a path with no back-edges. On a state with a detected loop a higher-offset
            // call can still execute before the write on a later iteration, so the offset filter
            // would unsoundly clear a genuine reentrancy. When a loop is present we drop the offset
            // filter and treat every non-benign external call as a pre-write candidate. Loop-free
            // states keep the original behavior.
            bool offsetOrderTrustworthy = state.Telemetry.LoopsDetected.Count == 0;
            var preWriteCalls = calls
                .Where(c => !c.ModeledSelfCall)
                .Where(c => !context.Natives.IsBenignReadOnlyCall(c))
                .Where(c => !offsetOrderTrustworthy || c.Offset < lastWriteOffset)
                .ToList();
            if (preWriteCalls.Count == 0) continue;

            var first = preWriteCalls.OrderBy(c => c.Offset).First();

            // Amplification scoring.
            int amp = 0;
            if (preWriteCalls.Count > 1) amp++;
            if (preWriteCalls.Any(c => c.TargetHashDynamic)) amp++;
            if (preWriteCalls.Any(c => c.MethodDynamic)) amp++;
            if (preWriteCalls.Any(c => c.CallFlagsDynamic || c.CallFlags == CallFlags.All)) amp++;
            if (state.Telemetry.MaxCallStackDepth >= 8) amp++;

            // Severity policy. Use the shared HasAnyEnforcedAuth helper so this stays in sync
            // with UpgradeabilityDetector and any future severity-downgrading detector.
            bool authEnforced = ProtocolRiskHelpers.HasAnyEnforcedAuth(state);
            Severity severity = amp switch
            {
                >= 1 => Severity.Critical,                                  // amplified -> always critical
                _ => authEnforced ? Severity.High : Severity.Critical,      // unamplified: auth downgrades, otherwise critical
            };

            var tags = new List<string> { "checks-effects-interactions" };
            if (preWriteCalls.Count > 1) tags.Add("multiple-pre-write-calls");
            if (preWriteCalls.Any(c => c.TargetHashDynamic)) tags.Add("dynamic-target-pre-write");
            if (preWriteCalls.Any(c => c.MethodDynamic)) tags.Add("dynamic-method-pre-write");
            if (state.Telemetry.MaxCallStackDepth >= 8) tags.Add("deep-call-chain");

            yield return MakeFinding(
                title: "External call precedes state write",
                description: $"External call at 0x{first.Offset:X4} ({first.Method}) executes before " +
                             $"a storage write at 0x{lastWriteOffset:X4}. A re-entrant callback could " +
                             $"observe inconsistent state. Amplification factors: {amp}. " +
                             $"Authorization enforced: {authEnforced}.",
                offset: first.Offset,
                severity: severity,
                state: state,
                tags: tags);
        }
    }

}
