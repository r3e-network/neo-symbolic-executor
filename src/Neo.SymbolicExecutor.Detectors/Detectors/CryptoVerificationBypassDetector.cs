using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// New detector per audit coverage gap #4: signature-verification result not validated.
///
/// CheckSig and CheckMultisig syscalls return a Bool. The engine emits the result as a symbol
/// like `sig_ok_<offset>`. Two distinct fail-open shapes are reported:
///   1. result-ignored: the `sig_ok_<offset>` symbol does NOT appear in any path condition — the
///      verification was performed but its result is never consumed by an ASSERT/JMPIF.
///   2. result-not-gating (Review fix #57): the symbol IS consumed by a branch, but the positive
///      verification result is NOT in the reaching state's enforced-signature-check set
///      (<see cref="Telemetry.IsSignatureCheckResultEnforced"/>). This is the branch-but-don't-gate
///      pattern: the code branches on the result yet the success path is not what authorizes the
///      sensitive continuation (e.g. the failure branch falls through instead of aborting).
/// </summary>
public sealed class CryptoVerificationBypassDetector : BaseDetector
{
    public override string Name => "crypto_verification_bypass";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.85;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            if (state.Telemetry.SignatureChecks.Count == 0) continue;

            foreach (var check in state.Telemetry.SignatureCheckOps)
            {
                bool consumed = state.PathConditions.Any(cond =>
                    cond.FreeSymbols().Any(n => n == check.ResultSymbol));
                if (!consumed)
                {
                    yield return MakeFinding(
                        title: "Signature verification result is not validated",
                        description: $"CheckSig/CheckMultisig at 0x{check.Offset:X4} is called but its result does not influence "
                                   + "any branch on this path. The signature failure case is silently ignored.",
                        offset: check.Offset,
                        severity: Severity.High,
                        state: state,
                        tags: new[] { "crypto-bypass", "fail-open-auth" });
                    continue;
                }

                // Review fix (#57): consumed by a branch but the positive result does not gate the
                // path (not enforced). The code looks at the verification outcome without letting it
                // authorize the continuation — a branch-but-don't-gate fail-open.
                if (!state.Telemetry.IsSignatureCheckResultEnforced(check))
                {
                    yield return MakeFinding(
                        title: "Signature verification result does not gate the path",
                        description: $"CheckSig/CheckMultisig at 0x{check.Offset:X4} influences a branch on this path, but the "
                                   + "positive verification result is not enforced as the gate (the success outcome does not "
                                   + "control whether the sensitive continuation runs). The failure case can still fall through "
                                   + "— fail-open authorization. Abort/return on verification failure before proceeding.",
                        offset: check.Offset,
                        severity: Severity.High,
                        state: state,
                        tags: new[] { "crypto-bypass", "fail-open-auth", "result-not-gating" });
                }
            }

            if (state.Telemetry.SignatureCheckOps.Count > 0)
                continue;

            // Backward-compatible path for tests or external embedders that populate only offsets.
            foreach (var off in state.Telemetry.SignatureChecks)
            {
                bool consumed = state.PathConditions.Any(cond =>
                    cond.FreeSymbols().Any(n => n == $"sig_ok_{off}" || n == $"multisig_ok_{off}"));
                if (consumed) continue;

                yield return MakeFinding(
                    title: "Signature verification result is not validated",
                    description: $"CheckSig/CheckMultisig at 0x{off:X4} is called but its result does not influence "
                               + "any branch on this path. The signature failure case is silently ignored.",
                    offset: off,
                    severity: Severity.High,
                    state: state,
                    tags: new[] { "crypto-bypass", "fail-open-auth" });
            }
        }
    }
}
