using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// New detector per audit coverage gap #4: signature-verification result not validated.
///
/// CheckSig and CheckMultisig syscalls return a Bool. The engine emits the result as a symbol
/// like `sig_ok_<offset>`. If that symbol does NOT appear in any path condition or is never
/// consumed by an ASSERT/JMPIF, the verification was performed but its result is ignored —
/// fail-open auth.
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

            // For each sig-check offset, look for a path condition naming the corresponding symbol.
            foreach (var off in state.Telemetry.SignatureChecks)
            {
                bool consumed = false;
                foreach (var cond in state.PathConditions)
                {
                    if (cond.FreeSymbols().Any(n => n == $"sig_ok_{off}" || n == $"multisig_ok_{off}"))
                    {
                        consumed = true;
                        break;
                    }
                }
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
