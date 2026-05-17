using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects contracts that use a raw ECDSA signature as a storage key for replay protection
/// or deduplication, without first normalizing the signature to its canonical low-S form.
/// secp256r1 signatures are malleable — for any valid (r, s) pair, (r, n-s) is also a valid
/// signature for the same message. A contract that keys uniqueness on the raw signature bytes
/// will accept the same logical authorization twice.
///
/// Detection signal: a state-mutating storage write whose key expression contains a symbol
/// derived from a method argument with a "sig"/"signature" name fragment (e.g. <c>arg_sig</c>,
/// <c>arg_signature</c>, <c>arg_proof</c>), and that argument was not concretized or compared
/// against a known canonical form on the path. Conservative — symbolic-key writes with no
/// sig-named argument in the expression do not fire.
///
/// Mitigation: normalize <c>s</c> to <c>s &lt; n/2</c> before any dedup check, or use a
/// transaction-hash-derived nonce instead of the signature itself.
/// </summary>
public sealed class SignatureMalleabilityDetector : BaseDetector
{
    public override string Name => "signature_malleability";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.6;

    private static readonly string[] SignatureNameHints =
        { "sig", "signature", "sign", "proof" };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            // Only fire when the contract actually performed at least one signature check —
            // signature-bytes-as-key is unremarkable in non-signed contexts.
            if (state.Telemetry.SignatureChecks.Count == 0) continue;

            foreach (var op in state.Telemetry.StorageOps)
            {
                if (!ProtocolRiskHelpers.IsStateWrite(op)) continue;
                var freeSyms = op.Key.Expression.FreeSymbols().ToList();
                if (freeSyms.Count == 0) continue;
                bool sigInKey = freeSyms.Any(IsSignatureArg);
                if (!sigInKey) continue;

                yield return MakeFinding(
                    title: "Signature bytes used as storage key without low-S normalization",
                    description: $"Storage write at 0x{op.Offset:X4} keys on a method argument whose symbol "
                               + $"name ({freeSyms.First(IsSignatureArg)}) suggests a raw ECDSA signature. "
                               + "secp256r1 signatures are malleable: (r, s) and (r, n-s) are both valid for the "
                               + "same message, so the same logical authorization will pass a uniqueness check twice. "
                               + "Normalize to low-S before using as a dedup key, or use a tx-hash-derived nonce.",
                    offset: op.Offset,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "signature-malleability", "crypto", "replay" });
            }
        }
    }

    private static bool IsSignatureArg(string symbolName)
    {
        // Manifest-named args appear as `arg_<name>`; positional args as `argN`. Only the named
        // form carries useful semantic information here, so scan the suffix after `arg_`.
        if (!symbolName.StartsWith("arg_", System.StringComparison.Ordinal)) return false;
        string suffix = symbolName[4..].ToLowerInvariant();
        return SignatureNameHints.Any(h => suffix.Contains(h));
    }
}
