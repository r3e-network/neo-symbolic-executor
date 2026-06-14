using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// New detector per audit coverage gap #3: replay attacks via missing nonce/sequence handling.
///
/// Heuristic: if a contract performs sensitive operations gated by a signature/witness check but
/// reads NO storage value with a nonce-shaped key (matching common naming patterns: "nonce",
/// "seq", "counter", "used_"), surface a finding.
///
/// This is admittedly a name-based heuristic — false positives expected on contracts that use
/// non-standard naming. SMT-backed taint analysis can refine this in a future iteration.
/// </summary>
public sealed class ReplayAttackDetector : BaseDetector
{
    public override string Name => "replay_attack";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.6;

    private static readonly string[] NonceHints =
        { "nonce", "seq", "sequence", "counter", "used_", "executed_", "nonces" };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            // Intentionally narrower than ProtocolRiskHelpers.HasAnyEnforcedAuth: WitnessChecks
            // are per-transaction bound (Neo wallet signs the actual tx) and not replayable, so
            // including them here would over-report on every CheckWitness-gated method. Only
            // signature checks (CheckSig/CheckMultisig over caller-supplied bytes) and caller-
            // hash checks (off-chain identity claims) are replay-relevant.
            if (state.Telemetry.SignatureChecks.Count == 0
                && state.Telemetry.CallerHashChecks.Count == 0) continue;

            bool hasSensitive = state.Telemetry.StorageOps.Any(ProtocolRiskHelpers.IsStateWrite);
            if (!hasSensitive) continue;

            // Audit C# #9 fix: only count Storage.Get reads as nonce-presence signals. Writes
            // alone don't prove the contract checks a previous nonce — an attacker-replay path
            // would still write a nonce key without first reading it.
            //
            // Review fix (#19): the dominant per-account nonce-map pattern is
            // `Storage.Get(concat(prefix, user))`, whose key is NOT fully concrete — only the
            // prefix literal is. Inspect every concrete `BytesConst` sub-fragment of the key
            // expression (not just a whole-key concrete value) for a nonce-shaped literal.
            bool nonceLooking = state.Telemetry.StorageOps.Any(o =>
                o.Kind == StorageOpKind.Get && KeyHasNonceLiteralFragment(o.Key.Expression));
            if (nonceLooking) continue;

            int firstSensitive = state.Telemetry.StorageOps
                .Where(ProtocolRiskHelpers.IsStateWrite)
                .Min(o => o.Offset);

            yield return MakeFinding(
                title: "Signature-gated state change without an apparent nonce",
                description: $"Sensitive operation at 0x{firstSensitive:X4} is gated by signature/witness, but no "
                           + "nonce-shaped storage key (nonce/seq/counter/used_) is read on this path. Off-chain "
                           + "signed messages may be replayable.",
                offset: firstSensitive,
                severity: Severity.Medium,
                state: state,
                tags: new[] { "replay" });
        }
    }

    /// <summary>
    /// Review fix (#19): true iff any concrete <see cref="BytesConst"/> sub-fragment of the storage
    /// key expression decodes to text containing a nonce hint. This matches the per-account
    /// nonce-map shape <c>Storage.Get(concat(prefix, user))</c> where only the prefix literal is
    /// concrete, rather than requiring the whole key to be concrete.
    /// </summary>
    private static bool KeyHasNonceLiteralFragment(Expression key) =>
        ConcreteByteFragments(key).Any(LiteralLooksLikeNonce);

    private static bool LiteralLooksLikeNonce(byte[] literal)
    {
        if (literal.Length == 0) return false;
        string text = System.Text.Encoding.UTF8.GetString(literal);
        return NonceHints.Any(h => text.Contains(h, System.StringComparison.OrdinalIgnoreCase));
    }

    private static IEnumerable<byte[]> ConcreteByteFragments(Expression expr)
    {
        switch (expr)
        {
            case BytesConst bytes:
                yield return bytes.Value;
                break;
            case UnaryExpr u:
                foreach (var f in ConcreteByteFragments(u.Operand)) yield return f;
                break;
            case BinaryExpr b:
                foreach (var f in ConcreteByteFragments(b.Left)) yield return f;
                foreach (var f in ConcreteByteFragments(b.Right)) yield return f;
                break;
            case TernaryExpr t:
                foreach (var f in ConcreteByteFragments(t.A)) yield return f;
                foreach (var f in ConcreteByteFragments(t.B)) yield return f;
                foreach (var f in ConcreteByteFragments(t.C)) yield return f;
                break;
        }
    }
}
