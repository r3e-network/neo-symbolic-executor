using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects Neo Oracle callback handlers — methods following the
/// <c>onOracleResponse(url, userdata, code, result)</c> shape — that mutate state without
/// branching on the <c>code</c> argument. The Oracle native passes a status code that is
/// non-<c>Success</c> when the upstream HTTP fetch failed, timed out, or was rejected by the
/// filter. A handler that doesn't check <c>code</c> proceeds to consume the (possibly
/// adversarial or empty) <c>result</c> as if it were authentic data — typical impacts are
/// reading stale prices, writing zero balances, or trusting attacker-supplied JSON.
///
/// Detection: any manifest method whose name matches the canonical <c>onOracleResponse</c> shape
/// (regardless of exact casing) OR whose parameter signature matches the Oracle callback shape
/// <c>(String url, Any userData, Integer code, * result)</c> is considered an oracle callback.
/// Review fix (#21): the structural signature match catches forged-caller callbacks that use a
/// non-standard method name, which the prior name-only gate missed.
///
/// The detector fires on two obligations:
///   1. missing-code-check: the method reaches a state-mutating storage write without the
///      <c>code</c> argument (positional index 2 in the canonical signature) appearing in any
///      path condition.
///   2. forged-caller (Review fix #21): the method consumes the response into a storage write
///      without verifying <c>Runtime.CallingScriptHash == OracleContract</c> first. Without that
///      check, any contract can invoke the callback directly and supply attacker-chosen
///      <c>result</c>/<c>code</c> values.
/// </summary>
public sealed class OracleResponseValidationDetector : BaseDetector
{
    public override string Name => "oracle_response_validation";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.8;

    private static readonly byte[] OracleContractHash =
        NeoNativeContractHashes.FromHex(NeoNativeContractHashes.OracleContract);

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;

        // Find oracle callback candidates. Match by exact/permissive name OR by the canonical
        // Oracle callback parameter shape (String, Any, Integer, *) to catch forged-caller attacks
        // that rename the handler.
        var callbacks = context.Manifest.Abi.Methods
            .Where(IsOracleCallback)
            .ToList();
        if (callbacks.Count == 0) yield break;

        // Round-2 fix (#21): a manifest-level reference to the Oracle native (a permission or trust
        // entry naming the Oracle native hash) is corroborating evidence that a structurally-shaped
        // method really is an oracle callback. Computed once per manifest.
        bool manifestReferencesOracle = ManifestReferencesOracle(context.Manifest);

        foreach (var method in callbacks)
        {
            // Round-2 fix (#21): a NAME match (canonical/permissive) is a strong oracle signal on
            // its own. A method matched only by the bare parameter shape (String, Any, Integer, *) is
            // a weak signal — that shape is common to many non-oracle methods — so the HIGH
            // forged-caller assertion must NOT fire on shape alone.
            bool strongNameSignal = HasStrongOracleNameSignal(method);

            string codeSym = ProtocolRiskHelpers.MethodArgSymbolName(method, index: 2, defaultIfMissing: "arg2");
            foreach (var state in context.States)
            {
                if (!ProtocolRiskHelpers.IsEntryStateFor(state, method)) continue;
                if (!state.Telemetry.StorageOps.Any(ProtocolRiskHelpers.IsStateWrite)) continue;

                int firstWrite = state.Telemetry.StorageOps
                    .Where(ProtocolRiskHelpers.IsStateWrite)
                    .Min(op => op.Offset);

                bool codeGated = state.PathConditions
                    .SelectMany(c => c.FreeSymbols())
                    .Any(n => n == codeSym);
                if (!codeGated)
                {
                    yield return MakeFinding(
                        title: $"Oracle callback `{method.Name}` mutates state without checking response code",
                        description: $"`{method.Name}` reaches a storage write at 0x{firstWrite:X4} without branching "
                                   + $"on the `{codeSym}` (OracleResponseCode) argument. A non-Success response — "
                                   + "timeout, fetch failure, filter rejection — will be consumed as authentic. "
                                   + "Guard with `if (code != OracleResponseCode.Success) return;` before touching "
                                   + "state derived from `result`.",
                        offset: firstWrite,
                        severity: Severity.High,
                        state: state,
                        tags: new[] { "oracle", "missing-code-check" });
                }

                // Review fix (#21): forged-caller obligation. A genuine oracle callback is invoked
                // only by the Oracle native contract; the handler must verify the caller before
                // consuming the response. Fire when no caller check binds CallingScriptHash to the
                // Oracle native hash on this path.
                if (!VerifiesOracleCaller(state))
                {
                    // Round-2 fix (#21): only assert the HIGH forged-caller finding when there is a
                    // STRONGER oracle signal than the bare type-shape: a canonical/permissive NAME
                    // match, OR (shape-match AND additional evidence — the manifest references the
                    // Oracle native, or this path calls the Oracle native). A bare-shape-only match
                    // with no corroborating evidence is downgraded to a Low advisory with its own tag
                    // so genuine oracle callbacks are still caught while common non-oracle methods
                    // sharing the (String, Any, Integer, *) shape no longer trigger a HIGH false
                    // positive.
                    bool strongOracleSignal =
                        strongNameSignal
                        || manifestReferencesOracle
                        || StateCallsOracleNative(state);

                    if (strongOracleSignal)
                    {
                        yield return MakeFinding(
                            title: $"Oracle callback `{method.Name}` consumes response without verifying the Oracle caller",
                            description: $"`{method.Name}` reaches a storage write at 0x{firstWrite:X4} without checking "
                                       + "that Runtime.CallingScriptHash equals the Oracle native contract. Any contract "
                                       + "can invoke this method directly and supply attacker-chosen result/code values. "
                                       + "Require `Runtime.CallingScriptHash == Oracle.Hash` before consuming `result`.",
                            offset: firstWrite,
                            severity: Severity.High,
                            state: state,
                            tags: new[] { "oracle", "forged-caller", "missing-auth" });
                    }
                    else
                    {
                        yield return MakeFinding(
                            title: $"Method `{method.Name}` matches the Oracle callback shape but lacks an Oracle-caller check",
                            description: $"`{method.Name}` matches the Oracle callback parameter shape "
                                       + "(String, Any, Integer, *) and reaches a storage write at "
                                       + $"0x{firstWrite:X4} without verifying Runtime.CallingScriptHash == Oracle. "
                                       + "No stronger oracle signal (canonical name, Oracle permission/trust, or a "
                                       + "call to the Oracle native) is present, so this is reported as a "
                                       + "low-confidence advisory: IF this is an oracle callback, add the caller check; "
                                       + "otherwise it is likely a false positive from the shared parameter shape.",
                            offset: firstWrite,
                            severity: Severity.Low,
                            state: state,
                            tags: new[] { "oracle", "forged-caller-advisory", "shape-only" });
                    }
                }
            }
        }
    }

    /// <summary>
    /// Round-2 fix (#21): true iff the method name itself is a strong oracle-callback signal —
    /// the canonical <c>onOracleResponse</c> (case-insensitive) or a permissive name containing
    /// both an "oracle" token and a "response"/"callback" token. Distinct from the bare structural
    /// shape, which is a weak signal common to non-oracle methods.
    /// </summary>
    private static bool HasStrongOracleNameSignal(Nef.ContractMethodDescriptor m)
    {
        string n = m.Name.ToLowerInvariant();
        return n == "onoracleresponse"
            || (n.Contains("oracle") && (n.Contains("response") || n.Contains("callback")));
    }

    /// <summary>
    /// Round-2 fix (#21): true iff the manifest declares a permission or trust entry naming the
    /// Oracle native contract (or a wildcard that subsumes it). Corroborating evidence that a
    /// structurally-shaped handler is a genuine oracle callback rather than a shape coincidence.
    /// </summary>
    private static bool ManifestReferencesOracle(Nef.ContractManifest? manifest)
    {
        if (manifest is null) return false;
        if (manifest.Permissions.Any(p => p.Contract == "*" || IsOracleHashString(p.Contract)))
            return true;
        if (manifest.Trusts.IsWildcard)
            return true;
        return manifest.Trusts.Items.Any(IsOracleHashString);
    }

    /// <summary>
    /// Round-2 fix (#21): true iff this path makes an external call whose concrete target hash is the
    /// Oracle native contract — i.e. the contract actually talks to the Oracle native, strong
    /// evidence that a shaped handler participates in the oracle flow.
    /// </summary>
    private static bool StateCallsOracleNative(ExecutionState state) =>
        state.Telemetry.ExternalCalls.Any(call =>
            call.TargetHash?.AsConcreteBytes() is { Length: NeoNativeContractHashes.HashLength } bytes
            && bytes.AsSpan().SequenceEqual(OracleContractHash));

    /// <summary>
    /// Round-2 fix (#21): true iff a manifest permission/trust string denotes the Oracle native
    /// hash. Manifest hash strings are conventionally <c>0x</c>-prefixed big-endian; the native hash
    /// constant is stored little-endian, so we normalize (strip <c>0x</c>, lowercase) and compare
    /// against both the little-endian and reversed (big-endian) hex forms.
    /// </summary>
    private static bool IsOracleHashString(string contract)
    {
        if (string.IsNullOrEmpty(contract)) return false;
        string normalized = contract.StartsWith("0x", System.StringComparison.OrdinalIgnoreCase)
            ? contract[2..]
            : contract;
        normalized = normalized.ToLowerInvariant();
        return string.Equals(normalized, OracleHashLittleEndianHex, System.StringComparison.Ordinal)
            || string.Equals(normalized, OracleHashBigEndianHex, System.StringComparison.Ordinal);
    }

    private static readonly string OracleHashLittleEndianHex =
        System.Convert.ToHexString(OracleContractHash).ToLowerInvariant();

    private static readonly string OracleHashBigEndianHex =
        System.Convert.ToHexString(ReverseBytes(OracleContractHash)).ToLowerInvariant();

    private static byte[] ReverseBytes(byte[] input)
    {
        var copy = (byte[])input.Clone();
        System.Array.Reverse(copy);
        return copy;
    }

    private static bool IsOracleCallback(Nef.ContractMethodDescriptor m)
    {
        if (m.Parameters.Count != 4) return false;
        string n = m.Name.ToLowerInvariant();
        if (n == "onoracleresponse") return true;
        // Permissive: "oracle" + "response"/"callback" tokens, in either order, for non-canonical
        // names.
        if (n.Contains("oracle") && (n.Contains("response") || n.Contains("callback")))
            return true;
        // Review fix (#21): structural match on the Oracle callback signature
        // (String url, Any userData, Integer code, * result) so a renamed handler is still
        // recognized as a forged-caller candidate.
        return IsOracleCallbackShape(m);
    }

    private static bool IsOracleCallbackShape(Nef.ContractMethodDescriptor m) =>
        m.Parameters.Count == 4
        && IsType(m.Parameters[0].Type, "String")
        && IsType(m.Parameters[1].Type, "Any")
        && IsType(m.Parameters[2].Type, "Integer");

    /// <summary>
    /// Review fix (#21): true iff the state enforces a caller check binding the calling script hash
    /// to the Oracle native contract — i.e. a recorded <see cref="CallerHashCheckOp"/> whose target
    /// principal is the concrete 20-byte Oracle native hash.
    /// </summary>
    private static bool VerifiesOracleCaller(ExecutionState state) =>
        state.Telemetry.CallerHashCheckOps.Any(op =>
            op.Target.AsConcreteBytes() is { Length: NeoNativeContractHashes.HashLength } bytes
            && bytes.AsSpan().SequenceEqual(OracleContractHash));

    // Review fix (#74): shared Nef.AbiTypeMatching source of truth (was a per-detector copy).
    private static bool IsType(string? actual, string expected) =>
        Nef.AbiTypeMatching.IsType(actual, expected);
}
