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
/// Detection: any manifest method whose first identifier-fragment matches the canonical
/// <c>onOracleResponse</c> shape (regardless of exact casing) is considered an oracle
/// callback. The detector fires when such a method reaches a state-mutating storage write
/// without the <c>code</c> argument (positional index 2 in the canonical signature) appearing
/// in any path condition.
/// </summary>
public sealed class OracleResponseValidationDetector : BaseDetector
{
    public override string Name => "oracle_response_validation";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.8;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        if (context.Manifest is null) yield break;

        // Find oracle callback candidates. Conservative: match by exact name first, then by
        // canonical-shape (4 args, name contains "oracle" + "response" tokens), to catch
        // variant capitalizations.
        var callbacks = context.Manifest.Abi.Methods
            .Where(IsOracleCallback)
            .ToList();
        if (callbacks.Count == 0) yield break;

        foreach (var method in callbacks)
        {
            string codeSym = ParameterSymbolName(method.Parameters, index: 2, defaultIfMissing: "arg2");
            foreach (var state in context.States)
            {
                if (state.Path.Count == 0 || state.Path[0] != method.Offset) continue;
                if (!state.Telemetry.StorageOps.Any(ProtocolRiskHelpers.IsStateWrite)) continue;

                bool codeGated = state.PathConditions
                    .SelectMany(c => c.FreeSymbols())
                    .Any(n => n == codeSym);
                if (codeGated) continue;

                int firstWrite = state.Telemetry.StorageOps
                    .Where(ProtocolRiskHelpers.IsStateWrite)
                    .Min(op => op.Offset);

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
        }
    }

    private static bool IsOracleCallback(Nef.ContractMethodDescriptor m)
    {
        if (m.Parameters.Count != 4) return false;
        string n = m.Name.ToLowerInvariant();
        if (n == "onoracleresponse") return true;
        // Permissive: "oracle" + "response" tokens, in either order, for non-canonical names.
        return n.Contains("oracle") && (n.Contains("response") || n.Contains("callback"));
    }

    private static string ParameterSymbolName(
        IReadOnlyList<Nef.ContractParameterDefinition> parameters,
        int index,
        string defaultIfMissing)
    {
        if (index < 0 || index >= parameters.Count) return defaultIfMissing;
        var p = parameters[index];
        return string.IsNullOrEmpty(p.Name) ? $"arg{index}" : $"arg_{p.Name}";
    }
}
