using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-17 fungible-token ABI compliance:
///   methods: symbol(): String safe, decimals(): Integer safe, totalSupply(): Integer safe,
///            balanceOf(Hash160 account): Integer safe,
///            transfer(Hash160 from, Hash160 to, Integer amount, Any data): Boolean !safe
///   events:  Transfer(from: Hash160, to: Hash160, amount: Integer)
///
/// Only fires when the manifest declares NEP-17 in supportedstandards.
///
/// Review fix (#20): brought to parity with <see cref="Nep11ComplianceDetector"/> — the view
/// methods now have their full return-type/parameter shapes validated (previously only presence
/// and the safe flag were checked), and the transfer method shape additionally requires the 4th
/// <c>data</c> parameter, a Boolean return type, and <c>safe=false</c>. Mirrors the predicate
/// style used by the NEP-11 detector.
/// </summary>
public sealed class Nep17ComplianceDetector : BaseDetector
{
    public override string Name => "nep17_compliance";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.95;

    private static readonly string[] RequiredMethods = { "symbol", "decimals", "totalSupply", "balanceOf", "transfer" };
    private static readonly string[] RequiredViewMethods = { "symbol", "decimals", "totalSupply", "balanceOf" };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var m = context.Manifest;
        if (m is null) yield break;
        if (!m.DeclaresStandard("NEP-17")) yield break;

        foreach (var name in RequiredMethods)
        {
            if (m.FindMethod(name) is null)
            {
                yield return MakeFinding(
                    title: $"NEP-17 missing required method: {name}",
                    description: $"Contract declares NEP-17 but does not define a `{name}` method.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep17", "missing-method" });
            }
        }
        foreach (var name in RequiredViewMethods)
        {
            var method = m.FindMethod(name);
            if (method is { Safe: false })
            {
                yield return MakeFinding(
                    title: $"NEP-17 view method `{name}` should be safe=true",
                    description: $"Method `{name}` must declare safe=true so wallets can call it without approval prompts.",
                    offset: method.Offset,
                    severity: Severity.Medium,
                    state: null,
                    tags: new[] { "nep17", "safe-flag" });
            }
        }

        // Review fix (#20): full method-shape validation, mirroring Nep11ComplianceDetector.
        foreach (var finding in CheckRequiredMethodShape(
            m, "symbol", IsStringSafeNoParameterMethod, "symbol(): String safe=true"))
            yield return finding;

        foreach (var finding in CheckRequiredMethodShape(
            m, "decimals", IsIntegerSafeNoParameterMethod, "decimals(): Integer safe=true"))
            yield return finding;

        foreach (var finding in CheckRequiredMethodShape(
            m, "totalSupply", IsIntegerSafeNoParameterMethod, "totalSupply(): Integer safe=true"))
            yield return finding;

        foreach (var finding in CheckRequiredMethodShape(
            m, "balanceOf", IsNep17BalanceOfMethod, "balanceOf(Hash160 account): Integer safe=true"))
            yield return finding;

        // Transfer event presence + parameter shape.
        var transferEvent = m.Abi.Events.FirstOrDefault(e => e.Name == "Transfer");
        if (transferEvent is null)
        {
            yield return MakeFinding(
                title: "NEP-17 missing Transfer event",
                description: "Contract declares NEP-17 but the Transfer event is not declared in the manifest.",
                offset: 0,
                severity: Severity.High,
                state: null,
                tags: new[] { "nep17", "missing-event" });
        }
        else
        {
            var p = transferEvent.Parameters;
            bool ok = p.Count == 3
                && IsType(p[0].Type, "Hash160")
                && IsType(p[1].Type, "Hash160")
                && IsType(p[2].Type, "Integer");
            if (!ok)
            {
                yield return MakeFinding(
                    title: "NEP-17 Transfer event has wrong parameter shape",
                    description: "Transfer event must declare exactly 3 parameters: Hash160 from, Hash160 to, Integer amount.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep17", "event-shape" });
            }
        }

        // transfer signature shape: (Hash160 from, Hash160 to, Integer amount, Any data): Boolean !safe.
        if (HasMethod(m, "transfer") && !HasMethod(m, "transfer", IsNep17TransferMethodShape))
        {
            yield return MakeFinding(
                title: "NEP-17 transfer parameter shape is wrong",
                description: "transfer must declare (Hash160 from, Hash160 to, Integer amount, Any data): Boolean safe=false.",
                offset: FirstMethodOffset(m, "transfer"),
                severity: Severity.High,
                state: null,
                tags: new[] { "nep17", "method-shape" });
        }
    }

    private IEnumerable<Finding> CheckRequiredMethodShape(
        Nef.ContractManifest manifest,
        string name,
        System.Func<Nef.ContractMethodDescriptor, bool> predicate,
        string expectedShape)
    {
        if (!HasMethod(manifest, name) || HasMethod(manifest, name, predicate))
            yield break;

        yield return MakeFinding(
            title: $"NEP-17 method `{name}` has wrong parameter, return, or safe shape",
            description: $"Method `{name}` must declare {expectedShape}.",
            offset: FirstMethodOffset(manifest, name),
            severity: Severity.High,
            state: null,
            tags: new[] { "nep17", "method-shape" });
    }

    private static bool HasMethod(Nef.ContractManifest manifest, string name) =>
        manifest.Abi.Methods.Any(m => IsNamedMethod(m, name));

    private static bool HasMethod(
        Nef.ContractManifest manifest,
        string name,
        System.Func<Nef.ContractMethodDescriptor, bool> predicate) =>
        manifest.Abi.Methods.Any(m => IsNamedMethod(m, name) && predicate(m));

    private static int FirstMethodOffset(Nef.ContractManifest manifest, string name) =>
        manifest.Abi.Methods.FirstOrDefault(m => IsNamedMethod(m, name))?.Offset ?? 0;

    private static bool IsNamedMethod(Nef.ContractMethodDescriptor method, string name) =>
        string.Equals(method.Name, name, System.StringComparison.Ordinal);

    private static bool IsStringSafeNoParameterMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 0
        && IsType(method.ReturnType, "String")
        && method.Safe;

    private static bool IsIntegerSafeNoParameterMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 0
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep17BalanceOfMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 1
        && IsType(method.Parameters[0].Type, "Hash160")
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep17TransferMethodShape(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 4
        && IsType(method.Parameters[0].Type, "Hash160")
        && IsType(method.Parameters[1].Type, "Hash160")
        && IsType(method.Parameters[2].Type, "Integer")
        && IsType(method.Parameters[3].Type, "Any")
        && IsType(method.ReturnType, "Boolean")
        && !method.Safe;

    // Review fix (#74): shared Nef.AbiTypeMatching source of truth (was a per-detector copy).
    private static bool IsType(string? actual, string expected) =>
        Nef.AbiTypeMatching.IsType(actual, expected);
}
