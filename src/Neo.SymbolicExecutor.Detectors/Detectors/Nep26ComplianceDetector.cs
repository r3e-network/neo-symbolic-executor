using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-26 non-fungible-token receiver callback ABI compliance:
///   method: onNEP11Payment(Hash160 from, Integer amount, ByteString-compatible tokenId, Any data): Void
///
/// Only fires when the manifest declares NEP-26 in supportedstandards.
/// </summary>
public sealed class Nep26ComplianceDetector : BaseDetector
{
    public override string Name => "nep26_compliance";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.95;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var manifest = context.Manifest;
        if (manifest is null) yield break;
        if (!manifest.DeclaresStandard("NEP-26")) yield break;

        var callback = FindMethod(manifest, "onNEP11Payment", IsNep11PaymentShape);
        if (callback is not null)
            yield break;

        var firstCallback = FindMethod(manifest, "onNEP11Payment");
        if (firstCallback is null)
        {
            yield return MakeFinding(
                title: "NEP-26 missing required method: onNEP11Payment",
                description: "Contract declares NEP-26 but does not define `onNEP11Payment(Hash160 from, Integer amount, ByteString-compatible tokenId, Any data): Void`.",
                offset: 0,
                severity: Severity.High,
                state: null,
                tags: new[] { "nep26", "missing-method" });
            yield break;
        }

        yield return MakeFinding(
            title: "NEP-26 onNEP11Payment method has wrong parameter or return shape",
            description: "onNEP11Payment must declare (Hash160 from, Integer amount, ByteString-compatible tokenId, Any data): Void.",
            offset: firstCallback.Offset,
            severity: Severity.High,
            state: null,
            tags: new[] { "nep26", "method-shape" });
    }

    private static bool IsNep11PaymentShape(Nef.ContractMethodDescriptor method)
    {
        var parameters = method.Parameters;
        return parameters.Count == 4
            && HasParameter(parameters, 0, "from", type => IsType(type, "Hash160"))
            && HasParameter(parameters, 1, "amount", type => IsType(type, "Integer"))
            && HasParameter(parameters, 2, "tokenId", IsByteString)
            && HasParameter(parameters, 3, "data", type => IsType(type, "Any"))
            && IsType(method.ReturnType, "Void");
    }

    private static bool IsByteString(string type) =>
        IsType(type, "ByteString") || IsType(type, "ByteArray") || IsType(type, "String");

    // Round-2 fix (#20): validate parameter TYPE and arity only — NOT the author's parameter
    // identifier. NEP-26 fixes the method name, parameter types, arity, and return type, but not the
    // spelling of parameter names; comparing parameters[index].Name produced false positives on
    // spec-compliant contracts that renamed a parameter. The `name` argument is retained for
    // call-site documentation of the canonical NEP name.
    private static bool HasParameter(
        IReadOnlyList<Nef.ContractParameterDefinition> parameters,
        int index,
        string name,
        System.Func<string, bool> typeMatches) =>
        parameters.Count > index
        && typeMatches(parameters[index].Type);

    // Review fix (#74): shared Nef.AbiTypeMatching source of truth (was a per-detector copy).
    private static bool IsType(string actual, string expected) =>
        Nef.AbiTypeMatching.IsType(actual, expected);

    private static Nef.ContractMethodDescriptor? FindMethod(
        Nef.ContractManifest manifest,
        string name,
        System.Func<Nef.ContractMethodDescriptor, bool>? predicate = null) =>
        manifest.Abi.Methods.FirstOrDefault(
            method => string.Equals(method.Name, name, System.StringComparison.Ordinal)
                && (predicate?.Invoke(method) ?? true));
}
