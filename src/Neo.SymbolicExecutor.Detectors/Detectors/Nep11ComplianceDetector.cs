using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// NEP-11 NFT ABI compliance — new detector per audit coverage gap #1 (zero coverage despite
/// identical structural risk to NEP-17).
///
/// NEP-11 required methods: symbol, decimals, totalSupply, balanceOf, ownerOf, tokensOf,
/// transfer. The balanceOf/ownerOf/transfer trio must match either the non-divisible or
/// divisible NEP-11 shape. Optional tokens/properties methods are checked when declared.
/// Events: Transfer(from: Hash160, to: Hash160, amount: Integer, tokenId: ByteString-compatible).
/// </summary>
public sealed class Nep11ComplianceDetector : BaseDetector
{
    public override string Name => "nep11_compliance";
    public override Severity DefaultSeverity => Severity.High;
    public override double DefaultConfidence => 0.95;

    private static readonly string[] RequiredMethods =
    {
        "symbol",
        "decimals",
        "totalSupply",
        "balanceOf",
        "ownerOf",
        "tokensOf",
        "transfer",
    };

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var m = context.Manifest;
        if (m is null) yield break;
        if (!m.DeclaresStandard("NEP-11")) yield break;

        foreach (var name in RequiredMethods)
        {
            if (m.FindMethod(name) is null)
            {
                yield return MakeFinding(
                    title: $"NEP-11 missing required method: {name}",
                    description: $"Contract declares NEP-11 but does not define a `{name}` method.",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep11", "missing-method" });
            }
        }

        foreach (var finding in CheckRequiredMethodShape(
            m,
            "symbol",
            IsStringSafeNoParameterMethod,
            "symbol(): String safe=true"))
        {
            yield return finding;
        }

        foreach (var finding in CheckRequiredMethodShape(
            m,
            "decimals",
            IsIntegerSafeNoParameterMethod,
            "decimals(): Integer safe=true"))
        {
            yield return finding;
        }

        foreach (var finding in CheckRequiredMethodShape(
            m,
            "totalSupply",
            IsIntegerSafeNoParameterMethod,
            "totalSupply(): Integer safe=true"))
        {
            yield return finding;
        }

        foreach (var finding in CheckRequiredMethodShape(
            m,
            "tokensOf",
            IsNep11TokensOfMethod,
            "tokensOf(Hash160 owner): InteropInterface safe=true"))
        {
            yield return finding;
        }

        bool nonDivisible =
            HasMethod(m, "balanceOf", IsNep11NonDivisibleBalanceOfMethod)
            && HasMethod(m, "ownerOf", IsNep11NonDivisibleOwnerOfMethod)
            && HasMethod(m, "transfer", IsNep11NonDivisibleTransferMethodShape);
        bool divisible =
            HasMethod(m, "balanceOf", IsNep11DivisibleBalanceOfMethod)
            && HasMethod(m, "ownerOf", IsNep11DivisibleOwnerOfMethod)
            && HasMethod(m, "transfer", IsNep11DivisibleTransferMethodShape);
        if (!nonDivisible && !divisible
            && HasMethod(m, "balanceOf")
            && HasMethod(m, "ownerOf")
            && HasMethod(m, "transfer"))
        {
            yield return MakeFinding(
                title: "NEP-11 balanceOf/ownerOf/transfer methods have wrong standard shape",
                description: "NEP-11 must match either the non-divisible ABI (balanceOf(owner), ownerOf(tokenId): Hash160, transfer(to, tokenId, data)) or the divisible ABI (balanceOf(owner, tokenId), ownerOf(tokenId): InteropInterface, transfer(from, to, amount, tokenId, data)).",
                offset: FirstMethodOffset(m, "transfer"),
                severity: Severity.High,
                state: null,
                tags: new[] { "nep11", "method-shape" });
        }

        if (HasMethod(m, "properties") && !HasMethod(m, "properties", IsNep11PropertiesMethod))
        {
            yield return MakeFinding(
                title: "NEP-11 optional method properties has wrong parameter or return shape",
                description: "properties must declare (ByteString-compatible tokenId): Map safe=true when present.",
                offset: FirstMethodOffset(m, "properties"),
                severity: Severity.High,
                state: null,
                tags: new[] { "nep11", "method-shape" });
        }

        if (HasMethod(m, "tokens") && !HasMethod(m, "tokens", IsNep11TokensMethod))
        {
            yield return MakeFinding(
                title: "NEP-11 optional method tokens has wrong parameter or return shape",
                description: "tokens must declare (): InteropInterface safe=true when present.",
                offset: FirstMethodOffset(m, "tokens"),
                severity: Severity.High,
                state: null,
                tags: new[] { "nep11", "method-shape" });
        }

        var transferEvent = m.Abi.Events.FirstOrDefault(e => e.Name == "Transfer");
        if (transferEvent is null)
        {
            yield return MakeFinding(
                title: "NEP-11 missing Transfer event",
                description: "NEP-11 contract must declare the Transfer event for explorer/wallet compatibility.",
                offset: 0,
                severity: Severity.High,
                state: null,
                tags: new[] { "nep11", "missing-event" });
        }
        else
        {
            var p = transferEvent.Parameters;
            bool ok = p.Count == 4
                && HasStandardParameter(p, 0, "from", IsStrictHash160)
                && HasStandardParameter(p, 1, "to", IsStrictHash160)
                && HasStandardParameter(p, 2, "amount", type => IsType(type, "Integer"))
                && HasStandardParameter(p, 3, "tokenId", IsByteString);
            if (!ok)
            {
                yield return MakeFinding(
                    title: "NEP-11 Transfer event has wrong parameter shape",
                    description: "Transfer event must declare exactly (Hash160 from, Hash160 to, Integer amount, ByteString-compatible tokenId).",
                    offset: 0,
                    severity: Severity.High,
                    state: null,
                    tags: new[] { "nep11", "event-shape" });
            }
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
            title: $"NEP-11 method `{name}` has wrong parameter, return, or safe shape",
            description: $"Method `{name}` must declare {expectedShape}.",
            offset: FirstMethodOffset(manifest, name),
            severity: Severity.High,
            state: null,
            tags: new[] { "nep11", "method-shape" });
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

    private static bool IsNep11NonDivisibleTransferMethodShape(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 3
        && HasStandardParameter(method.Parameters, 0, "to", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "tokenId", IsByteString)
        && HasStandardParameter(method.Parameters, 2, "data", type => IsType(type, "Any"))
        && IsType(method.ReturnType, "Boolean")
        && !method.Safe;

    private static bool IsNep11DivisibleTransferMethodShape(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 5
        && HasStandardParameter(method.Parameters, 0, "from", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "to", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 2, "amount", type => IsType(type, "Integer"))
        && HasStandardParameter(method.Parameters, 3, "tokenId", IsByteString)
        && HasStandardParameter(method.Parameters, 4, "data", type => IsType(type, "Any"))
        && IsType(method.ReturnType, "Boolean")
        && !method.Safe;

    private static bool IsNep11NonDivisibleOwnerOfMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "tokenId", IsByteString)
        && IsStrictHash160(method.ReturnType)
        && method.Safe;

    private static bool IsNep11DivisibleOwnerOfMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "tokenId", IsByteString)
        && IsType(method.ReturnType, "InteropInterface")
        && method.Safe;

    private static bool IsNep11NonDivisibleBalanceOfMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "owner", IsStrictHash160)
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep11DivisibleBalanceOfMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 2
        && HasStandardParameter(method.Parameters, 0, "owner", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "tokenId", IsByteString)
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep11TokensOfMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "owner", IsStrictHash160)
        && IsType(method.ReturnType, "InteropInterface")
        && method.Safe;

    private static bool IsNep11PropertiesMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "tokenId", IsByteString)
        && IsType(method.ReturnType, "Map")
        && method.Safe;

    private static bool IsNep11TokensMethod(Nef.ContractMethodDescriptor method) =>
        method.Parameters.Count == 0
        && IsType(method.ReturnType, "InteropInterface")
        && method.Safe;

    // Round-2 fix (#20): validate parameter TYPE and arity only — NOT the author's parameter
    // identifier. NEP standards fix method names, parameter types, arity, return type, and the Safe
    // flag, but NOT the spelling of parameter names; comparing parameters[index].Name produced false
    // positives on spec-compliant contracts that merely renamed a parameter (e.g. `owner` -> `account`).
    // The `name` argument is retained for call-site documentation of the canonical NEP name.
    private static bool HasStandardParameter(
        IReadOnlyList<Nef.ContractParameterDefinition> parameters,
        int index,
        string name,
        System.Func<string, bool> typeMatches) =>
        parameters.Count > index
        && typeMatches(parameters[index].Type);

    private static bool IsStrictHash160(string type) =>
        IsType(type, "Hash160");

    private static bool IsByteString(string type) =>
        IsType(type, "ByteString") || IsType(type, "ByteArray");

    // Review fix (#74): shared Nef.AbiTypeMatching source of truth (was a per-detector copy).
    private static bool IsType(string actual, string expected) =>
        Nef.AbiTypeMatching.IsType(actual, expected);
}
