using System.Collections.Immutable;
using System.Numerics;
using Neo.SymbolicExecutor.Nef;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Verification;

public static partial class FormalVerifier
{
    private static bool IsNamedMethod(ContractMethodDescriptor method, string name) =>
        string.Equals(method.Name, name, StringComparison.OrdinalIgnoreCase);

    private static bool IsTotalSupplyMethod(ContractMethodDescriptor method) =>
        IsNamedMethod(method, "totalSupply")
        && IsIntegerSafeNoParameterMethod(method);

    private static bool IsNep17TransferMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-17")
        && string.Equals(method.Name, "transfer", StringComparison.OrdinalIgnoreCase)
        && IsNep17TransferMethodShape(method);

    private static bool IsNep17TransferMethodShape(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "transfer", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 4
        && HasStandardParameter(method.Parameters, 0, "from", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "to", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 2, "amount", type => IsType(type, "Integer"))
        && HasStandardParameter(method.Parameters, 3, "data", type => IsType(type, "Any"))
        && IsType(method.ReturnType, "Boolean")
        && !method.Safe;

    private static bool IsNep17LifecycleMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        IsNep17MintMethod(manifest, method)
        || IsNep17BurnMethod(manifest, method);

    private static bool IsNep17MintMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-17")
        && IsNamedMethod(method, "mint")
        && FindToParameter(method) >= 0
        && FindAmountParameter(method) >= 0
        && IsLifecycleMutationReturn(method)
        && !method.Safe;

    private static bool IsNep17BurnMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-17")
        && IsNamedMethod(method, "burn")
        && FindFromParameter(method) >= 0
        && FindAmountParameter(method) >= 0
        && IsLifecycleMutationReturn(method)
        && !method.Safe;

    private static bool IsLifecycleMutationReturn(ContractMethodDescriptor method) =>
        IsType(method.ReturnType, "Boolean")
        || IsType(method.ReturnType, "Void")
        || string.IsNullOrWhiteSpace(method.ReturnType);

    private static bool IsNep11LifecycleMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        IsNep11MintMethod(manifest, method)
        || IsNep11BurnMethod(manifest, method);

    private static bool IsNep11MintMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-11")
        && IsNamedMethod(method, "mint")
        && FindToParameter(method) >= 0
        && FindNep11TokenIdParameter(method) >= 0
        && IsLifecycleMutationReturn(method)
        && !method.Safe;

    private static bool IsNep11BurnMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-11")
        && IsNamedMethod(method, "burn")
        && FindNep11TokenIdParameter(method) >= 0
        && IsLifecycleMutationReturn(method)
        && !method.Safe;

    private static bool IsNep11TransferMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-11")
        && string.Equals(method.Name, "transfer", StringComparison.OrdinalIgnoreCase);

    private static bool IsNep11NonDivisibleTransferMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        IsNep11TransferMethod(manifest, method)
        && IsNep11NonDivisibleTransferMethodShape(method);

    private static bool IsNep11NonDivisibleTransferMethodShape(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "transfer", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 3
        && HasStandardParameter(method.Parameters, 0, "to", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "tokenId", IsByteStringLike)
        && HasStandardParameter(method.Parameters, 2, "data", type => IsType(type, "Any"))
        && IsType(method.ReturnType, "Boolean")
        && !method.Safe;

    private static bool IsNep11DivisibleTransferMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        IsNep11TransferMethod(manifest, method)
        && IsNep11DivisibleTransferMethodShape(method);

    private static bool IsNep11DivisibleTransferMethodShape(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "transfer", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 5
        && HasStandardParameter(method.Parameters, 0, "from", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "to", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 2, "amount", type => IsType(type, "Integer"))
        && HasStandardParameter(method.Parameters, 3, "tokenId", IsByteStringLike)
        && HasStandardParameter(method.Parameters, 4, "data", type => IsType(type, "Any"))
        && IsType(method.ReturnType, "Boolean")
        && !method.Safe;

    private static bool IsNep24RoyaltyInfoMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-24")
        && IsNep24RoyaltyInfoMethod(method);

    private static bool IsNep27ReceiverCallbackMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-27")
        && IsNep27PaymentCallbackMethod(method);

    private static bool IsNep26ReceiverCallbackMethod(ContractManifest manifest, ContractMethodDescriptor method) =>
        manifest.DeclaresStandard("NEP-26")
        && IsNep26PaymentCallbackMethod(method);

    private static ContractMethodDescriptor? FindAbiMethod(ContractManifest manifest, string name) =>
        manifest.Abi.Methods.FirstOrDefault(m => string.Equals(m.Name, name, StringComparison.Ordinal));

    private static ContractMethodDescriptor? FindAbiMethod(
        ContractManifest manifest,
        string name,
        Func<ContractMethodDescriptor, bool> predicate) =>
        manifest.Abi.Methods.FirstOrDefault(
            m => string.Equals(m.Name, name, StringComparison.Ordinal)
                && predicate(m));

    private static bool IsStringSafeNoParameterMethod(ContractMethodDescriptor method) =>
        method.Parameters.Count == 0
        && IsType(method.ReturnType, "String")
        && method.Safe;

    private static bool IsIntegerSafeNoParameterMethod(ContractMethodDescriptor method) =>
        method.Parameters.Count == 0
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep17BalanceOfMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "balanceOf", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "account", IsStrictHash160)
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep24RoyaltyInfoMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "royaltyInfo", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 3
        && HasStandardParameter(method.Parameters, 0, "tokenId", IsByteStringLike)
        && HasStandardParameter(method.Parameters, 1, "royaltyToken", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 2, "salePrice", type => IsType(type, "Integer"))
        && IsType(method.ReturnType, "Array")
        && method.Safe;

    private static bool IsNep27PaymentCallbackMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "onNEP17Payment", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 3
        && HasStandardParameter(method.Parameters, 0, "from", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "amount", type => IsType(type, "Integer"))
        && HasStandardParameter(method.Parameters, 2, "data", type => IsType(type, "Any"))
        && IsType(method.ReturnType, "Void");

    private static bool IsNep26PaymentCallbackMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "onNEP11Payment", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 4
        && HasStandardParameter(method.Parameters, 0, "from", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "amount", type => IsType(type, "Integer"))
        && HasStandardParameter(method.Parameters, 2, "tokenId", IsNep26TokenIdType)
        && HasStandardParameter(method.Parameters, 3, "data", type => IsType(type, "Any"))
        && IsType(method.ReturnType, "Void");

    private static bool IsNep11NonDivisibleOwnerOfMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "ownerOf", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "tokenId", IsByteStringLike)
        && IsStrictHash160(method.ReturnType)
        && method.Safe;

    private static bool IsNep11DivisibleOwnerOfMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "ownerOf", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "tokenId", IsByteStringLike)
        && IsType(method.ReturnType, "InteropInterface")
        && method.Safe;

    private static bool IsNep11NonDivisibleBalanceOfMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "balanceOf", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "owner", IsStrictHash160)
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep11DivisibleBalanceOfMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "balanceOf", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 2
        && HasStandardParameter(method.Parameters, 0, "owner", IsStrictHash160)
        && HasStandardParameter(method.Parameters, 1, "tokenId", IsByteStringLike)
        && IsType(method.ReturnType, "Integer")
        && method.Safe;

    private static bool IsNep11TokensOfMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "tokensOf", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "owner", IsStrictHash160)
        && IsType(method.ReturnType, "InteropInterface")
        && method.Safe;

    private static bool IsNep11PropertiesMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "properties", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 1
        && HasStandardParameter(method.Parameters, 0, "tokenId", IsByteStringLike)
        && IsType(method.ReturnType, "Map")
        && method.Safe;

    private static bool IsNep11TokensMethod(ContractMethodDescriptor method) =>
        string.Equals(method.Name, "tokens", StringComparison.OrdinalIgnoreCase)
        && method.Parameters.Count == 0
        && IsType(method.ReturnType, "InteropInterface")
        && method.Safe;

    // Review fix (#74): delegate to the shared Nef.AbiTypeMatching source of truth.
    private static bool IsType(string actual, string expected) =>
        AbiTypeMatching.IsType(actual, expected);

    private static bool HasStandardParameter(
        IReadOnlyList<ContractParameterDefinition> parameters,
        int index,
        string name,
        Func<string, bool> typeMatches) =>
        parameters.Count > index
        && string.Equals(parameters[index].Name, name, StringComparison.Ordinal)
        && typeMatches(parameters[index].Type);

    private static bool TryFindNamedParameterSymbol(
        ContractMethodDescriptor method,
        string name,
        Func<string, bool> typeMatches,
        out string symbol)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            var parameter = method.Parameters[i];
            if (string.Equals(parameter.Name, name, StringComparison.OrdinalIgnoreCase)
                && typeMatches(parameter.Type))
            {
                symbol = SymbolicEngine.MethodEntryArgSymbolName(parameter.Name, i);
                return true;
            }
        }

        symbol = "";
        return false;
    }

    private static int FindFromParameter(ContractMethodDescriptor method)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (string.Equals(method.Parameters[i].Name, "from", StringComparison.OrdinalIgnoreCase)
                && IsHash160Like(method.Parameters[i].Type))
                return i;
        }

        if (method.Parameters.Count > 0 && IsHash160Like(method.Parameters[0].Type))
            return 0;
        return -1;
    }

    private static int FindToParameter(ContractMethodDescriptor method)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (string.Equals(method.Parameters[i].Name, "to", StringComparison.OrdinalIgnoreCase)
                && IsHash160Like(method.Parameters[i].Type))
                return i;
        }

        if (method.Parameters.Count > 1 && IsHash160Like(method.Parameters[1].Type))
            return 1;
        if (method.Parameters.Count == 3
            && IsHash160Like(method.Parameters[0].Type)
            && IsByteStringLike(method.Parameters[1].Type))
            return 0;
        return -1;
    }

    private static int FindAmountParameter(ContractMethodDescriptor method)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (string.Equals(method.Parameters[i].Name, "amount", StringComparison.OrdinalIgnoreCase)
                && string.Equals(method.Parameters[i].Type, "Integer", StringComparison.OrdinalIgnoreCase))
                return i;
        }

        if (method.Parameters.Count > 2
            && string.Equals(method.Parameters[2].Type, "Integer", StringComparison.OrdinalIgnoreCase))
            return 2;
        return -1;
    }

    private static int FindDataParameter(ContractMethodDescriptor method)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (string.Equals(method.Parameters[i].Name, "data", StringComparison.OrdinalIgnoreCase)
                && string.Equals(method.Parameters[i].Type, "Any", StringComparison.OrdinalIgnoreCase))
                return i;
        }

        if (method.Parameters.Count > 4
            && string.Equals(method.Parameters[4].Type, "Any", StringComparison.OrdinalIgnoreCase))
            return 4;
        if (method.Parameters.Count > 3
            && string.Equals(method.Parameters[3].Type, "Any", StringComparison.OrdinalIgnoreCase))
            return 3;
        if (method.Parameters.Count > 2
            && string.Equals(method.Parameters[2].Type, "Any", StringComparison.OrdinalIgnoreCase))
            return 2;
        return -1;
    }

    private static int FindNep11TokenIdParameter(ContractMethodDescriptor method)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (string.Equals(method.Parameters[i].Name, "tokenId", StringComparison.OrdinalIgnoreCase)
                && IsByteStringLike(method.Parameters[i].Type))
                return i;
        }

        if (method.Parameters.Count > 3 && IsByteStringLike(method.Parameters[3].Type))
            return 3;
        if (method.Parameters.Count > 1 && IsByteStringLike(method.Parameters[1].Type))
            return 1;
        return -1;
    }

    private static int FindNamedNep11TokenIdParameter(ContractMethodDescriptor method)
    {
        for (int i = 0; i < method.Parameters.Count; i++)
        {
            if (string.Equals(method.Parameters[i].Name, "tokenId", StringComparison.OrdinalIgnoreCase)
                && IsByteStringLike(method.Parameters[i].Type))
                return i;
        }

        return -1;
    }

    private static bool IsNep11TokenIdLengthBoundedMethod(ContractManifest manifest, ContractMethodDescriptor method)
    {
        if (!manifest.DeclaresStandard("NEP-11") || FindNamedNep11TokenIdParameter(method) < 0)
            return false;

        return IsNep11NonDivisibleOwnerOfMethod(method)
            || IsNep11DivisibleOwnerOfMethod(method)
            || IsNep11DivisibleBalanceOfMethod(method)
            || IsNep11PropertiesMethod(method)
            || IsNep11LifecycleMethod(manifest, method);
    }

    private static bool IsHash160Like(string type) =>
        string.Equals(type, "Hash160", StringComparison.OrdinalIgnoreCase)
        || string.Equals(type, "ByteArray", StringComparison.OrdinalIgnoreCase)
        || string.Equals(type, "ByteString", StringComparison.OrdinalIgnoreCase);

    private static bool IsStrictHash160(string type) =>
        AbiTypeMatching.IsStrictHash160(type);

    private static bool IsByteStringLike(string type) =>
        AbiTypeMatching.IsByteStringLike(type);

    private static bool IsNep26TokenIdType(string type) =>
        IsByteStringLike(type)
        || string.Equals(type, "String", StringComparison.OrdinalIgnoreCase);
}
