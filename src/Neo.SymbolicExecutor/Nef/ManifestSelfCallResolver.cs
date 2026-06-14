using System;
using System.Linq;

namespace Neo.SymbolicExecutor.Nef;

/// <summary>
/// Builds engine self-call resolvers from manifest ABI metadata.
/// </summary>
public static class ManifestSelfCallResolver
{
    public static ContractSelfCallResolver Build(ContractManifest manifest) =>
        (method, argumentCount) =>
        {
            var matches = manifest.Abi.Methods
                .Where(m => string.Equals(m.Name, method, StringComparison.Ordinal)
                    && m.Parameters.Count == argumentCount)
                .ToArray();
            if (matches.Length != 1)
                return null;

            var target = matches[0];
            return new ContractSelfCallTarget(
                target.Name,
                target.Offset,
                target.Parameters.Count,
                !IsAbiType(target.ReturnType, "Void"),
                target.Safe);
        };

    private static bool IsAbiType(string actual, string expected) =>
        string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase);
}
