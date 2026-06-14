using System;

namespace Neo.SymbolicExecutor.Nef;

/// <summary>
/// Review fix (#74): single source of truth for ABI parameter/return type-name matching, shared by
/// the <c>FormalVerifier</c> and the NEP-compliance detectors. Previously each of those carried a
/// near-identical private copy of these predicates (IsType / IsStrictHash160 / IsByteStringLike),
/// a divergent-fix risk if one copy were corrected and the others not. Type names are matched
/// case-insensitively per Neo manifest semantics; a null actual type is treated as no-match.
/// </summary>
public static class AbiTypeMatching
{
    public static bool IsType(string? actual, string expected) =>
        string.Equals(actual ?? string.Empty, expected, StringComparison.OrdinalIgnoreCase);

    public static bool IsStrictHash160(string? type) => IsType(type, "Hash160");

    public static bool IsByteStringLike(string? type) =>
        IsType(type, "ByteString") || IsType(type, "ByteArray");
}
