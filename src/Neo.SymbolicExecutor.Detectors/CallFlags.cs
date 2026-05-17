namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Neo N3 CallFlags bitmask values, mirroring src/Neo/SmartContract/CallFlags.cs upstream.
/// Centralized here so detector heuristics can refer to named bits and a shared "All" constant
/// instead of magic numbers (`0x0F`) scattered across the codebase. Bit semantics are stable
/// across the lifetime of the protocol; changing this requires a protocol fork.
/// </summary>
public static class CallFlags
{
    public const int None = 0x00;
    public const int ReadStates = 0x01;
    public const int WriteStates = 0x02;
    public const int AllowCall = 0x04;
    public const int AllowNotify = 0x08;

    /// <summary>States = ReadStates | WriteStates.</summary>
    public const int States = ReadStates | WriteStates;

    /// <summary>ReadOnly = ReadStates | AllowCall.</summary>
    public const int ReadOnly = ReadStates | AllowCall;

    /// <summary>The maximum-broad grant (all four bits set). Matches Neo.SmartContract.CallFlags.All.</summary>
    public const int All = ReadStates | WriteStates | AllowCall | AllowNotify;

    /// <summary>True iff three or more of the four defined bits are set (over-broad heuristic).</summary>
    public static bool IsBroad(int flags) =>
        System.Numerics.BitOperations.PopCount((uint)(flags & All)) >= 3;
}
