namespace Neo.SymbolicExecutor;

/// <summary>
/// Sort discriminator for symbolic expressions, mirroring the NeoVM stack-item type lattice.
/// </summary>
public enum Sort
{
    Unknown = 0,
    Int = 1,
    Bool = 2,
    Bytes = 3,
    Null = 4,
    Buffer = 5,
    Array = 6,
    Struct = 7,
    Map = 8,
    Pointer = 9,
    InteropInterface = 10,
}

public static class SortExtensions
{
    public static bool IsCollection(this Sort sort) =>
        sort is Sort.Array or Sort.Struct or Sort.Map;

    public static bool IsHeapBacked(this Sort sort) =>
        sort is Sort.Array or Sort.Struct or Sort.Map or Sort.Buffer;

    public static bool IsPrimitive(this Sort sort) =>
        sort is Sort.Int or Sort.Bool or Sort.Bytes or Sort.Null;

    /// <summary>
    /// True if two sorts can be coerced for cross-type equality per NeoVM's
    /// PrimitiveType.GetSpan().SequenceEqual semantics. Per audit HIGH-2:
    /// Integer(0) and ByteString(b"") are equal as map keys.
    /// </summary>
    public static bool IsCrossTypeEqualityCandidate(this Sort sort) =>
        sort is Sort.Int or Sort.Bool or Sort.Bytes;
}
