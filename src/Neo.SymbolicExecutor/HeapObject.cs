using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Heap-backed compound value with reference semantics. Multiple stack values can
/// reference the same object via <see cref="HeapRef"/>; mutations are visible to all
/// holders within the same execution state. State cloning does NOT deep-copy the heap
/// up-front (v0.8.0 copy-on-write refactor) — instead each shared HeapObject is flagged
/// via <see cref="IsShared"/> and copied lazily on first write through
/// <see cref="Heap.GetForWrite{T}"/>. Net behavior preserved per
/// <c>HeapCloneIsolationTests</c>; allocations on branch-heavy contracts drop ~4×.
/// </summary>
public abstract class HeapObject
{
    public Sort Sort { get; }
    public int Id { get; init; }

    /// <summary>
    /// Monotonically becomes true when <see cref="Heap.Clone"/> shares this instance with a
    /// freshly-cloned heap. Stays true thereafter — any mutation site that wants to write
    /// must first request a heap-private copy via <see cref="Heap.GetForWrite{T}"/>. The
    /// new copy's IsShared is false; the original retains its shared flag for any other
    /// heap that still aliases it.
    /// </summary>
    internal bool IsShared { get; set; }

    protected HeapObject(Sort sort, int id) { Sort = sort; Id = id; }

    public abstract HeapObject Clone(int newId);
}

public sealed class ArrayObject : HeapObject
{
    public List<SymbolicValue> Items { get; }
    public bool IsSymbolicOpen { get; }
    public int MinCount { get; }
    public int OpenSizeOffset { get; set; }
    public List<(SymbolicValue Key, SymbolicValue Value)> OpenWrites { get; }

    public ArrayObject(
        int id,
        IEnumerable<SymbolicValue>? items = null,
        bool isSymbolicOpen = false,
        int? minCount = null,
        int openSizeOffset = 0,
        IEnumerable<(SymbolicValue Key, SymbolicValue Value)>? openWrites = null) : base(Sort.Array, id)
    {
        Items = items?.ToList() ?? new List<SymbolicValue>();
        IsSymbolicOpen = isSymbolicOpen;
        MinCount = isSymbolicOpen
            ? System.Math.Max(0, minCount ?? 0)
            : Items.Count;
        OpenSizeOffset = openSizeOffset;
        OpenWrites = openWrites?.ToList() ?? new List<(SymbolicValue Key, SymbolicValue Value)>();
    }

    public override HeapObject Clone(int newId) => new ArrayObject(newId, Items, IsSymbolicOpen, MinCount, OpenSizeOffset, OpenWrites);
}

public sealed class StructObject : HeapObject
{
    public List<SymbolicValue> Fields { get; }
    public bool IsSymbolicOpen { get; }
    public int MinCount { get; }
    public int OpenSizeOffset { get; set; }
    public List<(SymbolicValue Key, SymbolicValue Value)> OpenWrites { get; }

    public StructObject(
        int id,
        IEnumerable<SymbolicValue>? fields = null,
        bool isSymbolicOpen = false,
        int? minCount = null,
        int openSizeOffset = 0,
        IEnumerable<(SymbolicValue Key, SymbolicValue Value)>? openWrites = null) : base(Sort.Struct, id)
    {
        Fields = fields?.ToList() ?? new List<SymbolicValue>();
        IsSymbolicOpen = isSymbolicOpen;
        MinCount = isSymbolicOpen
            ? System.Math.Max(0, minCount ?? 0)
            : Fields.Count;
        OpenSizeOffset = openSizeOffset;
        OpenWrites = openWrites?.ToList() ?? new List<(SymbolicValue Key, SymbolicValue Value)>();
    }

    public override HeapObject Clone(int newId) => new StructObject(newId, Fields, IsSymbolicOpen, MinCount, OpenSizeOffset, OpenWrites);
}

public sealed class MapObject : HeapObject
{
    /// <summary>
    /// Entries are kept as a list of (key, value) pairs to preserve NeoVM map semantics where the
    /// original-key identity is retained on overwrite (audit LOW-4) and to allow symbolic-key
    /// branching when concrete equality cannot be decided.
    /// </summary>
    public List<(SymbolicValue Key, SymbolicValue Value)> Entries { get; }

    /// <summary>
    /// True for ABI method-entry maps that represent an unknown runtime argument. Contract-created
    /// NEWMAP values stay closed/concrete, but an external Map parameter can contain keys the
    /// seed corpus did not enumerate, so lookups may conservatively materialize symbolic values.
    /// </summary>
    public bool IsSymbolicOpen { get; }
    public List<MapOpenUpdate> OpenUpdates { get; }

    public MapObject(
        int id,
        IEnumerable<(SymbolicValue, SymbolicValue)>? entries = null,
        bool isSymbolicOpen = false,
        IEnumerable<MapOpenUpdate>? openUpdates = null) : base(Sort.Map, id)
    {
        Entries = entries?.ToList() ?? new List<(SymbolicValue, SymbolicValue)>();
        IsSymbolicOpen = isSymbolicOpen;
        OpenUpdates = openUpdates?.ToList() ?? new List<MapOpenUpdate>();
    }

    public override HeapObject Clone(int newId) => new MapObject(newId, Entries, IsSymbolicOpen, OpenUpdates);
}

public sealed record MapOpenUpdate(SymbolicValue Key, SymbolicValue Value, bool IsRemove);

public sealed class BufferObject : HeapObject
{
    /// <summary>
    /// A buffer with potentially symbolic byte content. Concrete bytes when known; for symbolic
    /// bytes the cell holds an <see cref="Expression"/> of sort Int (treated as a byte 0..255).
    /// </summary>
    public List<Expression> Cells { get; }
    public bool IsSymbolicOpen { get; }
    public int MinLength { get; }
    public Expression? SymbolicLength { get; }
    public Expression? SourceBytes { get; }
    public List<(SymbolicValue Key, SymbolicValue Value)> OpenWrites { get; }

    public BufferObject(int id, int length) : base(Sort.Buffer, id)
    {
        Cells = new List<Expression>(length);
        for (int i = 0; i < length; i++) Cells.Add(Expr.Int(0));
        IsSymbolicOpen = false;
        MinLength = Cells.Count;
        OpenWrites = new List<(SymbolicValue Key, SymbolicValue Value)>();
    }

    public BufferObject(
        int id,
        IEnumerable<Expression> cells,
        bool isSymbolicOpen = false,
        int? minLength = null,
        Expression? symbolicLength = null,
        Expression? sourceBytes = null,
        IEnumerable<(SymbolicValue Key, SymbolicValue Value)>? openWrites = null) : base(Sort.Buffer, id)
    {
        Cells = cells.ToList();
        IsSymbolicOpen = isSymbolicOpen;
        MinLength = isSymbolicOpen
            ? System.Math.Max(0, minLength ?? 0)
            : Cells.Count;
        SymbolicLength = symbolicLength;
        SourceBytes = sourceBytes;
        OpenWrites = openWrites?.ToList() ?? new List<(SymbolicValue Key, SymbolicValue Value)>();
    }

    public BufferObject(int id, byte[] bytes) : base(Sort.Buffer, id)
    {
        Cells = new List<Expression>(bytes.Length);
        foreach (var b in bytes) Cells.Add(Expr.Int(b));
        IsSymbolicOpen = false;
        MinLength = Cells.Count;
        OpenWrites = new List<(SymbolicValue Key, SymbolicValue Value)>();
    }

    public int Length => Cells.Count;

    public override HeapObject Clone(int newId) => new BufferObject(newId, Cells, IsSymbolicOpen, MinLength, SymbolicLength, SourceBytes, OpenWrites);
}

public sealed class InteropObject : HeapObject
{
    public string Kind { get; }
    public byte[] Payload { get; }
    public SymbolicValue? SymbolicPayload { get; }

    public InteropObject(
        int id,
        string kind,
        byte[] payload,
        SymbolicValue? symbolicPayload = null) : base(Sort.InteropInterface, id)
    {
        Kind = kind;
        Payload = payload.ToArray();
        SymbolicPayload = symbolicPayload;
    }

    public override HeapObject Clone(int newId) => new InteropObject(newId, Kind, Payload, SymbolicPayload);
}
