using System.Collections.Generic;

namespace Neo.SymbolicExecutor;

/// <summary>
/// State-local heap. Owns object identity numbering. Cloned deeply when a state forks so
/// branches do not share mutable storage.
/// </summary>
public sealed class Heap
{
    private readonly Dictionary<int, HeapObject> _objects;
    private int _nextId;

    public int MaxObjects { get; init; } = 4096;
    public int MaxItemSize { get; init; } = 1024 * 1024; // 1 MiB
    public int MaxCollectionSize { get; init; } = 2048;

    public Heap()
    {
        _objects = new Dictionary<int, HeapObject>();
        _nextId = 1;
    }

    /// <summary>
    /// Construct a Heap with explicit budgets. Used by <see cref="SymbolicEngine"/> to plumb
    /// <see cref="ExecutionOptions"/> values through to the heap so a fuzz target's tighter
    /// MaxItemSize / MaxHeapObjects actually constrain allocation. Without this constructor,
    /// the default-constructed Heap silently overrode the engine's options and allowed up to
    /// 1 MiB × 4096 = 4 GiB peaks per state — the iter-2 wakeup-2 memory bomb.
    /// </summary>
    public Heap(int maxObjects, int maxItemSize, int maxCollectionSize)
    {
        _objects = new Dictionary<int, HeapObject>();
        _nextId = 1;
        MaxObjects = maxObjects;
        MaxItemSize = maxItemSize;
        MaxCollectionSize = maxCollectionSize;
    }

    private Heap(Dictionary<int, HeapObject> objects, int nextId, int maxObjects, int maxItemSize, int maxCollectionSize)
    {
        _objects = objects;
        _nextId = nextId;
        MaxObjects = maxObjects;
        MaxItemSize = maxItemSize;
        MaxCollectionSize = maxCollectionSize;
    }

    public IReadOnlyDictionary<int, HeapObject> Objects => _objects;

    public T Allocate<T>(System.Func<int, T> factory) where T : HeapObject
    {
        if (_objects.Count >= MaxObjects)
            throw new AnalysisBudgetException("Heap object limit exceeded");
        // Audit C# #32 fix: don't bump _nextId until the object is fully constructed and
        // registered. A throwing factory used to leak a monotonically-skipped id.
        int id = _nextId;
        var obj = factory(id);
        _objects[id] = obj;
        _nextId = id + 1;
        return obj;
    }

    public ArrayObject NewArray(
        IEnumerable<SymbolicValue>? items = null,
        bool isSymbolicOpen = false,
        int? minCount = null) =>
        Allocate(id => new ArrayObject(id, items, isSymbolicOpen, minCount));

    public StructObject NewStruct(
        IEnumerable<SymbolicValue>? fields = null,
        bool isSymbolicOpen = false,
        int? minCount = null) =>
        Allocate(id => new StructObject(id, fields, isSymbolicOpen, minCount));

    public MapObject NewMap(
        IEnumerable<(SymbolicValue, SymbolicValue)>? entries = null,
        bool isSymbolicOpen = false) =>
        Allocate(id => new MapObject(id, entries, isSymbolicOpen));

    public BufferObject NewBuffer(int length)
    {
        if (length < 0 || length > MaxItemSize)
            throw new VmFaultException($"NEWBUFFER size {length} out of range");
        return Allocate(id => new BufferObject(id, length));
    }

    public BufferObject NewBuffer(byte[] bytes)
    {
        if (bytes.Length > MaxItemSize)
            throw new VmFaultException($"Buffer size {bytes.Length} exceeds item size limit");
        return Allocate(id => new BufferObject(id, bytes));
    }

    public BufferObject NewSymbolicBuffer(Expression sourceBytes, Expression symbolicLength, int minLength = 0)
    {
        if (minLength < 0 || minLength > MaxItemSize)
            throw new VmFaultException($"Buffer minimum size {minLength} exceeds item size limit");
        return Allocate(id => new BufferObject(
            id,
            System.Array.Empty<Expression>(),
            isSymbolicOpen: true,
            minLength: minLength,
            symbolicLength: symbolicLength,
            sourceBytes: sourceBytes));
    }

    public InteropObject NewInterop(string kind, byte[] payload, SymbolicValue? symbolicPayload = null)
    {
        if (payload.Length > MaxItemSize)
            throw new VmFaultException($"Interop payload size {payload.Length} exceeds item size limit");
        return Allocate(id => new InteropObject(id, kind, payload, symbolicPayload));
    }

    public HeapObject Get(int id) =>
        _objects.TryGetValue(id, out var obj)
            ? obj
            : throw new VmFaultException($"Dangling heap reference {id}");

    public T Get<T>(int id) where T : HeapObject
    {
        var obj = Get(id);
        return obj is T typed
            ? typed
            : throw new VmFaultException($"Heap object {id} is {obj.Sort}, not {typeof(T).Name}");
    }

    /// <summary>
    /// Fetch a heap object for mutation. If the object is currently shared with another heap
    /// (via copy-on-write semantics — see <see cref="HeapObject.IsShared"/>), materialise a
    /// private copy in this heap, mark it non-shared, replace this heap's dictionary entry,
    /// and return the copy. Callers MUST use this method before any mutation of an existing
    /// heap object; <see cref="Get(int)"/> / <see cref="Get{T}(int)"/> are read-only.
    /// </summary>
    public HeapObject GetForWrite(int id)
    {
        var obj = Get(id);
        if (!obj.IsShared) return obj;
        var copy = obj.Clone(id);
        copy.IsShared = false;
        _objects[id] = copy;
        return copy;
    }

    /// <summary>
    /// Typed convenience for <see cref="GetForWrite(int)"/>. Throws a VmFault if the object's
    /// runtime sort differs from <typeparamref name="T"/>.
    /// </summary>
    public T GetForWrite<T>(int id) where T : HeapObject
    {
        var obj = GetForWrite(id);
        return obj is T typed
            ? typed
            : throw new VmFaultException($"Heap object {id} is {obj.Sort}, not {typeof(T).Name}");
    }

    public SymbolicValue CloneStructValueForCollection(SymbolicValue value) =>
        CloneStructValueForCollection(value, new Dictionary<int, int>());

    private SymbolicValue CloneStructValueForCollection(
        SymbolicValue value,
        Dictionary<int, int> clonedStructs)
    {
        if (value.Expression is not HeapRef { RefSort: Sort.Struct } href)
            return value;

        return SymbolicValue
            .HeapRef(Sort.Struct, CloneStructObjectForCollection(href.ObjectId, clonedStructs))
            .WithTaints(value.Taints);
    }

    private int CloneStructObjectForCollection(int sourceId, Dictionary<int, int> clonedStructs)
    {
        if (clonedStructs.TryGetValue(sourceId, out int existingClone))
            return existingClone;

        var source = Get<StructObject>(sourceId);
        EnforceCollectionGrowth(source.Fields.Count);
        var clone = Allocate(id => new StructObject(
            id,
            isSymbolicOpen: source.IsSymbolicOpen,
            minCount: source.MinCount,
            openSizeOffset: source.OpenSizeOffset));
        clonedStructs[sourceId] = clone.Id;

        foreach (var field in source.Fields)
            clone.Fields.Add(CloneStructValueForCollection(field, clonedStructs));
        foreach (var write in source.OpenWrites)
            clone.OpenWrites.Add((write.Key, CloneStructValueForCollection(write.Value, clonedStructs)));

        return clone.Id;
    }

    /// <summary>
    /// Copy-on-write clone. Both heaps share every HeapObject reference, marked shared, until
    /// the first <see cref="GetForWrite{T}"/> in either heap materialises a private copy of
    /// that object. The dictionary itself is shallow-copied (each heap gets its own map, but
    /// the values are shared references) so a new allocation on one heap does not leak into
    /// the other. _nextId is forked at the clone point and advances independently per heap.
    /// </summary>
    public Heap Clone()
    {
        foreach (var obj in _objects.Values)
            obj.IsShared = true;
        var copy = new Dictionary<int, HeapObject>(_objects);
        return new Heap(copy, _nextId, MaxObjects, MaxItemSize, MaxCollectionSize);
    }

    public void EnforceCollectionGrowth(int newSize)
    {
        if (newSize > MaxCollectionSize)
            throw new AnalysisBudgetException($"Collection grew to {newSize}, exceeds limit {MaxCollectionSize}");
    }

    public void EnforceItemSize(int newSize)
    {
        if (newSize > MaxItemSize)
            throw new VmFaultException($"Item size {newSize} exceeds NeoVM limit {MaxItemSize}");
    }
}
