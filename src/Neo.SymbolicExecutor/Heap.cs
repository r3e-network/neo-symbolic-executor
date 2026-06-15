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
    // NeoVM's reference-counted evaluation-stack limit; also bounds Struct.Clone subitems.
    public int MaxStackSize { get; init; } = 2048;

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
    public Heap(int maxObjects, int maxItemSize, int maxCollectionSize, int maxStackSize = 2048)
    {
        _objects = new Dictionary<int, HeapObject>();
        _nextId = 1;
        MaxObjects = maxObjects;
        MaxItemSize = maxItemSize;
        MaxCollectionSize = maxCollectionSize;
        MaxStackSize = maxStackSize;
    }

    private Heap(Dictionary<int, HeapObject> objects, int nextId, int maxObjects, int maxItemSize, int maxCollectionSize, int maxStackSize)
    {
        _objects = objects;
        _nextId = nextId;
        MaxObjects = maxObjects;
        MaxItemSize = maxItemSize;
        MaxCollectionSize = maxCollectionSize;
        MaxStackSize = maxStackSize;
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
        EnforceItemSize(length);
        return Allocate(id => new BufferObject(id, length));
    }

    public BufferObject NewBuffer(byte[] bytes)
    {
        EnforceItemSize(bytes.Length);
        return Allocate(id => new BufferObject(id, bytes));
    }

    public BufferObject NewSymbolicBuffer(Expression sourceBytes, Expression symbolicLength, int minLength = 0)
    {
        EnforceItemSize(minLength);
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

    /// <summary>
    /// Clone a Struct value by value, mirroring NeoVM's Neo.VM.Types.Struct.Clone exactly: a BFS that
    /// copies every Struct subitem INDEPENDENTLY (no memoization — a sub-struct referenced by two
    /// fields becomes two distinct copies, as on the real VM), shares non-struct items by reference,
    /// and faults (uncatchable) once the cumulative subitem count exceeds MaxStackSize - 1 (which also
    /// bounds circular structs, matching NeoVM's "Beyond struct subitem clone limits"). Round-3 audit
    /// fix: the prior id-memoization aliased shared sub-structs, producing wrong values after a later
    /// SETITEM into one of them.
    /// </summary>
    public SymbolicValue CloneStructValueForCollection(SymbolicValue value)
    {
        if (value.Expression is not HeapRef { RefSort: Sort.Struct } href)
            return value;

        int budget = MaxStackSize - 1;
        var rootClone = AllocateStructShell(Get<StructObject>(href.ObjectId));
        var queue = new Queue<(StructObject Source, StructObject Clone)>();
        queue.Enqueue((Get<StructObject>(href.ObjectId), rootClone));
        while (queue.Count > 0)
        {
            var (source, clone) = queue.Dequeue();
            foreach (var field in source.Fields)
                clone.Fields.Add(CloneStructSubitem(field, queue, ref budget));
            foreach (var write in source.OpenWrites)
                clone.OpenWrites.Add((write.Key, CloneStructSubitem(write.Value, queue, ref budget)));
        }

        return SymbolicValue.HeapRef(Sort.Struct, rootClone.Id).WithTaints(value.Taints);
    }

    private StructObject AllocateStructShell(StructObject source) =>
        Allocate(id => new StructObject(
            id,
            isSymbolicOpen: source.IsSymbolicOpen,
            minCount: source.MinCount,
            openSizeOffset: source.OpenSizeOffset));

    private SymbolicValue CloneStructSubitem(
        SymbolicValue item,
        Queue<(StructObject Source, StructObject Clone)> queue,
        ref int budget)
    {
        if (--budget < 0)
            throw new VmFaultException("Beyond struct subitem clone limits");

        if (item.Expression is HeapRef { RefSort: Sort.Struct } childRef
            && _objects.TryGetValue(childRef.ObjectId, out var obj)
            && obj is StructObject childSource)
        {
            var childClone = AllocateStructShell(childSource);
            queue.Enqueue((childSource, childClone));
            return SymbolicValue.HeapRef(Sort.Struct, childClone.Id).WithTaints(item.Taints);
        }

        return item;
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
        return new Heap(copy, _nextId, MaxObjects, MaxItemSize, MaxCollectionSize, MaxStackSize);
    }

    public void EnforceCollectionGrowth(int newSize)
    {
        if (newSize > MaxCollectionSize)
            throw new AnalysisBudgetException($"Collection grew to {newSize}, exceeds limit {MaxCollectionSize}");
    }

    // NeoVM's real StackItem byte-size limit (ExecutionEngineLimits.MaxItemSize).
    public const int NeoVmMaxItemSize = 1024 * 1024; // 1 MiB

    /// <summary>
    /// Round-3 audit fix: NeoVM faults only when a Buffer/ByteString exceeds NeoVmMaxItemSize (1 MiB).
    /// A size within that limit but above the analyzer's materialization budget (<see cref="MaxItemSize"/>,
    /// default 64 KiB) would SUCCEED on the real VM, so it is a modeling limit (CoverageIncomplete), not
    /// a fault — the prior `> MaxItemSize` fault pruned feasible paths for items between the budget and
    /// NeoVM's 1 MiB limit.
    /// </summary>
    public void EnforceItemSize(int newSize)
    {
        if (newSize < 0 || newSize > NeoVmMaxItemSize)
            throw new VmFaultException($"item size {newSize} exceeds NeoVM MaxItemSize {NeoVmMaxItemSize}");
        if (newSize > MaxItemSize)
            throw new ModelingLimitException(
                $"item size {newSize} exceeds the analyzer materialization budget {MaxItemSize} (NeoVM allows up to {NeoVmMaxItemSize})");
    }
}
