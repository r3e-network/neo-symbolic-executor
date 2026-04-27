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

    public ArrayObject NewArray(IEnumerable<SymbolicValue>? items = null) =>
        Allocate(id => new ArrayObject(id, items));

    public StructObject NewStruct(IEnumerable<SymbolicValue>? fields = null) =>
        Allocate(id => new StructObject(id, fields));

    public MapObject NewMap(IEnumerable<(SymbolicValue, SymbolicValue)>? entries = null) =>
        Allocate(id => new MapObject(id, entries));

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

    public Heap Clone()
    {
        var copy = new Dictionary<int, HeapObject>(_objects.Count);
        foreach (var (id, obj) in _objects)
        {
            copy[id] = obj.Clone(id);
        }
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
