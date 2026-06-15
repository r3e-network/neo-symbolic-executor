using System.Collections;
using System.Collections.Generic;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Copy-on-write list. <see cref="Fork"/> shares the backing storage with the parent until either side
/// mutates, at which point the mutating side copies the backing exactly once. This makes a state fork
/// (<see cref="Telemetry.Clone"/>) O(1) per collection instead of eagerly deep-copying every element on
/// every fork — the dominant per-fork cost on storage/arithmetic-heavy contracts.
///
/// SOUNDNESS: only correct for IMMUTABLE elements (records, value types, interned strings). Sharing a
/// list of MUTABLE objects would let one fork observe another's element mutations — exactly the clone
/// isolation leak the audit (C1/C6) guards against. The fork-then-copy-before-write discipline below
/// guarantees a shared backing is never mutated in place, so distinct forks never alias each other's
/// writes; the CloneIsolationOracle fuzz target exercises this.
/// </summary>
public sealed class CowList<T> : IReadOnlyList<T>
{
    private List<T> _items;
    private bool _shared;

    public CowList() => _items = new List<T>();

    private CowList(List<T> items)
    {
        _items = items;
        _shared = true;
    }

    /// <summary>Create a fork that shares this list's storage until the first write on either side.</summary>
    public CowList<T> Fork()
    {
        _shared = true;
        return new CowList<T>(_items);
    }

    private void EnsureWritable()
    {
        if (_shared)
        {
            _items = new List<T>(_items);
            _shared = false;
        }
    }

    public void Add(T item)
    {
        EnsureWritable();
        _items.Add(item);
    }

    public void AddRange(IEnumerable<T> items)
    {
        EnsureWritable();
        _items.AddRange(items);
    }

    public int Count => _items.Count;

    public T this[int index] => _items[index];

    public List<T>.Enumerator GetEnumerator() => _items.GetEnumerator();

    IEnumerator<T> IEnumerable<T>.GetEnumerator() => _items.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => _items.GetEnumerator();
}

/// <summary>
/// Copy-on-write hash set, the <see cref="CowList{T}"/> analogue for the membership-set telemetry fields
/// (loop headers, enforced witness offsets, …). Same fork-then-copy-before-write discipline and the same
/// immutable-element requirement.
/// </summary>
public sealed class CowSet<T> : IReadOnlyCollection<T>
{
    private HashSet<T> _items;
    private bool _shared;

    public CowSet() => _items = new HashSet<T>();

    private CowSet(HashSet<T> items)
    {
        _items = items;
        _shared = true;
    }

    public CowSet<T> Fork()
    {
        _shared = true;
        return new CowSet<T>(_items);
    }

    private void EnsureWritable()
    {
        if (_shared)
        {
            _items = new HashSet<T>(_items);
            _shared = false;
        }
    }

    public bool Add(T item)
    {
        EnsureWritable();
        return _items.Add(item);
    }

    public bool Contains(T item) => _items.Contains(item);

    public int Count => _items.Count;

    public HashSet<T>.Enumerator GetEnumerator() => _items.GetEnumerator();

    IEnumerator<T> IEnumerable<T>.GetEnumerator() => _items.GetEnumerator();

    IEnumerator IEnumerable.GetEnumerator() => _items.GetEnumerator();
}
