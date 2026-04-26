using System;
using System.Collections.Generic;
using System.Threading;

namespace Neo.SymbolicExecutor.Fuzzer.Coverage;

/// <summary>
/// Bounded ring of "interesting" inputs — those that opened new coverage on prior iterations.
/// Coverage-guided targets pick from here for ~70% of iterations and mutate the result; the
/// remaining ~30% is fresh-random to bootstrap exploration past local minima.
///
/// Concurrent reads + writes are safe: the array snapshot is rebuilt under a single lock,
/// and the read path uses a Volatile.Read of the snapshot reference. This is good enough for
/// our scale and avoids a contended ConcurrentBag enumerator on the hot path.
/// </summary>
public sealed class InterestingCorpus
{
    private readonly object _lock = new();
    private readonly int _capacity;
    private byte[][] _items;
    private int _writeIndex;
    private int _count;

    public InterestingCorpus(int capacity = 4096)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
        _items = new byte[capacity][];
    }

    public int Count => Volatile.Read(ref _count);

    public void Add(byte[] input)
    {
        if (input is null || input.Length == 0) return;
        lock (_lock)
        {
            _items[_writeIndex] = input;
            _writeIndex = (_writeIndex + 1) % _capacity;
            if (_count < _capacity) _count++;
        }
    }

    /// <summary>Pick one input at random. Returns null when empty.</summary>
    public byte[]? PickRandom(Random rng)
    {
        lock (_lock)
        {
            if (_count == 0) return null;
            int i = rng.Next(_count);
            return _items[i];
        }
    }
}
