using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
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
///
/// Optional disk persistence (iter-2 wakeup-3): when a corpus directory is configured, every
/// new entry is written as `&lt;sha256-prefix&gt;.bin` and loaded back on startup. Without this,
/// each wrapper restart loses all coverage state and the campaign re-explores the same shallow
/// inputs every 24 hours. With persistence, coverage compounds across days/weeks of runtime.
/// </summary>
public sealed class InterestingCorpus
{
    /// <summary>Disk-side cap on persisted entries. The in-memory ring is bounded at
    /// <see cref="_capacity"/>, but every Add() that opens new coverage also writes one
    /// disk entry — at ~10K interesting inputs / minute under load, that's tens of millions
    /// of files in a week. We stop persisting after this cap is reached; existing entries
    /// remain available for load on the next chunk.</summary>
    public const int MaxPersistedEntries = 8_192;

    private readonly object _lock = new();
    private readonly int _capacity;
    private byte[][] _items;
    private int _writeIndex;
    private int _count;
    private readonly string? _persistDir;
    private readonly HashSet<string> _persistedNames = new();

    public InterestingCorpus(int capacity = 4096, string? persistDir = null)
    {
        if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
        _capacity = capacity;
        _items = new byte[capacity][];
        _persistDir = persistDir;
        if (_persistDir is not null)
        {
            try
            {
                Directory.CreateDirectory(_persistDir);
                LoadFromDisk();
            }
            catch (IOException) { /* ignore — corpus is best-effort */ }
            catch (UnauthorizedAccessException) { /* same */ }
        }
    }

    public int Count => Volatile.Read(ref _count);

    public void Add(byte[] input)
    {
        if (input is null || input.Length == 0) return;
        bool added;
        lock (_lock)
        {
            _items[_writeIndex] = input;
            _writeIndex = (_writeIndex + 1) % _capacity;
            added = _count < _capacity;
            if (added) _count++;
        }
        if (_persistDir is not null) TryPersist(input);
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

    private void TryPersist(byte[] input)
    {
        try
        {
            string name = Sha256Prefix(input) + ".bin";
            lock (_persistedNames)
            {
                if (_persistedNames.Count >= MaxPersistedEntries) return;
                if (!_persistedNames.Add(name)) return;  // already on disk
            }
            string path = Path.Combine(_persistDir!, name);
            File.WriteAllBytes(path, input);
        }
        catch (IOException) { /* corpus persistence is best-effort */ }
        catch (UnauthorizedAccessException) { }
    }

    private void LoadFromDisk()
    {
        try
        {
            // Step 1: enumerate every existing file's NAME into _persistedNames so the
            // disk-side dedup + cap check accounts for prior chunks' work. Without this, a
            // restart that finds 8000 files on disk would still try to persist 8000 more
            // until the soft cap kicks in.
            int onDisk = 0;
            foreach (var path in Directory.EnumerateFiles(_persistDir!, "*.bin"))
            {
                _persistedNames.Add(Path.GetFileName(path));
                onDisk++;
            }
            // Step 2: load up to _capacity files into the in-memory ring. We sample the first
            // ones EnumerateFiles returns; this is fine since coverage progress is per-file
            // independent — any subset will seed the next chunk's mutation pool.
            int loaded = 0;
            foreach (var path in Directory.EnumerateFiles(_persistDir!, "*.bin"))
            {
                if (loaded >= _capacity) break;
                byte[] bytes;
                try { bytes = File.ReadAllBytes(path); }
                catch (IOException) { continue; }
                if (bytes.Length == 0) continue;
                lock (_lock)
                {
                    _items[_writeIndex] = bytes;
                    _writeIndex = (_writeIndex + 1) % _capacity;
                    if (_count < _capacity) _count++;
                }
                loaded++;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static string Sha256Prefix(byte[] bytes)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(bytes, hash);
        return Convert.ToHexString(hash[..8]);
    }
}
