using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;

namespace Neo.SymbolicExecutor.Fuzzer.Coverage;

/// <summary>
/// Global, thread-safe coverage tracker keyed by (target, offset). Used by coverage-guided
/// targets to decide whether an input opened new code paths and is therefore worth keeping
/// in the interesting-input corpus.
///
/// We intentionally use a flat (target | offset) key because the dispatcher in
/// <see cref="SymbolicEngine"/> is offset-driven, not opcode-driven — visiting offset 0x40
/// once in a TRY frame and once in normal flow may reach different sub-paths but they share
/// the same offset, and we want to count both as a single coverage point. Distinct opcodes
/// at the same offset are impossible (the script is parsed once), so offset is the right key.
/// </summary>
public sealed class CoverageTracker
{
    private readonly ConcurrentDictionary<long, byte> _seen = new();
    private long _newCount;
    private long _hitCount;

    /// <summary>Record visits, return how many were new.</summary>
    public int RecordPath(string target, IReadOnlyList<int> path)
    {
        int newOnes = 0;
        int targetHash = target.GetHashCode();
        foreach (int off in path)
        {
            // Pack (target hash | offset) into a 64-bit key — collisions on the hash side are
            // statistically negligible at our scale and let us avoid string allocation per hit.
            long key = ((long)targetHash << 32) | (uint)off;
            if (_seen.TryAdd(key, 1)) newOnes++;
            Interlocked.Increment(ref _hitCount);
        }
        if (newOnes > 0) Interlocked.Add(ref _newCount, newOnes);
        return newOnes;
    }

    public long UniqueEdges => _seen.Count;
    public long TotalHits => Interlocked.Read(ref _hitCount);
    public long NewEdgesEver => Interlocked.Read(ref _newCount);
}
