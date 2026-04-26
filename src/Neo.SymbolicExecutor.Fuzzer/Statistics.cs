using System.Collections.Concurrent;

namespace Neo.SymbolicExecutor.Fuzzer;

public sealed class Statistics
{
    private readonly ConcurrentDictionary<string, long> _iterations = new();
    private readonly ConcurrentDictionary<string, long> _crashes = new();
    public System.DateTime StartedUtc { get; } = System.DateTime.UtcNow;

    private long _total;
    private long _totalCrashes;

    public void RecordIteration(string target)
    {
        _iterations.AddOrUpdate(target, 1, (_, v) => v + 1);
        System.Threading.Interlocked.Increment(ref _total);
    }

    public void RecordCrash(string target)
    {
        _crashes.AddOrUpdate(target, 1, (_, v) => v + 1);
        System.Threading.Interlocked.Increment(ref _totalCrashes);
    }

    public long IterationsFor(string target) => _iterations.TryGetValue(target, out var v) ? v : 0;
    public long CrashesFor(string target) => _crashes.TryGetValue(target, out var v) ? v : 0;

    /// <summary>Total iterations across all targets. Audit C# #23: the prior auto-property
    /// was never assigned and always returned 0; this is the single source of truth.</summary>
    public long Total => System.Threading.Interlocked.Read(ref _total);

    /// <summary>Total crashes across all targets.</summary>
    public long TotalCrashesNow => System.Threading.Interlocked.Read(ref _totalCrashes);
}
