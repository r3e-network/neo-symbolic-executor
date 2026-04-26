using System.Collections.Concurrent;

namespace Neo.SymbolicExecutor.Fuzzer;

public sealed class Statistics
{
    private readonly ConcurrentDictionary<string, long> _iterations = new();
    private readonly ConcurrentDictionary<string, long> _crashes = new();
    public long TotalIterations { get; private set; }
    public long TotalCrashes { get; private set; }
    public System.DateTime StartedUtc { get; } = System.DateTime.UtcNow;

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

    private long _total;
    private long _totalCrashes;

    public long IterationsFor(string target) => _iterations.TryGetValue(target, out var v) ? v : 0;
    public long CrashesFor(string target) => _crashes.TryGetValue(target, out var v) ? v : 0;
    public long Total => _total;
    public long TotalCrashesNow => _totalCrashes;
}
