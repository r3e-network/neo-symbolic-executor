using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Neo.SymbolicExecutor.Fuzzer;

public sealed class FuzzCampaignOptions
{
    public required IReadOnlyList<IFuzzTarget> Targets { get; init; }
    public required string CorpusRoot { get; init; }
    public int Workers { get; init; } = Environment.ProcessorCount;
    public TimeSpan? MaxRuntime { get; init; }
    public int? StartSeed { get; init; }
    public TimeSpan StatusInterval { get; init; } = TimeSpan.FromSeconds(10);
    public bool StopOnFirstCrash { get; init; }
    public Action<string>? Log { get; init; }

    /// <summary>
    /// Self-restart safeguard: when GC.GetTotalMemory crosses this threshold (MB), the campaign
    /// exits cleanly. The wrapper script restarts the next chunk on a fresh process. 0 disables.
    /// Default 4 GB which keeps multi-week runs from accumulating into OOM territory.
    /// </summary>
    public long MaxMemoryMb { get; init; } = 4096;
}

/// <summary>
/// Multi-worker fuzz campaign. Each worker runs a round-robin over targets, recording crashes
/// into the corpus. The status thread prints periodic stats and listens for cancellation.
/// </summary>
public sealed class FuzzCampaign
{
    private readonly FuzzCampaignOptions _opts;
    private readonly CrashRecorder _recorder;
    private readonly Statistics _stats = new();
    private long _seedCounter;

    public FuzzCampaign(FuzzCampaignOptions opts)
    {
        _opts = opts;
        _recorder = new CrashRecorder(opts.CorpusRoot);
        _seedCounter = opts.StartSeed ?? Environment.TickCount;
    }

    public Statistics Stats => _stats;
    public CrashRecorder Recorder => _recorder;

    public async Task RunAsync(CancellationToken cancel)
    {
        using var statusCts = CancellationTokenSource.CreateLinkedTokenSource(cancel);
        if (_opts.MaxRuntime is { } cap) statusCts.CancelAfter(cap);

        var statusTask = Task.Run(() => StatusLoop(statusCts.Token), statusCts.Token);

        var workers = new Task[_opts.Workers];
        for (int i = 0; i < workers.Length; i++)
            workers[i] = Task.Run(() => WorkerLoop(statusCts.Token), statusCts.Token);

        try { await Task.WhenAll(workers); }
        catch (OperationCanceledException) { /* expected on stop */ }

        statusCts.Cancel();
        try { await statusTask; }
        catch (OperationCanceledException) { /* expected */ }

        Log("=== final ===");
        PrintStatus(force: true);
    }

    private void WorkerLoop(CancellationToken cancel)
    {
        while (!cancel.IsCancellationRequested && !_memoryCapBreached)
        {
            foreach (var target in _opts.Targets)
            {
                if (cancel.IsCancellationRequested) return;
                int seed = unchecked((int)Interlocked.Increment(ref _seedCounter));
                _stats.RecordIteration(target.Name);
                try
                {
                    bool ok = target.RunOnce(seed, out var reason, out var repro);
                    if (!ok)
                    {
                        var ex = new InvalidOperationException(reason ?? "<no reason>");
                        if (_recorder.Record(target.Name, seed, _stats.IterationsFor(target.Name),
                                              repro ?? Array.Empty<byte>(), ex, reason))
                        {
                            _stats.RecordCrash(target.Name);
                            Log($"  [INVARIANT] {target.Name} seed={seed} reason={reason}");
                            if (_opts.StopOnFirstCrash) return;
                        }
                    }
                }
                catch (Exception ex) when (!IsExpected(target, ex))
                {
                    // Fall through with whatever input we have. We don't have access to the
                    // failing input bytes from inside catch — many targets capture them via
                    // out-param BEFORE throwing. For targets that do, we minimize.
                    byte[] reproBytes = Array.Empty<byte>();
                    string targetName = target.Name;
                    // Try to retrieve the seed-derived input by re-invoking RunOnce defensively;
                    // if it succeeds the second time, fall back to an empty byte array.
                    try
                    {
                        target.RunOnce(seed, out _, out var captured);
                        if (captured is not null) reproBytes = captured;
                    }
                    catch { /* expected: same crash on replay; we still need bytes */ }
                    // Apply CrashMinimizer when the target supports direct replay.
                    if (target.SupportsDirectReplay && reproBytes.Length > 1)
                    {
                        try { reproBytes = CrashMinimizer.Minimize(target, reproBytes, maxAttempts: 64); }
                        catch { /* keep original bytes on minimize failure */ }
                    }
                    if (_recorder.Record(targetName, seed, _stats.IterationsFor(targetName),
                                          reproBytes, ex, null))
                    {
                        _stats.RecordCrash(targetName);
                        Log($"  [CRASH] {targetName} seed={seed} {ex.GetType().Name}: {ex.Message} (repro={reproBytes.Length} bytes)");
                        if (_opts.StopOnFirstCrash) return;
                    }
                }
            }
        }
    }

    private static bool IsExpected(IFuzzTarget target, Exception ex)
    {
        if (ex is OperationCanceledException) return true;
        foreach (var t in target.ExpectedExceptions)
            if (t.IsAssignableFrom(ex.GetType())) return true;
        return false;
    }

    private async Task StatusLoop(CancellationToken cancel)
    {
        while (!cancel.IsCancellationRequested)
        {
            await Task.Delay(_opts.StatusInterval, cancel).ContinueWith(_ => { });
            if (cancel.IsCancellationRequested) return;
            PrintStatus();
        }
    }

    private void PrintStatus(bool force = false)
    {
        var elapsed = DateTime.UtcNow - _stats.StartedUtc;
        long total = _stats.Total;
        double rate = total / Math.Max(1, elapsed.TotalSeconds);
        long memMb = GC.GetTotalMemory(false) / (1024 * 1024);
        var sb = new System.Text.StringBuilder();
        sb.Append($"[{elapsed:hh\\:mm\\:ss}] iters={total:N0} ({rate:F0}/s) " +
                  $"mem={memMb}MB crashes={_stats.TotalCrashesNow} unique={_recorder.UniqueCrashes}");
        foreach (var t in _opts.Targets.OrderBy(t => t.Name))
        {
            sb.Append($" | {t.Name}={_stats.IterationsFor(t.Name):N0}/{_stats.CrashesFor(t.Name)}");
        }
        Log(sb.ToString());

        // Self-restart safeguard: exit cleanly when memory crosses the configured threshold.
        // The long-run wrapper restarts the next chunk on a fresh process.
        if (_opts.MaxMemoryMb > 0 && memMb > _opts.MaxMemoryMb)
        {
            Log($"[fuzz] memory {memMb}MB exceeds cap {_opts.MaxMemoryMb}MB — exiting for fresh restart");
            _memoryCapBreached = true;
        }
    }

    private volatile bool _memoryCapBreached;

    private void Log(string s) => (_opts.Log ?? Console.WriteLine)(s);
}
