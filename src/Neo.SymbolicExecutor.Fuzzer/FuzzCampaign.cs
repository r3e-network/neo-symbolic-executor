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
        while (!cancel.IsCancellationRequested)
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
                    if (_recorder.Record(target.Name, seed, _stats.IterationsFor(target.Name),
                                          ex is OperationCanceledException ? Array.Empty<byte>() : Array.Empty<byte>(),
                                          ex, null))
                    {
                        _stats.RecordCrash(target.Name);
                        Log($"  [CRASH] {target.Name} seed={seed} {ex.GetType().Name}: {ex.Message}");
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
        // GC.GetTotalMemory(false) is a cheap snapshot of managed heap. A monotonically growing
        // value over a long run is a leak signal — surfacing it here lets the operator notice
        // before the fuzzer OOMs on a multi-day run.
        long mem = GC.GetTotalMemory(false);
        var sb = new System.Text.StringBuilder();
        sb.Append($"[{elapsed:hh\\:mm\\:ss}] iters={total:N0} ({rate:F0}/s) " +
                  $"mem={mem / (1024 * 1024)}MB crashes={_stats.TotalCrashesNow} unique={_recorder.UniqueCrashes}");
        foreach (var t in _opts.Targets.OrderBy(t => t.Name))
        {
            sb.Append($" | {t.Name}={_stats.IterationsFor(t.Name):N0}/{_stats.CrashesFor(t.Name)}");
        }
        Log(sb.ToString());
    }

    private void Log(string s) => (_opts.Log ?? Console.WriteLine)(s);
}
