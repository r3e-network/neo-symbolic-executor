using System;

namespace Neo.SymbolicExecutor.Fuzzer;

/// <summary>
/// Delta-debugging-style crash minimizer. Given an input that triggers a failure on a target,
/// repeatedly removes bytes (or chunks) and retains only the smaller versions that still
/// trigger the SAME failure signature. The output is the smallest input we found in a bounded
/// number of attempts.
///
/// Targets must opt in via <see cref="IFuzzTarget.SupportsDirectReplay"/> for shrinking to work.
/// We compare failures by signature class (exception type or invariant-reason prefix) so
/// trivial message-string differences don't stop minimization.
/// </summary>
public static class CrashMinimizer
{
    public sealed record Outcome(bool Failed, string SignatureClass);

    /// <summary>Replay an input through a target and classify the outcome.</summary>
    public static Outcome Probe(IFuzzTarget target, byte[] input)
    {
        if (!target.SupportsDirectReplay) return new Outcome(false, "<unsupported>");
        try
        {
            bool ok = target.RunWithInput(input, out var reason);
            if (ok) return new Outcome(false, "<ok>");
            return new Outcome(true, "invariant:" + (reason ?? "").Split('(', '[', ':', '\n')[0].Trim());
        }
        catch (Exception ex)
        {
            return new Outcome(true, ex.GetType().FullName ?? ex.GetType().Name);
        }
    }

    /// <summary>
    /// Attempt to shrink <paramref name="input"/> while preserving the failure signature.
    /// Returns the smallest input that still fails, or the original on no progress.
    /// </summary>
    public static byte[] Minimize(IFuzzTarget target, byte[] input, int maxAttempts = 256)
    {
        if (!target.SupportsDirectReplay || input.Length <= 1) return input;
        var initial = Probe(target, input);
        if (!initial.Failed) return input;
        string sig = initial.SignatureClass;

        byte[] best = input;
        int attempts = 0;

        // Pass 1: drop chunks of decreasing size, sliding across the buffer.
        for (int chunk = best.Length / 2; chunk >= 1 && attempts < maxAttempts; chunk = Math.Max(1, chunk / 2))
        {
            for (int start = 0; start + chunk <= best.Length && attempts < maxAttempts; start += Math.Max(1, chunk / 2))
            {
                var trial = Drop(best, start, chunk);
                if (trial.Length == 0) continue;
                var probe = Probe(target, trial);
                if (probe.Failed && probe.SignatureClass == sig) best = trial;
                attempts++;
            }
            if (chunk == 1) break;
        }

        // Pass 2: random single-byte deletion (catches cases the chunked pass misses).
        var rng = new Random(unchecked(input.Length * 1664525 + 1013904223));
        for (int i = 0; i < 64 && best.Length > 1 && attempts < maxAttempts; i++)
        {
            int idx = rng.Next(best.Length);
            var trial = Drop(best, idx, 1);
            var probe = Probe(target, trial);
            if (probe.Failed && probe.SignatureClass == sig) best = trial;
            attempts++;
        }

        return best;
    }

    private static byte[] Drop(byte[] src, int start, int count)
    {
        if (start < 0) start = 0;
        if (start + count > src.Length) count = src.Length - start;
        if (count <= 0) return src;
        byte[] dst = new byte[src.Length - count];
        Buffer.BlockCopy(src, 0, dst, 0, start);
        Buffer.BlockCopy(src, start + count, dst, start, src.Length - (start + count));
        return dst;
    }
}
