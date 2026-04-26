using System;

namespace Neo.SymbolicExecutor.Fuzzer;

/// <summary>
/// Delta-debugging-style crash minimizer. Given an input that triggers a failure on a target,
/// repeatedly removes bytes (or chunks) and retains only the smaller versions that still
/// trigger the SAME failure signature. The output is the smallest input we found in a bounded
/// number of attempts.
///
/// We compare failures by signature class (exception type + invariant-reason prefix) rather
/// than by exact text so trivial message-string differences don't stop minimization.
/// </summary>
public static class CrashMinimizer
{
    /// <summary>
    /// Attempt to shrink <paramref name="input"/> while preserving the failure signature.
    /// Returns the smallest input that still fails, or the original on no progress.
    /// </summary>
    public static byte[] Minimize(IFuzzTarget target, byte[] input, string failureClass,
                                   int maxAttempts = 256)
    {
        if (input.Length <= 1) return input;
        byte[] best = input;
        int attempts = 0;
        var rng = new Random(unchecked(input.Length * 1664525 + 1013904223));

        // Pass 1: drop chunks of decreasing size.
        for (int chunk = best.Length / 2; chunk >= 1 && attempts < maxAttempts; chunk = Math.Max(1, chunk / 2))
        {
            for (int start = 0; start + chunk <= best.Length && attempts < maxAttempts; start += Math.Max(1, chunk / 2))
            {
                var trial = Drop(best, start, chunk);
                if (StillFails(target, trial, failureClass)) best = trial;
                attempts++;
            }
        }

        // Pass 2: random single-byte deletion (catches cases the chunked pass misses).
        for (int i = 0; i < 64 && best.Length > 1 && attempts < maxAttempts; i++)
        {
            int idx = rng.Next(best.Length);
            var trial = Drop(best, idx, 1);
            if (StillFails(target, trial, failureClass)) best = trial;
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

    private static bool StillFails(IFuzzTarget target, byte[] input, string failureClass)
    {
        // For now we drive the target via its seed-based RunOnce by injecting the input
        // directly — but most current targets generate from seed, not from raw input. This
        // helper is therefore best-effort: it shrinks inputs only for targets whose RunOnce
        // happens to read identical bytes.
        // A direct-input replay is a TODO; until then, signature-based matching makes shrinking
        // safe (it never accepts a smaller input that flips to a different bug class).
        try
        {
            target.RunOnce(unchecked((int)BitConverter.ToUInt32(System.Security.Cryptography.SHA256.HashData(input).AsSpan(0, 4))),
                           out var reason, out var _);
            // We can't directly know whether the trial reproduces without input replay.
            // Conservative: only accept the trial if the seed-derived reproducer also fails the
            // same class. In practice this is too restrictive — return false to leave the
            // input untouched until full input-replay lands.
            return false;
        }
        catch (Exception ex) when (ClassOf(ex) == failureClass)
        {
            return true;
        }
        catch { return false; }
    }

    public static string ClassOf(Exception ex) => ex.GetType().FullName ?? ex.GetType().Name;
}
