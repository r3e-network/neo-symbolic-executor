using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

namespace Neo.SymbolicExecutor.Fuzzer;

/// <summary>
/// Persists unique crashes to disk under a corpus directory. Dedupes by SHA-256 of
/// (target name + exception type + first 4 stack frames).
///
/// Layout:
///   &lt;corpus&gt;/crashes/&lt;target&gt;-&lt;sig&gt;/
///       crash.txt          — exception type, message, full stack
///       input.bin          — minimal repro bytes
///       meta.json          — target, seed, iteration, first-seen timestamp
/// </summary>
public sealed class CrashRecorder
{
    private const int MaxPreloadedCrashSignatures = 8_192;

    private readonly string _root;
    private readonly ConcurrentDictionary<string, byte> _seen = new();

    public CrashRecorder(string corpusRoot)
    {
        _root = Path.Combine(corpusRoot, "crashes");
        Directory.CreateDirectory(_root);
        // Pre-load any previously-seen signatures so re-runs don't double-record.
        if (Directory.Exists(_root))
        {
            foreach (var dir in Directory.EnumerateDirectories(_root).Take(MaxPreloadedCrashSignatures))
            {
                _seen.TryAdd(Path.GetFileName(dir), 1);
            }
        }
    }

    public int UniqueCrashes => _seen.Count;

    public bool Record(string target, int seed, long iteration,
                       byte[] reproInput, Exception ex, string? invariantReason)
    {
        string sig = Signature(target, ex, invariantReason);
        if (!_seen.TryAdd(sig, 1)) return false;

        string dir = Path.Combine(_root, sig);
        Directory.CreateDirectory(dir);

        string crashText = invariantReason is not null
            ? $"INVARIANT VIOLATION in target '{target}'\nseed={seed} iteration={iteration}\n\n{invariantReason}\n"
            : $"EXCEPTION {ex.GetType().FullName} in target '{target}'\n"
              + $"seed={seed} iteration={iteration}\n\n{ex.Message}\n\nStack:\n{ex.StackTrace}\n";
        File.WriteAllText(Path.Combine(dir, "crash.txt"), crashText);
        File.WriteAllBytes(Path.Combine(dir, "input.bin"), reproInput);
        var meta = new JsonObject
        {
            ["target"] = target,
            ["seed"] = seed,
            ["iteration"] = iteration,
            ["exception_type"] = invariantReason is not null ? "InvariantViolation" : ex.GetType().FullName,
            ["first_seen_utc"] = DateTime.UtcNow.ToString("o"),
            ["signature"] = sig,
        };
        File.WriteAllText(Path.Combine(dir, "meta.json"), meta.ToJsonString());
        return true;
    }

    private static string Signature(string target, Exception ex, string? invariantReason)
    {
        var sb = new StringBuilder();
        sb.Append(target).Append('|');
        if (invariantReason is not null)
        {
            // Group by leading words of the reason so similar invariant violations cluster.
            int trim = invariantReason.IndexOfAny(new[] { ':', '(', '[', '\n' });
            sb.Append("invariant:").Append(trim < 0 ? invariantReason : invariantReason[..trim]);
        }
        else
        {
            sb.Append(ex.GetType().FullName);
            // First few stack frames keep the signature stable across iterations.
            string trace = ex.StackTrace ?? "";
            int newlines = 0;
            int end = 0;
            while (newlines < 3 && end < trace.Length)
            {
                int n = trace.IndexOf('\n', end);
                if (n < 0) { end = trace.Length; break; }
                end = n + 1; newlines++;
            }
            sb.Append('|').Append(trace.AsSpan(0, end).ToString());
        }
        Span<byte> buf = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString()), buf);
        return target + "-" + Convert.ToHexString(buf[..6]);
    }
}
