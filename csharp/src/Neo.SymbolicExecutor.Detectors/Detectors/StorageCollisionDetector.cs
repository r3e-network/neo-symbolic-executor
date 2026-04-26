using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Detects storage-key collisions where one concrete key is a strict prefix of another with no
/// separator byte — a pattern that lets one record be partially overwritten by another.
///
/// Audit precision fix: Don't flag every byte-prefix relationship; that's the normal pattern
/// for namespaced storage (e.g. b"balance:" + addr vs b"balance:total"). We only flag when one
/// key is fully contained in another AND there's no separator byte at the boundary.
/// </summary>
public sealed class StorageCollisionDetector : BaseDetector
{
    public override string Name => "storage_collision";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.7;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var keys = new List<(int Offset, byte[] Key, ExecutionState State)>();
        foreach (var state in context.States)
            foreach (var op in state.Telemetry.StorageOps)
                if (op.Key.AsConcreteBytes() is byte[] kb && kb.Length > 0)
                    keys.Add((op.Offset, kb, state));

        for (int i = 0; i < keys.Count; i++)
        {
            for (int j = i + 1; j < keys.Count; j++)
            {
                var (oi, ki, si) = keys[i];
                var (oj, kj, sj) = keys[j];
                if (ki.Length == kj.Length) continue;          // exact match isn't a collision

                byte[] shorter = ki.Length < kj.Length ? ki : kj;
                byte[] longer = ki.Length < kj.Length ? kj : ki;
                int shortOff = ki.Length < kj.Length ? oi : oj;
                int longOff = ki.Length < kj.Length ? oj : oi;
                ExecutionState refState = ki.Length < kj.Length ? si : sj;

                bool isPrefix = true;
                for (int k = 0; k < shorter.Length; k++)
                {
                    if (longer[k] != shorter[k]) { isPrefix = false; break; }
                }
                if (!isPrefix) continue;

                // Namespace heuristic: if either the last byte of the shorter key or the first
                // byte of the longer key's suffix is a typical separator (':' '/' '|' 0x00), the
                // longer key is intentionally namespaced under the shorter — not a collision.
                byte sepInLonger = longer[shorter.Length];
                byte sepEndShorter = shorter[shorter.Length - 1];
                static bool IsSep(byte b) => b is (byte)':' or (byte)'/' or (byte)'|' or 0x00;
                if (IsSep(sepInLonger) || IsSep(sepEndShorter)) continue;

                yield return MakeFinding(
                    title: "Storage key prefix overlap",
                    description: $"Storage key at 0x{shortOff:X4} is a strict prefix of the key at 0x{longOff:X4} "
                               + "with no separator byte between them. Reads/writes via Storage.Find can return both.",
                    offset: shortOff,
                    severity: Severity.Medium,
                    state: refState,
                    tags: new[] { "storage-key-overlap" });
            }
        }
    }
}
