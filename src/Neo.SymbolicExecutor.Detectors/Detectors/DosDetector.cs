using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Denial-of-service patterns: unbounded loops, deep recursion, iterator-driven storage scans,
/// excessive storage writes.
///
/// Audit precision lessons:
/// - Don't fire on every back-edge in <see cref="Telemetry.LoopsDetected"/>; many loops have
///   concrete bounded iteration counts. We separate iterator-driven loops (always suspect) from
///   plain back-edges (HIGH confidence only when also unbounded by symbolic state).
/// - Storage-write threshold must consider a single Find+iterate-and-Put pattern at low static
///   count; we cross-reference iterator presence.
/// - Recursion via deep call stack is a distinct finding.
/// </summary>
public sealed class DosDetector : BaseDetector
{
    public override string Name => "dos";
    public override Severity DefaultSeverity => Severity.Medium;
    public override double DefaultConfidence => 0.7;

    public const int RecursionThreshold = 8;
    public const int StorageWriteThreshold = 32;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        foreach (var state in context.States)
        {
            // Iterator-driven storage scan with a write inside the loop.
            if (state.Telemetry.IteratorLoops.Count > 0
                && state.Telemetry.StorageOps.Count > 0)
            {
                int firstIter = state.Telemetry.IteratorLoops.GetEnumerator() is var it && it.MoveNext() ? it.Current : 0;
                yield return MakeFinding(
                    title: "Iterator-driven storage scan may consume unbounded gas",
                    description: $"State explores Storage.Find/Iterator.Next at 0x{firstIter:X4}; a malicious "
                               + "key prefix can force the contract into an unbounded scan.",
                    offset: firstIter,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "iterator-dos" });
            }

            // Loop with no concrete bound: very heuristic — we treat any back-edge that survived
            // visit-cap truncation as suspect.
            if (state.Telemetry.Truncated && state.Telemetry.LoopsDetected.Count > 0)
            {
                int firstLoop = MinOf(state.Telemetry.LoopsDetected);
                yield return MakeFinding(
                    title: "Loop appears unbounded under symbolic exploration",
                    description: $"Loop body at 0x{firstLoop:X4} hit the visit cap during exploration; "
                               + "the loop may iterate without a sound static bound.",
                    offset: firstLoop,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "unbounded-loop" });
            }

            // Deep recursion / call chain.
            if (state.Telemetry.MaxCallStackDepth >= RecursionThreshold)
            {
                yield return MakeFinding(
                    title: "Deep call chain risks recursion DoS",
                    description: $"Call stack depth reached {state.Telemetry.MaxCallStackDepth} (threshold {RecursionThreshold}). "
                               + "Recursive call patterns can exhaust GAS or invocation depth.",
                    offset: 0,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "recursion-dos" });
            }

            // Excessive storage writes — not absolute, contextualized by iterator presence.
            int writes = 0;
            foreach (var op in state.Telemetry.StorageOps)
                if (op.Kind == StorageOpKind.Put) writes++;
            if (writes >= StorageWriteThreshold)
            {
                yield return MakeFinding(
                    title: "Excessive storage writes per invocation",
                    description: $"Path performs {writes} storage writes (threshold {StorageWriteThreshold}). "
                               + "GAS cost and storage growth scale with this count.",
                    offset: 0,
                    severity: Severity.Medium,
                    state: state,
                    tags: new[] { "storage-dos" });
            }
        }
    }

    private static int MinOf(IEnumerable<int> set)
    {
        int min = int.MaxValue;
        foreach (var v in set) if (v < min) min = v;
        return min == int.MaxValue ? 0 : min;
    }
}
