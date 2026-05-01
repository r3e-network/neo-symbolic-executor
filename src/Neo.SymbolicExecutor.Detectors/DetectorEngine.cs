using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// Runs a list of detectors over an analysis context and returns deduplicated findings.
///
/// Per audit Phase 11 (Python): dedupe key is (detector, title, offset). When duplicates
/// collide, retain the highest severity, the highest confidence, and union the tags.
/// </summary>
public sealed class DetectorEngine
{
    private readonly IReadOnlyList<IDetector> _detectors;

    public DetectorEngine(IEnumerable<IDetector> detectors)
    {
        _detectors = detectors.ToList();
    }

    public IReadOnlyList<IDetector> Detectors => _detectors;

    public ImmutableArray<Finding> Run(AnalysisContext context)
    {
        var raw = new List<Finding>();
        foreach (var detector in _detectors)
        {
            foreach (var f in detector.Analyze(context))
                raw.Add(f);
        }
        if (context.SmtBackend?.IsAvailable == true)
            raw = ValidateWithSmt(raw, context).ToList();
        return Dedupe(raw);
    }

    /// <summary>
    /// For each finding, locate the originating <see cref="ExecutionState"/> (best-effort by
    /// offset matching) and ask the SMT backend whether its path conditions are satisfiable.
    /// SAT -> mark <see cref="Finding.PathSatisfiable"/>=true and attach a concrete witness.
    /// UNSAT -> drop the finding (when DropUnsatFindings) or annotate with a confidence penalty.
    /// UNKNOWN -> leave as null; report through the confidence rationale.
    ///
    /// Phase 4 of the SMT plan: a SAT witness attached to each finding is the reproducer the
    /// user can replay. This is what raises the tool above static-only competitors.
    /// </summary>
    private static IEnumerable<Finding> ValidateWithSmt(IEnumerable<Finding> findings, AnalysisContext context)
    {
        var smt = context.SmtBackend!;
        foreach (var f in findings)
        {
            // Prefer the source state's path conditions captured when the detector emitted the
            // finding. Fall back to the old offset heuristic only for hand-built findings.
            var conds = f.PathConditions.IsDefault
                ? (context.States.FirstOrDefault(s => s.Path.Contains(f.Offset))
                   ?? context.States.FirstOrDefault())?.PathConditions.ToList()
                : f.PathConditions.ToList();
            if (conds is null) { yield return f; continue; }
            var outcome = smt.IsSatisfiable(conds);
            if (outcome == Smt.SmtOutcome.Sat)
            {
                var witness = smt.BuildWitness(conds);
                yield return f with { PathSatisfiable = true, Witness = witness };
            }
            else if (outcome == Smt.SmtOutcome.Unsat)
            {
                if (context.DropUnsatFindings) continue;
                yield return f with
                {
                    PathSatisfiable = false,
                    ConfidenceReason = f.ConfidenceReason + "; path UNSAT under SMT",
                    Confidence = System.Math.Round(f.Confidence * 0.25, 3),
                };
            }
            else
            {
                yield return f with
                {
                    PathSatisfiable = null,
                    ConfidenceReason = f.ConfidenceReason + "; SMT returned UNKNOWN",
                };
            }
        }
    }

    public static ImmutableArray<Finding> Dedupe(IEnumerable<Finding> findings)
    {
        var byKey = new Dictionary<string, Finding>();
        foreach (var f in findings)
        {
            if (!byKey.TryGetValue(f.DedupeKey, out var existing))
            {
                byKey[f.DedupeKey] = f;
                continue;
            }
            // Audit Phase 11: highest severity wins, max confidence, union tags.
            var winner = existing.Severity >= f.Severity ? existing : f;
            byKey[f.DedupeKey] = winner with
            {
                Confidence = System.Math.Max(existing.Confidence, f.Confidence),
                ConfidenceReason = winner.Confidence >= f.Confidence ? winner.ConfidenceReason : f.ConfidenceReason,
                Tags = existing.Tags.Union(f.Tags),
            };
        }
        return byKey.Values
            .OrderByDescending(f => (int)f.Severity)
            .ThenBy(f => f.Detector)
            .ThenBy(f => f.Offset)
            .ToImmutableArray();
    }
}
