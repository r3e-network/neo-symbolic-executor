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
            // Static findings are not scoped to any execution path. Do not attach an arbitrary
            // path for SMT filtering, or --smt-drop-unsat can hide manifest-only risks.
            if (f.PathConditions.IsDefault)
            {
                yield return f;
                continue;
            }

            var conds = f.PathConditions.ToList();
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
                PathSatisfiable = MergePathSatisfiability(existing.PathSatisfiable, f.PathSatisfiable),
                Witness = PickWitness(existing, f, winner),
            };
        }
        // Findings render directly into JSON/Markdown reports; sort with Ordinal so a non-en-US
        // CI agent never reorders them by locale-specific casing rules.
        return byKey.Values
            .OrderByDescending(f => (int)f.Severity)
            .ThenBy(f => f.Detector, System.StringComparer.Ordinal)
            .ThenBy(f => f.Offset)
            .ToImmutableArray();
    }

    private static bool? MergePathSatisfiability(bool? left, bool? right)
    {
        if (left == true || right == true) return true;
        if (left is null || right is null) return null;
        return false;
    }

    private static IReadOnlyDictionary<string, object>? PickWitness(Finding left, Finding right, Finding fallback)
    {
        if (left.PathSatisfiable == true && left.Witness is { Count: > 0 }) return left.Witness;
        if (right.PathSatisfiable == true && right.Witness is { Count: > 0 }) return right.Witness;
        return fallback.Witness;
    }
}
