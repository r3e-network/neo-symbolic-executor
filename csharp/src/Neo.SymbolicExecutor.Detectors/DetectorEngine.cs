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
        return Dedupe(raw);
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
