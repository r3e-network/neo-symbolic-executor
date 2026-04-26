using System.Collections.Generic;
using System.Collections.Immutable;

namespace Neo.SymbolicExecutor.Detectors;

/// <summary>
/// A security finding emitted by a detector against an <see cref="ExecutionState"/>.
/// Immutable; produced via <see cref="BaseDetector.MakeFinding"/> which auto-calibrates confidence.
/// </summary>
public sealed record Finding(
    string Detector,
    Severity Severity,
    string Title,
    string Description,
    int Offset,
    double Confidence,
    string ConfidenceReason,
    ImmutableHashSet<string> Tags,
    bool? PathSatisfiable = null,
    IReadOnlyDictionary<string, object>? Witness = null)
{
    public string DedupeKey => $"{Detector}|{Title}|0x{Offset:X4}";
}
