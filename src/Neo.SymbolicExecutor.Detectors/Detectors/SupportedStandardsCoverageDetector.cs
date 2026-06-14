using System.Collections.Generic;
using System.Linq;

namespace Neo.SymbolicExecutor.Detectors.Detectors;

/// <summary>
/// Reports manifest-declared standards that do not have dedicated detector/profile coverage.
/// This is a coverage notice, not a claim that the standard tag is invalid.
/// </summary>
public sealed class SupportedStandardsCoverageDetector : BaseDetector
{
    private static readonly HashSet<string> DedicatedCoverage = new(System.StringComparer.Ordinal)
    {
        NormalizeStandardTag("NEP-17"),
        NormalizeStandardTag("NEP-11"),
        NormalizeStandardTag("NEP-24"),
        NormalizeStandardTag("NEP-27"),
        NormalizeStandardTag("NEP-26"),
    };

    private static readonly HashSet<string> AbiOnlyCoverage = new(System.StringComparer.Ordinal)
    {
        NormalizeStandardTag("NEP-24"),
        NormalizeStandardTag("NEP-27"),
        NormalizeStandardTag("NEP-26"),
    };

    public override string Name => "supported_standards_coverage";
    public override Severity DefaultSeverity => Severity.Info;
    public override double DefaultConfidence => 0.95;

    public override IEnumerable<Finding> Analyze(AnalysisContext context)
    {
        var manifest = context.Manifest;
        if (manifest is null) yield break;

        foreach (var standard in manifest.SupportedStandards
                     .Where(s => !string.IsNullOrWhiteSpace(s))
                     .GroupBy(NormalizeStandardTag)
                     .Select(g => g.First())
                     .OrderBy(s => s, System.StringComparer.Ordinal))
        {
            if (AbiOnlyCoverage.Contains(NormalizeStandardTag(standard)))
            {
                yield return MakeFinding(
                    title: $"Manifest standard `{standard}` currently has ABI-only analyzer coverage",
                    description: "neo-sym validates this standard's manifest ABI shape, but the neo-n3-security profile still reports the standard-specific behavior obligation as incomplete until semantic proof rules are implemented.",
                    offset: 0,
                    severity: Severity.Info,
                    state: null,
                    tags: new[] { "manifest", "standard-coverage", "abi-only" });
                continue;
            }

            if (DedicatedCoverage.Contains(NormalizeStandardTag(standard)))
                continue;

            yield return MakeFinding(
                title: $"Manifest standard `{standard}` has no dedicated analyzer coverage",
                description: "The manifest declares this supported standard, but neo-sym does not currently run dedicated compliance rules for it. Treat the scan as general VM/security coverage for this standard-specific surface.",
                offset: 0,
                severity: Severity.Info,
                state: null,
                tags: new[] { "manifest", "standard-coverage" });
        }
    }

    private static string NormalizeStandardTag(string standard) =>
        new(standard.Where(char.IsLetterOrDigit).Select(char.ToUpperInvariant).ToArray());
}
