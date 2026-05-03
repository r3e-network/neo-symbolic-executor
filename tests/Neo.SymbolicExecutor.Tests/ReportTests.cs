using System.Collections.Immutable;
using System.Text.Json.Nodes;
using Neo.SymbolicExecutor.Detectors;

namespace Neo.SymbolicExecutor.Tests;

public class ReportTests
{
    private static Finding F(string detector, Severity sev, string title, int offset, double conf = 0.8) =>
        new(detector, sev, title, "desc", offset, conf, "test", ImmutableHashSet<string>.Empty);

    [Fact]
    public void RiskProfile_AggregatesFromFindings()
    {
        var findings = new[]
        {
            F("a", Severity.High, "x", 0x10, 0.9),
            F("a", Severity.Critical, "y", 0x20, 0.8),
            F("b", Severity.Low, "z", 0x30, 0.5),
        };
        var risk = RiskProfile.FromFindings(findings);
        risk.OverallMaxSeverity.Should().Be(Severity.Critical);
        risk.TotalFindings.Should().Be(3);
        risk.SeverityCounts[Severity.High].Should().Be(1);
        risk.SeverityCounts[Severity.Critical].Should().Be(1);
        risk.DetectorMaxSeverity["a"].Should().Be(Severity.Critical);
        risk.DetectorAverageConfidence["a"].Should().Be(0.85);
        risk.WeightedScore.Should().Be(15 + 31 + 3);  // High + Critical + Low
        risk.ConfidenceWeightedScore.Should().BeGreaterThan(0);
    }

    [Fact]
    public void GatePolicy_FailsOnMaxSeverity()
    {
        var findings = new[] { F("a", Severity.High, "x", 0x10) };
        var risk = RiskProfile.FromFindings(findings);
        var policy = new GatePolicy { FailOnMaxSeverity = Severity.Medium };
        var eval = policy.Evaluate(findings, risk);
        eval.Passed.Should().BeFalse();
        eval.Violations.Should().Contain(v => v.Contains("max severity"));
    }

    [Fact]
    public void GatePolicy_ViolationStringsUseLowercaseSeverity()
    {
        // All severity-bearing violation strings must use the canonical lowercase form so they
        // diff cleanly against JSON-rendered severity_counts keys (which always lowercase). Prior
        // to normalization, max-severity and detector-severity violations leaked PascalCase
        // ("High"/"Critical") while severity-count violations used lowercase — inconsistent.
        var findings = new[]
        {
            F("reentrancy", Severity.Critical, "x", 0x10),
            F("overflow", Severity.High, "y", 0x20),
        };
        var risk = RiskProfile.FromFindings(findings);
        var policy = new GatePolicy
        {
            FailOnMaxSeverity = Severity.Medium,
            FailOnSeverityCount = new System.Collections.Generic.Dictionary<Severity, int>
            {
                [Severity.High] = 1,
            },
            FailOnDetectorSeverity = new System.Collections.Generic.Dictionary<string, Severity>
            {
                ["reentrancy"] = Severity.High,
            },
        };
        var eval = policy.Evaluate(findings, risk);

        // No violation string should contain the PascalCase severity names — they all flow into
        // CI artifacts that scripts may match against.
        foreach (var v in eval.Violations)
        {
            v.Should().NotContain("Critical");
            v.Should().NotContain("High");
            v.Should().NotContain("Medium");
            v.Should().NotContain("Low");
        }
        eval.Violations.Should().Contain(v => v.Contains("critical"));
    }

    [Fact]
    public void GatePolicy_FailsOnBudgetExceeded()
    {
        // Empty findings: a clean run that hit the budget cap is still incomplete and should
        // surface that to CI when the operator opts into the gate.
        var findings = System.Array.Empty<Finding>();
        var risk = RiskProfile.FromFindings(findings);
        var policy = new GatePolicy { FailOnBudgetExceeded = true };

        policy.Evaluate(findings, risk, budgetExceeded: false).Passed.Should().BeTrue();
        var failed = policy.Evaluate(findings, risk, budgetExceeded: true);
        failed.Passed.Should().BeFalse();
        failed.Violations.Should().Contain(v => v.Contains("budget exceeded"));
    }

    [Fact]
    public void GatePolicy_FailsOnTotal()
    {
        var findings = new[] { F("a", Severity.Low, "x", 0x10), F("a", Severity.Low, "y", 0x20) };
        var risk = RiskProfile.FromFindings(findings);
        var policy = new GatePolicy { FailOnTotalFindings = 2 };
        var eval = policy.Evaluate(findings, risk);
        eval.Passed.Should().BeFalse();
    }

    [Fact]
    public void GatePolicy_FailsOnDetectorSeverity()
    {
        var findings = new[] { F("reentrancy", Severity.Critical, "x", 0x10) };
        var risk = RiskProfile.FromFindings(findings);
        var policy = new GatePolicy
        {
            FailOnDetectorSeverity = new System.Collections.Generic.Dictionary<string, Severity>
            {
                ["reentrancy"] = Severity.High,
            },
        };
        var eval = policy.Evaluate(findings, risk);
        eval.Passed.Should().BeFalse();
    }

    [Fact]
    public void GatePolicy_FailsOnMinConfidenceBelow()
    {
        var findings = new[] { F("a", Severity.High, "x", 0x10, conf: 0.5) };
        var risk = RiskProfile.FromFindings(findings);
        var policy = new GatePolicy
        {
            MinConfidence = new System.Collections.Generic.Dictionary<Severity, double>
            {
                [Severity.High] = 0.7,
            },
        };
        var eval = policy.Evaluate(findings, risk);
        eval.Passed.Should().BeFalse();
        eval.Violations[0].Should().Contain("confidence");
    }

    [Fact]
    public void GatePolicy_PassesByDefault()
    {
        var findings = new[] { F("a", Severity.Medium, "x", 0x10) };
        var risk = RiskProfile.FromFindings(findings);
        var eval = new GatePolicy().Evaluate(findings, risk);
        eval.Passed.Should().BeTrue();
        eval.Violations.Should().BeEmpty();
    }

    [Fact]
    public void Json_IncludesSmtStatsWhenPresent()
    {
        // ISmtBackend.GetStats's doc says "Surfaced in JSON reports". The CLI now wires
        // smtBackend?.GetStats() into AnalysisMeta.SmtStats and the report serializer
        // emits a "smt_stats" object. Pin both ends of that contract.
        var stats = new Smt.SmtStats(Queries: 10, CacheHits: 3, Unknowns: 1, Timeouts: 0, Sat: 5, Unsat: 4);
        var meta = new AnalysisMeta(SmtAvailable: true, SmtEngaged: true) { SmtStats = stats };
        var risk = RiskProfile.FromFindings(System.Array.Empty<Finding>());
        var gate = new GatePolicy().Evaluate(System.Array.Empty<Finding>(), risk);
        var report = new AnalysisReport(ImmutableArray<Finding>.Empty, risk, gate, meta);
        string json = ReportGenerator.ToJson(report);

        var node = JsonNode.Parse(json)!;
        var smtNode = node["meta"]!["smt_stats"]!;
        smtNode["queries"]!.GetValue<long>().Should().Be(10);
        smtNode["cache_hits"]!.GetValue<long>().Should().Be(3);
        smtNode["sat"]!.GetValue<long>().Should().Be(5);
        smtNode["unsat"]!.GetValue<long>().Should().Be(4);
        smtNode["unknowns"]!.GetValue<long>().Should().Be(1);
        smtNode["timeouts"]!.GetValue<long>().Should().Be(0);

        ReportGenerator.ToMarkdown(report).Should().Contain("**SMT queries:** 10");
    }

    [Fact]
    public void Json_OmitsSmtStatsWhenAbsent()
    {
        // Non-SMT runs should not have a smt_stats key — keeps the report minimal.
        var report = new AnalysisReport(ImmutableArray<Finding>.Empty,
            RiskProfile.FromFindings(System.Array.Empty<Finding>()),
            new GatePolicy().Evaluate(System.Array.Empty<Finding>(), RiskProfile.FromFindings(System.Array.Empty<Finding>())),
            new AnalysisMeta());
        var node = JsonNode.Parse(ReportGenerator.ToJson(report))!;
        node["meta"]!.AsObject().ContainsKey("smt_stats").Should().BeFalse();
    }

    [Fact]
    public void AnalysisMeta_CurrentVersionMatchesAssemblyInfo()
    {
        // Surface the static (one cached read at type init) and confirm it equals the
        // assembly's stripped InformationalVersion. The CLI's `neo-sym version` command also
        // reads CurrentVersion, so this test lock-steps both surfaces.
        var asmInfo = typeof(AnalysisMeta).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .Cast<System.Reflection.AssemblyInformationalVersionAttribute>()
            .Single().InformationalVersion;
        int plus = asmInfo.IndexOf('+');
        if (plus >= 0) asmInfo = asmInfo[..plus];
        AnalysisMeta.CurrentVersion.Should().Be(asmInfo);
    }

    [Fact]
    public void AnalysisMeta_VersionFlowsFromAssembly_NotHardcoded()
    {
        // Production-readiness regression: AnalysisMeta.Version used to be a hardcoded "0.4.0"
        // default. Bumping NeoSymExecVersion in Directory.Build.props would silently leave
        // reports stale. Now the default reads InformationalVersion from this assembly so the
        // two stay in lockstep.
        var meta = new AnalysisMeta();
        var asmVersion = typeof(AnalysisMeta).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .Cast<System.Reflection.AssemblyInformationalVersionAttribute>()
            .Single().InformationalVersion;
        int plus = asmVersion.IndexOf('+');
        if (plus >= 0) asmVersion = asmVersion[..plus];

        meta.Version.Should().Be(asmVersion);
        meta.Version.Should().NotBeEmpty();
        meta.Version.Should().NotContain("+", "the SourceLink commit suffix should be stripped");
    }

    [Fact]
    public void Json_IncludesAllSections()
    {
        var findings = ImmutableArray.Create(F("a", Severity.High, "x", 0x10));
        var risk = RiskProfile.FromFindings(findings);
        var gate = new GatePolicy().Evaluate(findings, risk);
        var report = new AnalysisReport(findings, risk, gate, new AnalysisMeta(StatesExplored: 5));
        var json = ReportGenerator.ToJson(report);

        var node = JsonNode.Parse(json)!;
        node["meta"]!["tool"]!.GetValue<string>().Should().Be("Neo.SymbolicExecutor");
        node["meta"]!["states_explored"]!.GetValue<int>().Should().Be(5);
        node["risk_profile"]!["overall_max_severity"]!.GetValue<string>().Should().Be("high");
        node["gate_evaluation"]!["passed"]!.GetValue<bool>().Should().BeTrue();
        node["findings"]!.AsArray().Count.Should().Be(1);
    }

    [Fact]
    public void Markdown_RendersHeadingsAndFindings()
    {
        var findings = ImmutableArray.Create(F("reentrancy", Severity.Critical, "X-CALL before write", 0x42));
        var risk = RiskProfile.FromFindings(findings);
        var gate = new GatePolicy { FailOnMaxSeverity = Severity.High }.Evaluate(findings, risk);
        var report = new AnalysisReport(findings, risk, gate, new AnalysisMeta());
        var md = ReportGenerator.ToMarkdown(report);

        md.Should().Contain("# Neo Symbolic Executor");
        md.Should().Contain("## Risk Profile");
        md.Should().Contain("## Gate Evaluation");
        md.Should().Contain("**Passed:** NO");
        md.Should().Contain("X-CALL before write");
        md.Should().Contain("`reentrancy`");
    }
}
