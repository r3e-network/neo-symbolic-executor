using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;

namespace Neo.SymbolicExecutor.Tests;

public class DetectorTests
{
    private static AnalysisContext Ctx(params ExecutionState[] states) =>
        new() { States = states };

    private static ExecutionState NewState()
    {
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        return s;
    }

    [Fact]
    public void Reentrancy_FlagsExternalCallBeforeWrite()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "doSomething",
            HasReturnValue = true,
        });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var findings = new ReentrancyDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);  // unamplified, no auth
        findings[0].Offset.Should().Be(0x10);
    }

    [Fact]
    public void Reentrancy_DowngradedWhenWitnessEnforced()
    {
        var s = NewState();
        s.Telemetry.WitnessChecks.Add(0x05);
        s.Telemetry.WitnessChecksEnforced.Add(0x05);
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "doSomething", HasReturnValue = true });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var findings = new ReentrancyDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Reentrancy_AmplifiedRemainsCriticalEvenWithAuth()
    {
        var s = NewState();
        s.Telemetry.WitnessChecksEnforced.Add(0x05);
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "a", HasReturnValue = true });
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x12, Method = "b", HasReturnValue = true });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var findings = new ReentrancyDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Tags.Should().Contain("multiple-pre-write-calls");
    }

    [Fact]
    public void Reentrancy_GuardSuppresses()
    {
        // Audit C1 fix: when the engine sets ReentrancyGuard, the detector skips the state.
        var s = NewState();
        s.Telemetry.ReentrancyGuard = true;
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "x", HasReturnValue = true });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        new ReentrancyDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void Reentrancy_NativeReadOnlyCallNotFlagged()
    {
        // Audit detector audit #1: native read-only methods (Ledger.GetBlock etc.) are NOT
        // re-enterable. Don't flag them as reentrancy risk.
        var s = NewState();
        var ledgerHash = System.Convert.FromHexString("da65b600f7124ce6c79950c1772a36403104f2be");
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "getBlock",
            TargetHash = SymbolicValue.Bytes(ledgerHash),
            HasReturnValue = true,
        });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        new ReentrancyDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void AccessControl_FlagsMissingAuth()
    {
        var s = NewState();
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var findings = new AccessControlDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("missing-auth");
    }

    [Fact]
    public void AccessControl_FlagsUnenforcedWitness()
    {
        // Audit Phase 5 + audit detector audit: CheckWitness invoked but result never used.
        var s = NewState();
        s.Telemetry.WitnessChecks.Add(0x05);
        // No entry in WitnessChecksEnforced -> fail-open.
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var findings = new AccessControlDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("unenforced-witness");
    }

    [Fact]
    public void AccessControl_RespectsManifestSafeFlag()
    {
        // Audit detector audit #18: when manifest declares method `safe=true`, downgrade.
        var s = NewState();
        s.Path.Add(0xA0);  // entry offset
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[{"name":"view","parameters":[],"returntype":"Integer","offset":160,"safe":true}],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);

        var ctx = new AnalysisContext { States = new[] { s }, Manifest = manifest };
        new AccessControlDetector().Analyze(ctx).Should().BeEmpty();
    }

    [Fact]
    public void AccessControl_DoesNotInheritSafetyFromCalledHelper()
    {
        // Per-method analysis seeds Pc = method.Offset, so state.Path[0] is the entry. A
        // non-safe method that CALLs into a safe-flagged helper at a lower offset must NOT
        // inherit the helper's safety — the entry method's findings are the ones that matter.
        var s = NewState();
        s.Path.Add(0xA0);   // entry: non-safe method `mint` at 0xA0
        s.Path.Add(0xA1);
        s.Path.Add(0x50);   // CALL down to safe helper `_initialize` at 0x50
        s.Path.Add(0x51);
        s.Telemetry.StorageOps.Add(new StorageOp(0xA5, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));

        var manifestJson = """
        {
          "name":"X","groups":[],"features":{},"supportedstandards":[],
          "abi":{"methods":[
            {"name":"mint","parameters":[],"returntype":"Boolean","offset":160,"safe":false},
            {"name":"_initialize","parameters":[],"returntype":"Void","offset":80,"safe":true}
          ],"events":[]},
          "permissions":[],"trusts":[]
        }
        """;
        var manifest = Nef.ContractManifest.FromJson(manifestJson);
        var ctx = new AnalysisContext { States = new[] { s }, Manifest = manifest };

        var findings = new AccessControlDetector().Analyze(ctx).ToList();
        findings.Should().NotBeEmpty("the unsafe `mint` method should still surface its missing-auth finding");
        findings[0].Tags.Should().Contain("missing-auth");
    }

    [Fact]
    public void Overflow_FlagsOverflowPossibleOps()
    {
        var s = NewState();
        s.Telemetry.ArithmeticOps.Add(new ArithmeticOp(0x10, "ADD",
            SymbolicValue.Symbol(Sort.Int, "x"), SymbolicValue.Symbol(Sort.Int, "y"),
            OverflowPossible: true, DivisorMaybeZero: false, Checked: false));

        var findings = new OverflowDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Overflow_FlagsDivByZero()
    {
        var s = NewState();
        s.Telemetry.ArithmeticOps.Add(new ArithmeticOp(0x10, "DIV",
            SymbolicValue.Int(100), SymbolicValue.Symbol(Sort.Int, "y"),
            OverflowPossible: false, DivisorMaybeZero: true, Checked: false));

        var findings = new OverflowDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("divide-by-zero");
    }

    [Fact]
    public void Overflow_DoesNotFlagCheckedOps()
    {
        var s = NewState();
        s.Telemetry.ArithmeticOps.Add(new ArithmeticOp(0x10, "ADD",
            SymbolicValue.Symbol(Sort.Int, "x"), SymbolicValue.Symbol(Sort.Int, "y"),
            OverflowPossible: true, DivisorMaybeZero: false, Checked: true));

        new OverflowDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void UncheckedReturn_FlagsUncheckedExternal()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "transfer",
            HasReturnValue = true,
            ReturnChecked = false,
        });

        var findings = new UncheckedReturnDetector().Analyze(Ctx(s)).ToList();
        findings.Should().ContainSingle();
        findings[0].Tags.Should().Contain("unchecked-return");
    }

    [Fact]
    public void UncheckedReturn_SkipsChecked()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "transfer",
            HasReturnValue = true,
            ReturnChecked = true,
        });
        new UncheckedReturnDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void DynamicCallTarget_RanksSeverityByDynamism()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "x",
            TargetHashDynamic = true,
            MethodDynamic = true,
            HasReturnValue = true,
        });
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x20,
            Method = "y",
            TargetHashDynamic = true,
            MethodDynamic = false,
            HasReturnValue = true,
        });
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x30,
            Method = "z",
            TargetHashDynamic = false,
            MethodDynamic = true,
            HasReturnValue = true,
        });

        var findings = new DynamicCallTargetDetector().Analyze(Ctx(s)).ToList();
        findings.Should().HaveCount(3);
        findings.Single(f => f.Offset == 0x10).Severity.Should().Be(Severity.Critical);
        findings.Single(f => f.Offset == 0x20).Severity.Should().Be(Severity.High);
        findings.Single(f => f.Offset == 0x30).Severity.Should().Be(Severity.Medium);
    }

    [Fact]
    public void DetectorEngine_DedupesByKey_KeepingHighestSeverity()
    {
        // Audit Phase 11: dedupe key (detector, title, offset); highest severity wins.
        var dummy = new DummyDetector();
        var f1 = new Finding("dummy", Severity.High, "X", "", 0x10, 0.5, "", System.Collections.Immutable.ImmutableHashSet.Create("a"));
        var f2 = new Finding("dummy", Severity.Critical, "X", "", 0x10, 0.7, "", System.Collections.Immutable.ImmutableHashSet.Create("b"));
        var deduped = DetectorEngine.Dedupe(new[] { f1, f2 });
        deduped.Should().ContainSingle();
        deduped[0].Severity.Should().Be(Severity.Critical);
        deduped[0].Confidence.Should().Be(0.7);
        deduped[0].Tags.Should().BeEquivalentTo(new[] { "a", "b" });
    }

    [Fact]
    public void DefaultDetectorSet_RunsOverEmptyContextWithoutThrowing()
    {
        var engine = new DetectorEngine(DefaultDetectorSet.All());
        var findings = engine.Run(new AnalysisContext { States = System.Array.Empty<ExecutionState>() });
        findings.Should().BeEmpty();
    }

    private sealed class DummyDetector : BaseDetector
    {
        public override string Name => "dummy";
        public override IEnumerable<Finding> Analyze(AnalysisContext context) => System.Linq.Enumerable.Empty<Finding>();
    }
}
