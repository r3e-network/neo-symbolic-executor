using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;

namespace Neo.SymbolicExecutor.Tests;

public class AdditionalDetectorTests
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
    public void DangerousCallFlags_FlagsCallFlagsAll()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "x", CallFlags = 0x0F, HasReturnValue = true });
        var f = new DangerousCallFlagsDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.High);
        f[0].Tags.Should().Contain("callflags-all");
    }

    [Fact]
    public void DangerousCallFlags_FlagsBroadFlagsBitcountThree()
    {
        var s = NewState();
        // 0x07 = WriteStates|AllowCall|AllowNotify (3 bits) — audit fix: should fire even though != 0x0F.
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "x", CallFlags = 0x07, HasReturnValue = true });
        var f = new DangerousCallFlagsDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.Medium);
        f[0].Tags.Should().Contain("broad-call-flags");
    }

    [Fact]
    public void Dos_FlagsDeepRecursion()
    {
        var s = NewState();
        s.Telemetry.MaxCallStackDepth = 16;
        var f = new DosDetector().Analyze(Ctx(s)).ToList();
        f.Should().Contain(x => x.Tags.Contains("recursion-dos"));
    }

    [Fact]
    public void Randomness_FlagsTimestampInPathCondition()
    {
        var s = NewState();
        s.Telemetry.TimeAccesses.Add(0x10);
        s.PathConditions = s.PathConditions.Add(Expr.Eq(Expr.Sym(Sort.Int, "timestamp"), Expr.Int(123)));
        var f = new RandomnessDetector().Analyze(Ctx(s)).ToList();
        f.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("weak-randomness"));
    }

    [Fact]
    public void Randomness_GetRandomIsInfo_NotMedium()
    {
        // Audit fix: GetRandom is Neo N3's secure VRF; should be INFO, not MEDIUM.
        var s = NewState();
        s.Telemetry.RandomnessAccesses.Add(0x20);
        var f = new RandomnessDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle(x => x.Severity == Severity.Info && x.Tags.Contains("vrf"));
    }

    [Fact]
    public void Upgradeability_CriticalWithoutAuth()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "update", HasReturnValue = false });
        var f = new UpgradeabilityDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void Upgradeability_HighWhenAuthEnforced()
    {
        var s = NewState();
        s.Telemetry.WitnessChecksEnforced.Add(0x05);
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "destroy", HasReturnValue = false });
        var f = new UpgradeabilityDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Severity.Should().Be(Severity.High);
    }

    [Fact]
    public void Permissions_FlagsFullWildcard()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"X","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[],"events":[]},
             "permissions":[{"contract":"*","methods":"*"}],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new PermissionsDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Severity == Severity.High && x.Tags.Contains("permissions-wildcard"));
    }

    [Fact]
    public void Permissions_FlagsTrustsWildcard()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"X","groups":[],"features":{},"supportedstandards":[],
             "abi":{"methods":[],"events":[]},
             "permissions":[],"trusts":"*"}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new PermissionsDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Tags.Contains("trusts-wildcard"));
    }

    [Fact]
    public void Nep17_FiresWhenStandardDeclaredButMethodMissing()
    {
        var manifest = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-17"],
             "abi":{"methods":[{"name":"transfer","parameters":[],"returntype":"Boolean","offset":0,"safe":false}],
                    "events":[]},
             "permissions":[],"trusts":[]}
        """);
        var ctx = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = manifest };
        var f = new Nep17ComplianceDetector().Analyze(ctx).ToList();
        f.Should().Contain(x => x.Title.Contains("symbol"));
        f.Should().Contain(x => x.Title.Contains("balanceOf"));
        f.Should().Contain(x => x.Title.Contains("Transfer event"));
    }

    [Fact]
    public void Nep11_FiresOnlyWhenStandardDeclared()
    {
        var nep17Only = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-17"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctxNo = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = nep17Only };
        new Nep11ComplianceDetector().Analyze(ctxNo).Should().BeEmpty();

        var nep11 = Nef.ContractManifest.FromJson("""
            {"name":"T","groups":[],"features":{},"supportedstandards":["NEP-11"],
             "abi":{"methods":[],"events":[]},"permissions":[],"trusts":[]}
        """);
        var ctxYes = new AnalysisContext { States = new System.Collections.Generic.List<ExecutionState>(), Manifest = nep11 };
        new Nep11ComplianceDetector().Analyze(ctxYes).Should().NotBeEmpty();
    }

    [Fact]
    public void CallbackReentry_FlagsTransferBeforePostWriteState()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall { Offset = 0x10, Method = "transfer", HasReturnValue = true });
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(1), false, false));
        var f = new CallbackReentryDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Tags.Should().Contain("callback-reentry");
    }

    [Fact]
    public void CryptoBypass_FlagsUnusedSigCheck()
    {
        var s = NewState();
        s.Telemetry.SignatureChecks.Add(0x20);
        // No path condition mentions sig_ok_<offset>.
        var f = new CryptoVerificationBypassDetector().Analyze(Ctx(s)).ToList();
        f.Should().ContainSingle();
        f[0].Tags.Should().Contain("crypto-bypass");
    }

    [Fact]
    public void CryptoBypass_SkipsSigCheckUsedInBranch()
    {
        var s = NewState();
        s.Telemetry.SignatureChecks.Add(0x20);
        s.PathConditions = s.PathConditions.Add(Expr.Sym(Sort.Bool, "sig_ok_32"));
        new CryptoVerificationBypassDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void StorageCollision_NamespacedKeysAreNotFlagged()
    {
        // Audit fix: "balance:" is a prefix of "balance:total" but the separator ':' makes it
        // a legitimate namespace, not a collision.
        var s = NewState();
        s.Telemetry.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("balance:")), SymbolicValue.Int(0), false, false));
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(System.Text.Encoding.UTF8.GetBytes("balance:total")), SymbolicValue.Int(0), false, false));
        new StorageCollisionDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void StorageCollision_TrueOverlapIsFlagged()
    {
        var s = NewState();
        s.Telemetry.StorageOps.Add(new StorageOp(0x10, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1, 2 }), SymbolicValue.Int(0), false, false));
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1, 2, 3 }), SymbolicValue.Int(0), false, false));
        new StorageCollisionDetector().Analyze(Ctx(s)).Should().ContainSingle();
    }

    [Fact]
    public void DefaultDetectorSet_HasAllAuditDrivenDetectors()
    {
        var detectors = DefaultDetectorSet.All();
        var names = detectors.Select(d => d.Name).ToHashSet();
        names.Should().Contain(new[]
        {
            "reentrancy", "access_control", "overflow", "unchecked_return", "dynamic_call_target",
            "dangerous_call_flags", "dos", "gas_exhaustion", "randomness", "timestamp",
            "storage_collision", "upgradeability", "permissions", "admin_centralization",
            "nep17_compliance", "unknown_instructions",
            // 5 audit-derived new detectors
            "nep11_compliance", "callback_reentry", "crypto_verification_bypass",
            "replay_attack", "taint_flow_upgrade",
        });
        detectors.Should().HaveCountGreaterThanOrEqualTo(21);
    }
}
