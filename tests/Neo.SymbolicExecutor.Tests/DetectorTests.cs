using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;
using Neo.SymbolicExecutor.Nef;
using NeoVm = Neo.VM;

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

    [Theory]
    [InlineData("keccak256")]
    [InlineData("recoverSecp256K1")]
    [InlineData("verifyWithEd25519")]
    public void NativeContractRegistry_CryptoLibReadOnlyMethodsCoverCurrentNeoFrameworkSurface(string method)
    {
        var cryptoLibHash = System.Convert.FromHexString("726CB6E0CD8628A1350A611384688911AB75F51B");
        var call = new ExternalCall
        {
            Offset = 0x10,
            Method = method,
            TargetHash = SymbolicValue.Bytes(cryptoLibHash),
            HasReturnValue = true,
        };

        NativeContractRegistry.Default.IsBenignReadOnlyCall(call).Should().BeTrue();
    }

    [Theory]
    [InlineData("strLen")]
    [InlineData("stringSplit")]
    public void NativeContractRegistry_StdLibStringReadOnlyMethodsCoverCurrentNeoFrameworkSurface(string method)
    {
        var stdLibHash = System.Convert.FromHexString("ACCE6FD80D44E1796AA0C2C625E9E4E0CE39EFC0");
        var call = new ExternalCall
        {
            Offset = 0x10,
            Method = method,
            TargetHash = SymbolicValue.Bytes(stdLibHash),
            HasReturnValue = true,
        };

        NativeContractRegistry.Default.IsBenignReadOnlyCall(call).Should().BeTrue();
    }

    [Theory]
    [InlineData("isContract")]
    public void NativeContractRegistry_ContractManagementReadOnlyMethodsCoverCurrentNeoFrameworkSurface(string method)
    {
        var contractManagementHash = System.Convert.FromHexString("FFFDC93764DBADDD97C48F252A53EA4643FAA3FD");
        var call = new ExternalCall
        {
            Offset = 0x10,
            Method = method,
            TargetHash = SymbolicValue.Bytes(contractManagementHash),
            HasReturnValue = true,
        };

        NativeContractRegistry.Default.IsBenignReadOnlyCall(call).Should().BeTrue();
    }

    [Theory]
    [InlineData("getCandidateVote")]
    [InlineData("getCommittee")]
    [InlineData("getCommitteeAddress")]
    [InlineData("getNextBlockValidators")]
    public void NativeContractRegistry_NeoTokenGovernanceReadsCoverCurrentNeoFrameworkSurface(string method)
    {
        var neoTokenHash = System.Convert.FromHexString("EF4073A0F2B305A38EC4050E4D3D28BC40EA63F5");
        var call = new ExternalCall
        {
            Offset = 0x10,
            Method = method,
            TargetHash = SymbolicValue.Bytes(neoTokenHash),
            HasReturnValue = true,
        };

        NativeContractRegistry.Default.IsBenignReadOnlyCall(call).Should().BeTrue();
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
        // Manifest safe=true is only a trust assertion: keep the evidence visible,
        // but downgrade the severity so gates can decide how to treat it.
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
        var finding = new AccessControlDetector().Analyze(ctx).Should().ContainSingle().Subject;
        finding.Severity.Should().Be(Severity.Info);
        finding.Tags.Should().Contain("manifest-safe-assertion");
        finding.Tags.Should().Contain("missing-auth");
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
    public void UncheckedReturn_DowngradesModeledNativeReturn()
    {
        var s = NewState();
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "strLen",
            HasReturnValue = true,
            ReturnModeledNative = true,
            ReturnChecked = false,
        });

        var finding = new UncheckedReturnDetector().Analyze(Ctx(s)).Should().ContainSingle().Which;
        finding.Severity.Should().Be(Severity.Low);
        finding.Tags.Should().Contain("modeled-native-return");
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

    [Fact]
    public void Timestamp_FlagsRuntimeGetTimeReadAsInfo()
    {
        // TimestampDetector previously had no direct unit test (only listed in DefaultDetectorSet).
        var s = NewState();
        s.Telemetry.TimeAccesses.Add(0x42);
        var findings = new TimestampDetector().Analyze(Ctx(s)).ToList();
        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Info);
        findings[0].Offset.Should().Be(0x42);
        findings[0].Tags.Should().Contain("timestamp");
    }

    [Fact]
    public void Timestamp_NoFinding_WhenNoTimeAccess()
    {
        var s = NewState();
        new TimestampDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void UnknownInstructions_DedupesAcrossStates()
    {
        // Same offset reached on two different paths must produce one finding — without the
        // (kind, offset) HashSet guard, a per-state walk would emit one finding per state.
        var s1 = NewState();
        s1.Telemetry.UnknownOpcodes.Add(0x10);
        var s2 = NewState();
        s2.Telemetry.UnknownOpcodes.Add(0x10);
        var s3 = NewState();
        s3.Telemetry.UnknownOpcodes.Add(0x20);
        var findings = new UnknownInstructionsDetector().Analyze(Ctx(s1, s2, s3)).ToList();
        findings.Should().HaveCount(2);
        findings.Select(f => f.Offset).Should().BeEquivalentTo(new[] { 0x10, 0x20 });
    }

    [Fact]
    public void UnknownInstructions_SeparateBucketsForOpcodeAndSyscall()
    {
        // Dedupe key is (kind, offset) so an unknown opcode at 0x10 and an unknown syscall at
        // 0x10 produce distinct findings — the coverage-gap signal must point at both surfaces
        // independently.
        var s = NewState();
        s.Telemetry.UnknownOpcodes.Add(0x10);
        s.Telemetry.UnknownSyscalls.Add(0x10);
        var findings = new UnknownInstructionsDetector().Analyze(Ctx(s)).ToList();
        findings.Should().HaveCount(2);
        findings.Should().Contain(f => f.Title.Contains("opcode"));
        findings.Should().Contain(f => f.Title.Contains("syscall"));
    }

    [Fact]
    public void TaintFlowUpgrade_FiresWhenUpdateArgFlowsFromMethodParameter()
    {
        // Critical detector for malicious admin / caller-controlled NEF replacement.
        var s = NewState();
        var taintedNef = SymbolicValue.Symbol(Sort.Bytes, "newNef").WithTaint("arg_newNef");
        var call = new ExternalCall { Offset = 0x80, Method = "update" };
        call.Args.Add(taintedNef);
        s.Telemetry.ExternalCalls.Add(call);
        var findings = new TaintFlowUpgradeDetector().Analyze(Ctx(s)).ToList();
        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Critical);
        findings[0].Tags.Should().Contain("taint-flow");
    }

    [Fact]
    public void TaintFlowUpgrade_FiresWhenAbiParameterFlowsThroughContractCall()
    {
        byte[] contractManagement = Convert.FromHexString("fffdc93764dbaddd97c48f252a53ea4643faa3fd");
        byte[] script = Concat(
            new[]
            {
                (byte)NeoVm.OpCode.INITSLOT, (byte)0x00, (byte)0x03,
            },
            Pushdata1(contractManagement),
            Pushdata1(System.Text.Encoding.UTF8.GetBytes("update")),
            new[]
            {
                (byte)NeoVm.OpCode.PUSH15,
                (byte)NeoVm.OpCode.LDARG0,
                (byte)NeoVm.OpCode.LDARG1,
                (byte)NeoVm.OpCode.LDARG2,
                (byte)NeoVm.OpCode.PUSH3,
                (byte)NeoVm.OpCode.PACK,
            },
            Syscall("System.Contract.Call"),
            new[] { (byte)NeoVm.OpCode.RET });
        var engine = new SymbolicEngine(ScriptDecoder.Decode(script));
        var entry = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("newNef", "ByteArray"),
            new ContractParameterDefinition("newManifest", "ByteArray"),
            new ContractParameterDefinition("data", "Any"),
        });

        var result = engine.Run(entry);

        result.FinalStates.Should().ContainSingle();
        var state = result.FinalStates.Single();
        state.Status.Should().Be(TerminalStatus.Halted);
        state.Telemetry.ExternalCalls.Should().ContainSingle()
            .Which.Args.SelectMany(arg => arg.Taints)
            .Should().Contain("arg_newNef");
        var findings = new TaintFlowUpgradeDetector().Analyze(Ctx(state)).ToList();
        findings.Should().ContainSingle();
        findings[0].Severity.Should().Be(Severity.Critical);
    }

    [Fact]
    public void TaintFlowUpgrade_NoFinding_WhenUpdateArgIsConcrete()
    {
        // A hard-coded NEF blob being passed to update() is NOT a taint-flow finding even though
        // it's an upgrade — the upgradeability detector covers that, not this one.
        var s = NewState();
        var call = new ExternalCall { Offset = 0x80, Method = "update" };
        call.Args.Add(SymbolicValue.Bytes(new byte[] { 1, 2, 3 }));
        s.Telemetry.ExternalCalls.Add(call);
        new TaintFlowUpgradeDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void TaintFlowUpgrade_NoFinding_WhenCallIsNotUpdate()
    {
        // Tainted args to a non-upgrade method must not trip this detector.
        var s = NewState();
        var taintedNef = SymbolicValue.Symbol(Sort.Bytes, "newNef").WithTaint("arg_newNef");
        var call = new ExternalCall { Offset = 0x80, Method = "transfer" };
        call.Args.Add(taintedNef);
        s.Telemetry.ExternalCalls.Add(call);
        new TaintFlowUpgradeDetector().Analyze(Ctx(s)).Should().BeEmpty();
    }

    [Fact]
    public void GasExhaustion_FiresAtThreshold_NotBelow()
    {
        // Threshold is the boundary: GasCost == Threshold should fire (>= Threshold), one below should not.
        var below = NewState();
        below.Telemetry.GasCost = GasExhaustionDetector.Threshold - 1;
        new GasExhaustionDetector().Analyze(Ctx(below)).Should().BeEmpty();

        var atOrAbove = NewState();
        atOrAbove.Telemetry.GasCost = GasExhaustionDetector.Threshold;
        var findings = new GasExhaustionDetector().Analyze(Ctx(atOrAbove)).ToList();
        findings.Should().HaveCount(1);
        findings[0].Severity.Should().Be(Severity.Medium);
        findings[0].Tags.Should().Contain("gas");
    }

    [Fact]
    public void GasExhaustion_OneFindingPerHighCostState()
    {
        // Two states both over threshold should each produce a finding (no cross-state dedupe
        // here — gas cost is per-path, and the report layer dedupes by (detector, title, offset)).
        // Both findings share offset 0 / same title so the post-detector Dedupe collapses them
        // to one — verify that reduction happens at the engine layer, not the detector.
        var s1 = NewState();
        s1.Telemetry.GasCost = GasExhaustionDetector.Threshold + 1;
        var s2 = NewState();
        s2.Telemetry.GasCost = GasExhaustionDetector.Threshold + 999;
        new GasExhaustionDetector().Analyze(Ctx(s1, s2)).Should().HaveCount(2);
    }

    private sealed class DummyDetector : BaseDetector
    {
        public override string Name => "dummy";
        public override IEnumerable<Finding> Analyze(AnalysisContext context) => System.Linq.Enumerable.Empty<Finding>();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int len = parts.Sum(p => p.Length);
        byte[] result = new byte[len];
        int offset = 0;
        foreach (var part in parts)
        {
            System.Array.Copy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }

    private static byte[] Pushdata1(byte[] data)
    {
        byte[] result = new byte[data.Length + 2];
        result[0] = (byte)NeoVm.OpCode.PUSHDATA1;
        result[1] = (byte)data.Length;
        System.Array.Copy(data, 0, result, 2, data.Length);
        return result;
    }

    private static byte[] Syscall(string name)
    {
        uint hash = SyscallRegistry.ComputeHash(name);
        byte[] bytes = System.BitConverter.GetBytes(hash);
        return new[] { (byte)NeoVm.OpCode.SYSCALL, bytes[0], bytes[1], bytes[2], bytes[3] };
    }
}
