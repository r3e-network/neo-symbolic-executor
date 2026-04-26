using System.Linq;
using Neo.SymbolicExecutor.Detectors;
using Neo.SymbolicExecutor.Detectors.Detectors;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Locked-in regressions for the C# audit findings (iter 10). Each test names the audit
/// finding number it covers.
/// </summary>
public class AuditFixesTests
{
    [Fact]
    public void TryFinally_PreservesPostFinallyContinuation_AuditFinding1()
    {
        // Layout: TRY catch=0,finally=4 ; PUSH1 ; ENDTRY +4 ; PUSH7 ; ENDFINALLY ; PUSH9 ; RET
        //         0    1                  4       5    6      8       9            10     11
        // The TRY operand is 2 bytes (sbyte catch, sbyte finally). We use catch=0 (no catch)
        // and finally=8 (relative to TRY at offset 0 -> offset 8 = ENDFINALLY's predecessor PUSH7).
        // Actually let me build a script that exercises the post-finally continuation.
        //
        // Layout (offsets in [brackets]):
        //   [0] TRY 0,6   (catch=none, finally=offset 0+6=6 = PUSH7)
        //   [3] PUSH1     (try-body)
        //   [4] ENDTRY +4 (post-try resume = 4+4 = 8 = PUSH9)
        //   [6] PUSH7     (finally body)
        //   [7] ENDFINALLY
        //   [8] PUSH9     (post-finally continuation — must resume here)
        //   [9] RET
        // Expected stack at halt: [1, 7, 9].
        byte[] script =
        {
            (byte)NeoVm.OpCode.TRY, 0x00, 0x06,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.ENDTRY, 0x04,
            (byte)NeoVm.OpCode.PUSH7,
            (byte)NeoVm.OpCode.ENDFINALLY,
            (byte)NeoVm.OpCode.PUSH9,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        var s = result.FinalStates.Single();
        s.Status.Should().Be(TerminalStatus.Halted);
        // After try-body PUSH1, finally runs PUSH7, ENDFINALLY resumes at PUSH9. Stack: [1, 7, 9].
        s.EvaluationStack.Should().HaveCount(3);
        s.EvaluationStack.Last().AsConcreteInt().Should().Be(new System.Numerics.BigInteger(9));
    }

    [Fact]
    public void Upgradeability_DoesNotFireOnUserlandUpdateBalance_AuditFinding12()
    {
        // Audit C# #12: "update" / "destroy" matched as substring → updateBalance fired.
        // Now must require exact name AND (concrete ContractManagement target OR null target).
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "updateBalance",   // userland method, NOT ContractManagement.update
            TargetHash = SymbolicValue.Bytes(new byte[20]),  // some concrete non-CM hash
            HasReturnValue = true,
        });
        var ctx = new AnalysisContext { States = new[] { s } };
        new UpgradeabilityDetector().Analyze(ctx).Should().BeEmpty();
    }

    [Fact]
    public void Upgradeability_FiresOnContractManagementUpdate_AuditFinding12()
    {
        var cmHash = System.Convert.FromHexString("fffdc93764dbaddd97c48f252a53ea4643faa3fd");
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "update",
            TargetHash = SymbolicValue.Bytes(cmHash),
            HasReturnValue = false,
        });
        var ctx = new AnalysisContext { States = new[] { s } };
        new UpgradeabilityDetector().Analyze(ctx).Should().NotBeEmpty();
    }

    [Fact]
    public void AccessControl_UnenforcedWitness_FiresEvenWithUnrelatedCallerHash_AuditFinding11()
    {
        // Audit C# #11: was suppressed when callerChecks/sigChecks coexisted with the
        // unenforced witness. Should now fire regardless.
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        s.Telemetry.WitnessChecks.Add(0x05);                 // CheckWitness invoked
        // ...but never enforced (WitnessChecksEnforced is empty)
        s.Telemetry.CallerHashChecks.Add(0x07);               // unrelated caller-hash signal
        s.Telemetry.StorageOps.Add(new StorageOp(0x20, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(0), false, false));

        var ctx = new AnalysisContext { States = new[] { s } };
        var findings = new AccessControlDetector().Analyze(ctx).ToList();
        findings.Should().Contain(f => f.Tags.Contains("unenforced-witness"));
    }

    [Fact]
    public void GasExhaustion_AccumulatesOnSyscalls_AuditFinding6()
    {
        // Audit C# #6: GasCost was never updated. Each syscall must add its declared price.
        uint chk = SyscallRegistry.ComputeHash("System.Runtime.CheckWitness");
        byte[] hashBytes = System.BitConverter.GetBytes(chk);

        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHNULL,                  // pubkey arg
            (byte)NeoVm.OpCode.SYSCALL, hashBytes[0], hashBytes[1], hashBytes[2], hashBytes[3],
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Telemetry.GasCost.Should().BeGreaterThan(0);
    }

    [Fact]
    public void Manifest_TolaratesNonObjectArrayItems_AuditFinding28()
    {
        // Numbers / strings / arrays inside what should be object arrays should be skipped,
        // not crash with InvalidOperationException.
        var manifestJson = """
        {
          "name":"X","groups":[1,2,"hi"],"features":{},"supportedstandards":["NEP-17", 5],
          "abi":{"methods":[{"name":"f","parameters":[],"returntype":"Void","offset":0,"safe":false}, 99],
                 "events":[{"name":"E","parameters":[7]}, "string-event"]},
          "permissions":[{"contract":"*","methods":"*"}, 42],
          "trusts":["bad", 3, true]
        }
        """;
        var act = () => Nef.ContractManifest.FromJson(manifestJson);
        act.Should().NotThrow();
        var m = Nef.ContractManifest.FromJson(manifestJson);
        m.Abi.Methods.Should().ContainSingle();
        m.Abi.Events.Should().ContainSingle();
        m.Permissions.Should().ContainSingle();
        m.SupportedStandards.Should().Contain("NEP-17");
    }

    [Fact]
    public void Statistics_TotalAndCrashCounters_ReturnRealValues_AuditFinding23()
    {
        var s = new Neo.SymbolicExecutor.Fuzzer.Statistics();
        s.Total.Should().Be(0);
        s.TotalCrashesNow.Should().Be(0);
        s.RecordIteration("a");
        s.RecordIteration("b");
        s.RecordCrash("a");
        s.Total.Should().Be(2);
        s.TotalCrashesNow.Should().Be(1);
        s.IterationsFor("a").Should().Be(1);
        s.CrashesFor("a").Should().Be(1);
    }

    [Fact]
    public void Heap_IdNotConsumedOnFactoryThrow_AuditFinding32()
    {
        // Audit #32: id was bumped before factory ran, leaving a gap on a throwing factory.
        var heap = new Heap();
        var a1 = heap.NewArray();
        int firstId = a1.Id;
        // Trigger an exception inside the factory by passing items that exceed collection size.
        try
        {
            heap.Allocate<ArrayObject>(_ => throw new System.InvalidOperationException("test"));
        }
        catch (System.InvalidOperationException) { /* expected */ }
        var a2 = heap.NewArray();
        a2.Id.Should().Be(firstId + 1, "the throwing allocate must not consume an id");
    }

    [Fact]
    public void DefaultDetectorSet_ReturnsSameInstance_AuditPerf()
    {
        // Audit C# perf (iter 12): cached detector list saves millions of allocations/sec under
        // fuzz load. Verify reference equality.
        var a = Detectors.DefaultDetectorSet.All();
        var b = Detectors.DefaultDetectorSet.All();
        a.Should().BeSameAs(b);
    }

    // ---------- Iteration-2 audit fixes (2026-04-27 detector + engine audit) ----------

    [Fact]
    public void Dos_IteratorFinding_OffsetIsDeterministic_DetectorAuditH1()
    {
        // Audit detector H1: DosDetector used HashSet enumerator order, producing different
        // finding offsets across runs of identical telemetry.
        var s1 = MakeStateWithIteratorLoops(0x10, 0x80, 0x20);
        var s2 = MakeStateWithIteratorLoops(0x80, 0x20, 0x10);  // same set, different insertion order
        var d = new DosDetector();
        var f1 = d.Analyze(new AnalysisContext { States = new[] { s1 } }).ToList();
        var f2 = d.Analyze(new AnalysisContext { States = new[] { s2 } }).ToList();
        f1.Should().NotBeEmpty();
        f1[0].Offset.Should().Be(0x10);
        f1[0].Offset.Should().Be(f2[0].Offset, "deterministic min offset");
        f1[0].DedupeKey.Should().Be(f2[0].DedupeKey);
    }

    private static ExecutionState MakeStateWithIteratorLoops(params int[] loops)
    {
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        foreach (var off in loops) s.Telemetry.IteratorLoops.Add(off);
        s.Telemetry.StorageOps.Add(new StorageOp(0x100, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(0), false, false));
        s.Status = TerminalStatus.Halted;
        return s;
    }

    [Fact]
    public void AdminCentralization_OffsetIsDeterministic_DetectorAuditH2()
    {
        // Audit detector H2: read first element of WitnessChecksEnforced HashSet → unstable.
        var s1 = MakeStateWithEnforcedWitnesses(0x100, 0x40, 0x80);
        var s2 = MakeStateWithEnforcedWitnesses(0x80, 0x100, 0x40);
        var d = new AdminCentralizationDetector();
        // Limit to 1 enforced for the detector to fire (it requires Count==1). For the
        // determinism test we use a separate single-witness assertion.
        var single1 = MakeStateWithEnforcedWitnesses(0x40);
        var single2 = MakeStateWithEnforcedWitnesses(0x40);
        var f1 = d.Analyze(new AnalysisContext { States = new[] { single1 } }).ToList();
        var f2 = d.Analyze(new AnalysisContext { States = new[] { single2 } }).ToList();
        f1.Should().ContainSingle();
        f2.Should().ContainSingle();
        f1[0].Offset.Should().Be(0x40);
        f1[0].DedupeKey.Should().Be(f2[0].DedupeKey);
        // And: the count-≠1 case never fires (existing behavior preserved).
        d.Analyze(new AnalysisContext { States = new[] { s1 } }).Should().BeEmpty();
    }

    private static ExecutionState MakeStateWithEnforcedWitnesses(params int[] offsets)
    {
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        foreach (var off in offsets) s.Telemetry.WitnessChecksEnforced.Add(off);
        s.Telemetry.StorageOps.Add(new StorageOp(0x200, StorageOpKind.Put,
            SymbolicValue.Bytes(new byte[] { 1 }), SymbolicValue.Int(0), false, false));
        s.Status = TerminalStatus.Halted;
        return s;
    }

    [Fact]
    public void GatePolicy_FailOnInfo_PassesOnEmptyFindings_DetectorAuditH5()
    {
        // Audit detector H5: empty findings returned OverallMaxSeverity=Info (sentinel),
        // which made `FailOnMaxSeverity=Info` falsely fire on a clean run.
        var risk = RiskProfile.FromFindings(System.Array.Empty<Finding>());
        var gate = new GatePolicy { FailOnMaxSeverity = Severity.Info }
            .Evaluate(System.Array.Empty<Finding>(), risk);
        gate.Passed.Should().BeTrue("zero findings cannot exceed any severity threshold");
        gate.Violations.Should().BeEmpty();
    }

    [Fact]
    public void Upgradeability_RejectsNon20ByteHash_DetectorAuditH6()
    {
        // Audit detector H6: IsContractManagement was missing a length validation, so
        // adversarial 19/21-byte values from malformed PUSHDATA were silently lookups.
        var s = new ExecutionState();
        s.CallStack.Add(new CallFrame(returnPc: -1));
        s.Telemetry.ExternalCalls.Add(new ExternalCall
        {
            Offset = 0x10,
            Method = "update",
            TargetHash = SymbolicValue.Bytes(new byte[] { 0xff }), // 1 byte — clearly malformed
        });
        var ctx = new AnalysisContext { States = new[] { s } };
        // Detector should not crash and should not fire (no concrete CM target, no null target).
        new UpgradeabilityDetector().Analyze(ctx).Should().BeEmpty();
    }

    [Fact]
    public void IsType_FaultsOnUndefinedTypeByte_EngineAuditH4()
    {
        // Audit engine H4: ISTYPE on undefined / Any byte returned false silently.
        // Now matches NeoVM and faults.
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.ISTYPE, 0xFF,   // 0xFF — undefined StackItemType
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
    }

    [Fact]
    public void IsType_FaultsOnAnyTypeByte_EngineAuditH4()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.ISTYPE, 0x00,   // Any
            (byte)NeoVm.OpCode.RET,
        };
        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();
        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
    }

    [Fact]
    public void Convert_FaultsOnUnsupportedPair_EngineAuditH1()
    {
        // Audit engine H1: CONVERT used to forward the input unchanged for unsupported pairs,
        // letting Buffer-shaped values flow through ISTYPE Integer checks. Now faults.
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHNULL,
            (byte)NeoVm.OpCode.CONVERT, 0x21,   // Null → Integer is not a defined conversion
            (byte)NeoVm.OpCode.RET,
        };
        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();
        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
    }

    [Fact]
    public void Initslot_FaultsOnDoubleInit_EngineAuditM1()
    {
        // Audit engine M1: INITSLOT could be called twice, growing the slot table silently.
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSLOT, 0x01, 0x00,
            (byte)NeoVm.OpCode.INITSLOT, 0x01, 0x00,    // <— must fault
            (byte)NeoVm.OpCode.RET,
        };
        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();
        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
    }

    [Fact]
    public void Initsslot_FaultsOnDoubleInit_EngineAuditL3()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.INITSSLOT, 0x02,
            (byte)NeoVm.OpCode.INITSSLOT, 0x02,    // <— must fault
            (byte)NeoVm.OpCode.RET,
        };
        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();
        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
    }

    [Fact]
    public void NewArrayT_PrefillsTypeAppropriateDefault_EngineAuditH5()
    {
        // Audit engine H5: NEWARRAY_T silently ignored the type byte, so cells were always Null
        // even when the spec said "fill with Integer.Zero" or "Boolean.False".
        // Build: PUSH3 ; NEWARRAY_T 0x21 (Integer) ; PUSH0 ; PICKITEM ; ISTYPE 0x21 (Integer) ; RET
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH3,
            (byte)NeoVm.OpCode.NEWARRAY_T, 0x21,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.ISTYPE, 0x21,
            (byte)NeoVm.OpCode.RET,
        };
        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();
        result.FinalStates.Should().ContainSingle();
        var s = result.FinalStates[0];
        s.Status.Should().Be(TerminalStatus.Halted);
        s.EvaluationStack.Should().ContainSingle();
        s.EvaluationStack[0].AsConcreteBool().Should().Be(true,
            "NEWARRAY_T with Integer should prefill cells as Integer(0), so ISTYPE Integer is true");
    }

    [Fact]
    public void Eq_NullVsSymbolicBytes_RemainsSymbolic_EngineAuditM4()
    {
        // Audit engine M4: Eq used to collapse to BoolConst.False when one side is Null and the
        // other is symbolic, hiding any contract that branches on a maybe-null argument.
        var symBytes = Expr.Sym(Sort.Bytes, "arg0");
        var result = Expr.Eq(symBytes, Expr.Null());
        result.Should().BeOfType<BinaryExpr>("symbolic operand prevents proving non-null at compile time");
    }
}
