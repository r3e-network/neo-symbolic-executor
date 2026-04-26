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
}
