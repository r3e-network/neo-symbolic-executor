using System.Linq;
using System.Numerics;
using FluentAssertions;
using Neo.SymbolicExecutor.Nef;
using Xunit;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

public class SmokeTests
{
    private static BigInteger Bi(int i) => new(i);

    [Fact]
    public void Decode_PushPushAddRet_HasFourInstructions()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.ADD,
            (byte)NeoVm.OpCode.RET,
        };

        var program = ScriptDecoder.Decode(script);

        program.Instructions.Should().HaveCount(4);
        program.Instructions[0].OpCode.Should().Be(NeoVm.OpCode.PUSH1);
        program.Instructions[1].OpCode.Should().Be(NeoVm.OpCode.PUSH2);
        program.Instructions[2].OpCode.Should().Be(NeoVm.OpCode.ADD);
        program.Instructions[3].OpCode.Should().Be(NeoVm.OpCode.RET);
    }

    [Fact]
    public void Run_PushPushAddRet_HaltsWithThreeOnStack()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.ADD,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().HaveCount(1);
        var halted = result.FinalStates.Single();
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Should().HaveCount(1);
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(Bi(3));
    }

    [Fact]
    public void Run_MaxStepsStopMarksBudgetExceeded()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program, new ExecutionOptions { MaxSteps = 1 }).Run();

        result.BudgetExceeded.Should().BeTrue();
        result.BudgetReason.Should().Contain("max steps");
        result.Stopped.Should().ContainSingle()
            .Which.TerminationReason.Should().Contain("budget: max steps");
    }

    [Fact]
    public void Run_VisitCapStopMarksBudgetExceeded()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.JMP,
            0x00,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program, new ExecutionOptions
        {
            MaxSteps = 10,
            MaxVisitsPerOffset = 1,
        }).Run();

        result.BudgetExceeded.Should().BeTrue();
        result.BudgetReason.Should().Contain("visit cap");
        result.Stopped.Should().ContainSingle()
            .Which.TerminationReason.Should().Contain("budget: visit cap");
    }

    [Fact]
    public void Run_Call_ReturnsToContinuationAndPreservesEvaluationStack()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH2,        // 0
            (byte)NeoVm.OpCode.CALL, 0x04,   // 1: call helper at offset 5
            (byte)NeoVm.OpCode.ADD,          // 3
            (byte)NeoVm.OpCode.RET,          // 4
            (byte)NeoVm.OpCode.PUSH5,        // 5
            (byte)NeoVm.OpCode.RET,          // 6
        };
        var program = ScriptDecoder.Decode(script);

        program.Instructions[1].Target.Should().Be(5);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates[0];
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(Bi(7));
        halted.Telemetry.MaxCallStackDepth.Should().Be(2);
    }

    [Fact]
    public void Run_CallL_TargetBeyondShortCallRangeReturnsToContinuation()
    {
        byte[] script = Enumerable.Repeat((byte)NeoVm.OpCode.NOP, 143).ToArray();
        script[0] = (byte)NeoVm.OpCode.PUSH4;
        script[1] = (byte)NeoVm.OpCode.CALL_L;
        BitConverter.GetBytes(140).CopyTo(script, 2); // CALL_L at offset 1 targets offset 141.
        script[6] = (byte)NeoVm.OpCode.ADD;
        script[7] = (byte)NeoVm.OpCode.RET;
        script[141] = (byte)NeoVm.OpCode.PUSH5;
        script[142] = (byte)NeoVm.OpCode.RET;
        var program = ScriptDecoder.Decode(script);

        program.Instructions.Single(i => i.Offset == 1).Target.Should().Be(141);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates[0];
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(Bi(9));
        halted.Telemetry.MaxCallStackDepth.Should().Be(2);
    }

    [Fact]
    public void Run_Call_InvocationStackOverflowFaults()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.CALL, 0x00,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(
            program,
            new ExecutionOptions { MaxInvocationStackDepth = 1 }).Run();

        result.Faulted.Should().ContainSingle()
            .Which.TerminationReason.Should().Contain("invocation stack overflow");
    }

    [Fact]
    public void Run_ConcreteAddOverflowFaults()
    {
        byte[] script = Concat(
            PushInt256((BigInteger.One << 255) - BigInteger.One),
            new[]
            {
                (byte)NeoVm.OpCode.PUSH1,
                (byte)NeoVm.OpCode.ADD,
                (byte)NeoVm.OpCode.RET,
            });

        var result = new SymbolicEngine(ScriptDecoder.Decode(script)).Run();

        result.FinalStates.Should().ContainSingle();
        var faulted = result.FinalStates[0];
        faulted.Status.Should().Be(TerminalStatus.Faulted);
        faulted.TerminationReason.Should().Contain("integer overflow");
    }

    [Fact]
    public void Run_JmpIf_ConcreteEqualPath()
    {
        // Layout (offsets): 0:PUSH1 1:PUSH1 2:NUMEQUAL 3:JMPIF 4:[delta] 5:PUSH7 6:RET 7:PUSH8 8:RET
        // 1==1 -> true, JMPIF takes the +4 jump -> offset 7 (PUSH8) -> RET. Stack: [8].
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.NUMEQUAL,
            (byte)NeoVm.OpCode.JMPIF, 0x04,
            (byte)NeoVm.OpCode.PUSH7,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.PUSH8,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Halted);
        result.FinalStates[0].EvaluationStack.Single().AsConcreteInt().Should().Be(Bi(8));
    }

    [Fact]
    public void Run_AbortFaultsImmediately()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.ABORT,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
    }

    [Fact]
    public void Run_AssertOnConcreteFalse_Faults()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHF,
            (byte)NeoVm.OpCode.ASSERT,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Faulted);
    }

    [Fact]
    public void CrossTypeEquality_IntZeroEqualsEmptyBytes()
    {
        // Audit HIGH-2 fix: Integer(0) and ByteString(b"") must be equal per NeoVM semantics.
        var lhs = Expr.Eq(Expr.Int(0), Expr.Bytes(System.Array.Empty<byte>()));
        lhs.Should().BeOfType<BoolConst>().Which.Value.Should().BeTrue();

        var rhs = Expr.Eq(Expr.Int(1), Expr.Bytes(new byte[] { 1 }));
        rhs.Should().BeOfType<BoolConst>().Which.Value.Should().BeTrue();

        var ne = Expr.Eq(Expr.Int(1), Expr.Bytes(new byte[] { 2 }));
        ne.Should().BeOfType<BoolConst>().Which.Value.Should().BeFalse();
    }

    [Fact]
    public void Pusha_TargetZero_PushesPointerToZeroNotDelta()
    {
        // Audit CRIT-1 fix: PUSHA with resolved target == 0 must push a pointer to 0, never the negative delta.
        // Layout: offset 0: NOP, offset 1: PUSHA(operand=0xFFFFFFFF -> target = 1 + -1 = 0), then RET.
        byte[] script =
        {
            (byte)NeoVm.OpCode.NOP,
            (byte)NeoVm.OpCode.PUSHA,
            0xFF, 0xFF, 0xFF, 0xFF,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var pusha = program.Instructions[1];
        pusha.OpCode.Should().Be(NeoVm.OpCode.PUSHA);
        pusha.Target.Should().Be(0);

        var result = new SymbolicEngine(program).Run();
        result.FinalStates.Should().ContainSingle();
        var pointer = result.FinalStates[0].EvaluationStack.Single();
        pointer.Sort.Should().Be(Sort.Pointer);
        pointer.AsConcretePointer().Should().Be(0);
    }

    [Fact]
    public void Run_PushaCallA_CallsPointerTargetAndReturnsToContinuation()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH2,        // 0
            (byte)NeoVm.OpCode.PUSHA,        // 1
            0x08, 0x00, 0x00, 0x00,          // target = offset 1 + 8 = 9
            (byte)NeoVm.OpCode.CALLA,        // 6
            (byte)NeoVm.OpCode.ADD,          // 7
            (byte)NeoVm.OpCode.RET,          // 8
            (byte)NeoVm.OpCode.PUSH5,        // 9
            (byte)NeoVm.OpCode.RET,          // 10
        };
        var program = ScriptDecoder.Decode(script);

        program.Instructions[1].Target.Should().Be(9);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates[0];
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().AsConcreteInt().Should().Be(Bi(7));
        halted.Telemetry.MaxCallStackDepth.Should().Be(2);
    }

    [Fact]
    public void Run_CallaWithIntegerFaults()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.CALLA,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("CALLA requires Pointer");
    }

    [Fact]
    public void Run_TryWithoutCatchOrFinallyFaults()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.TRY, 0x00, 0x00,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("TRY requires catch or finally");
    }

    [Fact]
    public void Run_PushaIsTypePointerReturnsTrue()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSHA,
            0x06, 0x00, 0x00, 0x00,
            (byte)NeoVm.OpCode.ISTYPE,
            SymbolicEngine.StackItemTypeCodes.Pointer,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Halted);
        result.FinalStates[0].EvaluationStack.Single().AsConcreteBool().Should().BeTrue();
    }

    [Fact]
    public void StateClone_DoesNotShareTelemetry()
    {
        // Audit C1, C6 lessons: cloned states must have isolated telemetry.
        var s1 = new ExecutionState();
        s1.CallStack.Add(new CallFrame(returnPc: -1));
        s1.Telemetry.WitnessChecks.Add(0x100);

        var s2 = s1.Clone();
        s2.Telemetry.WitnessChecks.Add(0x200);

        s1.Telemetry.WitnessChecks.Should().ContainSingle().Which.Should().Be(0x100);
        s2.Telemetry.WitnessChecks.Should().HaveCount(2);
    }

    [Fact]
    public void Run_SymbolicJmpIf_ProducesTwoBranches()
    {
        // Layout: 0:NOP 1:JMPIF 2:[+5] 3:PUSH1 4:RET 5:PUSH2 6:RET
        // JMPIF target = 1 + 5 = 6 (RET). Hmm need +4 to land on PUSH2 (offset 5).
        // Actually target = offset + delta. JMPIF at 1 with delta 4 -> target = 5 (PUSH2). Good.
        byte[] script =
        {
            (byte)NeoVm.OpCode.NOP,                // 0
            (byte)NeoVm.OpCode.JMPIF, 0x04,        // 1: jump +4 on true -> offset 5
            (byte)NeoVm.OpCode.PUSH1,              // 3
            (byte)NeoVm.OpCode.RET,                // 4
            (byte)NeoVm.OpCode.PUSH2,              // 5
            (byte)NeoVm.OpCode.RET,                // 6
        };
        var program = ScriptDecoder.Decode(script);

        // Seed a state with a symbolic Bool already on the stack at the JMPIF site.
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = 1;
        state.Push(SymbolicValue.Symbol(Sort.Bool, "user_input"));

        var result = new SymbolicEngine(program).Run(state);
        result.FinalStates.Length.Should().Be(2);
        result.FinalStates.All(s => s.Status == TerminalStatus.Halted).Should().BeTrue();
        var pushed = result.FinalStates
            .Select(s => s.EvaluationStack.Single().AsConcreteInt())
            .ToHashSet();
        pushed.Should().BeEquivalentTo(new[] { (BigInteger?)Bi(1), (BigInteger?)Bi(2) });
    }

    [Fact]
    public void Run_NewArrayAppendPickItem_RoundTrips()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.NEWARRAY,
            (byte)NeoVm.OpCode.DUP,
            (byte)NeoVm.OpCode.PUSH7,
            (byte)NeoVm.OpCode.APPEND,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Halted);
        result.FinalStates[0].EvaluationStack.Single().AsConcreteInt().Should().Be(Bi(7));
    }

    [Fact]
    public void Run_PackMatchesNeoVmPopOrder()
    {
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PACK,
            (byte)NeoVm.OpCode.PUSH0,
            (byte)NeoVm.OpCode.PICKITEM,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Halted);
        result.FinalStates[0].EvaluationStack.Single().AsConcreteInt().Should().Be(Bi(2));
    }

    [Fact]
    public void Run_StoragePutThenGetSameKeyReturnsWrittenValue()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Pushdata1("alice"u8.ToArray()),
            Syscall("System.Storage.Put"),
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates[0];
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal("alice"u8.ToArray(), "Storage.Get after Storage.Put on the same key should reflect path-local storage state");
    }

    [Fact]
    public void Run_StoragePutIntegerThenGetReturnsByteStringEncoding()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Pushdata1("count"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Syscall("System.Storage.Put"),
            Syscall("System.Storage.GetContext"),
            Pushdata1("count"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().Sort.Should().Be(Sort.Bytes);
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal(new byte[] { 1 }, "Neo storage stores primitive values as byte strings");
    }

    [Fact]
    public void Run_StorageLocalPutBooleanThenGetReturnsByteStringEncoding()
    {
        byte[] script = Concat(
            Pushdata1("flag"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSHT },
            Syscall("System.Storage.Local.Put"),
            Pushdata1("flag"u8.ToArray()),
            Syscall("System.Storage.Local.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().Sort.Should().Be(Sort.Bytes);
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal(new byte[] { 1 }, "Storage.Local.Get returns the stored byte representation");
    }

    [Fact]
    public void Run_StorageDeleteThenGetSameKeyReturnsNull()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Pushdata1("alice"u8.ToArray()),
            Syscall("System.Storage.Put"),
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Delete"),
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates[0];
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().IsConcreteNull.Should()
            .BeTrue("Storage.Delete creates a path-local tombstone for the same key");
    }

    [Fact]
    public void Run_StorageAsReadOnlyThenPutFaults()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Syscall("System.Storage.AsReadOnly"),
            Pushdata1("owner"u8.ToArray()),
            Pushdata1("alice"u8.ToArray()),
            Syscall("System.Storage.Put"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        var faulted = result.Faulted.Should().ContainSingle().Subject;
        faulted.TerminationReason.Should().Contain("Storage.Put on read-only context");
    }

    [Fact]
    public void Run_StorageAsReadOnlyThenGetReadsPathLocalStorage()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Pushdata1("alice"u8.ToArray()),
            Syscall("System.Storage.Put"),
            Syscall("System.Storage.GetContext"),
            Syscall("System.Storage.AsReadOnly"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal("alice"u8.ToArray(), "Storage.AsReadOnly preserves the same contract storage area for reads");
        halted.Telemetry.StorageOps.Should().ContainSingle(op =>
            op.Kind == StorageOpKind.Get && op.ContextReadOnly);
    }

    [Fact]
    public void Run_StorageFindRecordsReadOnlyContextAfterAsReadOnly()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Syscall("System.Storage.AsReadOnly"),
            Pushdata1("prefix"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.PUSH1 },
            Syscall("System.Storage.Find"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        var halted = result.Halted.Should().ContainSingle().Subject;
        var find = halted.Telemetry.StorageOps.Should().ContainSingle(op => op.Kind == StorageOpKind.Find).Subject;
        find.ContextReadOnly.Should().BeTrue("Storage.Find should preserve telemetry for read-only storage contexts");
        find.ContextDynamic.Should().BeFalse();
    }

    [Fact]
    public void Run_RepeatedUnknownStorageGetSameKeyIsStableWithinPath()
    {
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x01, (byte)0x00 },
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.STLOC0 },
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.LDLOC0, (byte)NeoVm.OpCode.EQUAL, (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().HaveCount(2, "the first unknown read forks present and missing exactly once");
        result.FinalStates.Should().OnlyContain(s => s.Status == TerminalStatus.Halted);
        result.FinalStates.Should().OnlyContain(s =>
            s.EvaluationStack.Single().Expression.Equals(Expr.Bool(true)),
            "the second read of the same key must reuse the first read's path-local value/null");
    }

    [Fact]
    public void Run_StorageGetUsesPathConditionEqualSymbolicKeyAlias()
    {
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x00, (byte)0x02 },
            new[] { (byte)NeoVm.OpCode.LDARG0, (byte)NeoVm.OpCode.LDARG1, (byte)NeoVm.OpCode.EQUAL, (byte)NeoVm.OpCode.ASSERT },
            Syscall("System.Storage.GetContext"),
            new[] { (byte)NeoVm.OpCode.LDARG0 },
            Pushdata1("alice"u8.ToArray()),
            Syscall("System.Storage.Put"),
            Syscall("System.Storage.GetContext"),
            new[] { (byte)NeoVm.OpCode.LDARG1 },
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var state = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("left", "ByteString"),
            new ContractParameterDefinition("right", "ByteString"),
        });

        var result = engine.Run(state);

        var halted = result.Halted.Should().ContainSingle().Subject;
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal("alice"u8.ToArray(), "asserted-equal symbolic storage keys refer to the same path-local slot");
    }

    [Fact]
    public void Run_StorageGetDoesNotUseNumericEqualityAsByteStringKeyAlias()
    {
        byte[] script = Concat(
            new[] { (byte)NeoVm.OpCode.INITSLOT, (byte)0x00, (byte)0x02 },
            Syscall("System.Storage.GetContext"),
            new[] { (byte)NeoVm.OpCode.LDARG1 },
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);
        var engine = new SymbolicEngine(program);
        var state = engine.CreateMethodEntryState(0, new[]
        {
            new ContractParameterDefinition("left", "ByteString"),
            new ContractParameterDefinition("right", "ByteString"),
        });
        var left = Expr.Sym(Sort.Bytes, "arg_left");
        var right = Expr.Sym(Sort.Bytes, "arg_right");
        state.PathConditions = state.PathConditions.Add(Expr.NumEq(left, right));
        state.StorageValues[left] = SymbolicValue.Bytes("alice"u8.ToArray());

        var result = engine.Run(state);

        result.Halted.Should().HaveCount(2, "numeric equality does not prove byte-for-byte storage key equality");
        result.Halted.Should().Contain(s => s.EvaluationStack.Single().IsConcreteNull);
        result.Halted.Any(s => s.EvaluationStack.Single().Expression is Symbol symbol
            && symbol.Name.StartsWith("storage_value_", StringComparison.Ordinal))
            .Should().BeTrue();
    }

    [Fact]
    public void Run_UnknownStorageGetPresentValueCarriesStorageSizeDomain()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[]
            {
                (byte)NeoVm.OpCode.DUP,
                (byte)NeoVm.OpCode.ISNULL,
                (byte)NeoVm.OpCode.JMPIF,
                (byte)0x15,
            },
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.ROT },
            Syscall("System.Storage.Put"),
            new[] { (byte)NeoVm.OpCode.RET },
            new[] { (byte)NeoVm.OpCode.DROP, (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        result.Faulted.Should().BeEmpty();
        result.Halted.Should().HaveCount(2);
        var present = result.Halted.Single(s => s.PathConditions.Any(c => c is Symbol { Name: "storage_exists_12" }));
        present.PathConditions.Any(c => c is BinaryExpr
        {
            Op: "<=",
            Left: UnaryExpr { Op: "size", Operand: Symbol { Name: "storage_value_12" } },
            Right: IntConst right,
        } && right.Value == new BigInteger(65535))
            .Should().BeTrue("values returned by Neo N3 Storage.Get are bounded to the maximum storage item size");
    }

    [Fact]
    public void Run_RuntimeCallingScriptHashCoversEntryNullAndContractCaller()
    {
        byte[] script = Concat(
            Syscall("System.Runtime.GetCallingScriptHash"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        result.Faulted.Should().BeEmpty();
        result.Halted.Should().HaveCount(2);
        result.Halted.Should().Contain(s => s.EvaluationStack.Single().IsConcreteNull);
        var caller = result.Halted.Single(s => !s.EvaluationStack.Single().IsConcreteNull);
        caller.EvaluationStack.Single().Expression.Should().BeOfType<Symbol>()
            .Which.Name.Should().Be("calling_script_hash");
        caller.PathConditions.Any(c => c is BinaryExpr
        {
            Op: "==",
            Left: UnaryExpr { Op: "size", Operand: Symbol { Name: "calling_script_hash" } },
            Right: IntConst right,
        } && right.Value == new BigInteger(20))
            .Should().BeTrue("contract-caller hashes are UInt160 values while entry contexts have no caller");
    }

    [Fact]
    public void Run_StoragePutWithConcatenatedConcreteKeyCanBeReadByByteEquivalentKey()
    {
        byte[] script = Concat(
            Syscall("System.Storage.GetContext"),
            Pushdata1("own"u8.ToArray()),
            Pushdata1("er"u8.ToArray()),
            new[] { (byte)NeoVm.OpCode.CAT },
            Pushdata1("alice"u8.ToArray()),
            Syscall("System.Storage.Put"),
            Syscall("System.Storage.GetContext"),
            Pushdata1("owner"u8.ToArray()),
            Syscall("System.Storage.Get"),
            new[] { (byte)NeoVm.OpCode.RET });
        var program = ScriptDecoder.Decode(script);

        var result = new SymbolicEngine(program).Run();

        result.FinalStates.Should().ContainSingle();
        var halted = result.FinalStates[0];
        halted.Status.Should().Be(TerminalStatus.Halted);
        halted.EvaluationStack.Single().AsConcreteBytes().Should()
            .Equal("alice"u8.ToArray(), "Neo storage keys compare by bytes, not by symbolic expression object identity");
    }

    [Fact]
    public void OpCodeInfo_KnowsAllCanonicalOpcodes()
    {
        foreach (var name in System.Enum.GetNames<NeoVm.OpCode>())
        {
            byte b = (byte)System.Enum.Parse<NeoVm.OpCode>(name);
            OpCodeInfo.IsDefined(b).Should().BeTrue($"opcode {name} (0x{b:X2}) should be recognized");
        }
    }

    private static byte[] Syscall(string name)
    {
        uint hash = SyscallRegistry.ComputeHash(name);
        byte[] bytes = BitConverter.GetBytes(hash);
        return new[] { (byte)NeoVm.OpCode.SYSCALL, bytes[0], bytes[1], bytes[2], bytes[3] };
    }

    private static byte[] Pushdata1(byte[] data)
    {
        byte[] result = new byte[data.Length + 2];
        result[0] = (byte)NeoVm.OpCode.PUSHDATA1;
        result[1] = (byte)data.Length;
        Array.Copy(data, 0, result, 2, data.Length);
        return result;
    }

    private static byte[] PushInt256(BigInteger value)
    {
        byte[] result = new byte[33];
        result[0] = (byte)NeoVm.OpCode.PUSHINT256;
        byte[] encoded = value.ToByteArray(isUnsigned: false, isBigEndian: false);
        encoded.CopyTo(result, 1);
        return result;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        int len = parts.Sum(p => p.Length);
        byte[] result = new byte[len];
        int offset = 0;
        foreach (var part in parts)
        {
            Array.Copy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }
}
