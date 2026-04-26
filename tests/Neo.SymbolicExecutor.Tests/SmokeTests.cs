using System.Linq;
using System.Numerics;
using FluentAssertions;
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
    public void Pusha_TargetZero_PushesZeroNotDelta()
    {
        // Audit CRIT-1 fix: PUSHA with resolved target == 0 must push 0, never the negative delta.
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
        result.FinalStates[0].EvaluationStack.Single().AsConcreteInt().Should().Be(BigInteger.Zero);
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
    public void OpCodeInfo_KnowsAllCanonicalOpcodes()
    {
        foreach (var name in System.Enum.GetNames<NeoVm.OpCode>())
        {
            byte b = (byte)System.Enum.Parse<NeoVm.OpCode>(name);
            OpCodeInfo.IsDefined(b).Should().BeTrue($"opcode {name} (0x{b:X2}) should be recognized");
        }
    }
}
