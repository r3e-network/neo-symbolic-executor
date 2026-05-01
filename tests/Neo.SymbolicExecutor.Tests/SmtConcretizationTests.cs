using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Neo.SymbolicExecutor.Smt;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Tests for SMT phase 5 — concretization. Each test exercises an opcode that historically
/// halted with "requires concrete X"; under SMT, the engine asks the solver for one concrete
/// value and continues, appending an `expr == value` constraint to the path.
/// </summary>
public class SmtConcretizationTests
{
    [Fact]
    public void Concretize_NoBackend_HaltsAsBefore()
    {
        // Without an SMT backend, a symbolic PICK count must still terminate with Stopped.
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.PICK,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = 0;
        // After PUSH1/PUSH2 we have stack [1, 2]. Replace top with a symbolic count.
        state.EvaluationStack.Add(SymbolicValue.Int(1));
        state.EvaluationStack.Add(SymbolicValue.Int(2));
        state.EvaluationStack.Add(SymbolicValue.Symbol(Sort.Int, "n"));
        state.Pc = 2;  // PICK

        var result = new SymbolicEngine(program).Run(state);
        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Stopped);
        result.FinalStates[0].TerminationReason.Should().Contain("PICK requires concrete");
    }

    [Fact]
    public void TryConcretizeIndex_HelperUsesBackend()
    {
        // White-box: verify TryConcretizeIndex appends a path condition when SMT solves.
        // Use a stub backend so this white-box test stays focused on engine concretization.
        var stub = new StubBackend(new BigInteger(3));
        byte[] script =
        {
            (byte)NeoVm.OpCode.PUSH4,
            (byte)NeoVm.OpCode.NEWARRAY,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = 0;
        // Replace the PUSH4 result with a symbolic value that the stub will concretize to 3.
        state.EvaluationStack.Add(SymbolicValue.Symbol(Sort.Int, "size"));
        state.Pc = 1;  // NEWARRAY

        var engine = new SymbolicEngine(program, new ExecutionOptions { SmtBackend = stub });
        var result = engine.Run(state);

        result.FinalStates.Should().ContainSingle();
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Halted);
        result.FinalStates[0].Telemetry.SmtConcretizations.Should().Be(1);
        // Path condition was extended with `size == 3`.
        result.FinalStates[0].PathConditions.Should().ContainSingle();
    }

    [Fact]
    public void Concretize_RespectsMaxBudget()
    {
        // With MaxConcretizations=0, even a working backend must not be consulted.
        var stub = new StubBackend(new BigInteger(0));
        byte[] script = { (byte)NeoVm.OpCode.PICK, (byte)NeoVm.OpCode.RET };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.EvaluationStack.Add(SymbolicValue.Int(7));
        state.EvaluationStack.Add(SymbolicValue.Symbol(Sort.Int, "n"));
        state.Pc = 0;

        var engine = new SymbolicEngine(program, new ExecutionOptions
        {
            SmtBackend = stub,
            MaxConcretizations = 0,
        });
        var result = engine.Run(state);
        result.FinalStates[0].Status.Should().Be(TerminalStatus.Stopped);
    }

    private sealed class StubBackend : ISmtBackend
    {
        private readonly BigInteger _next;
        public StubBackend(BigInteger v) { _next = v; }
        public bool IsAvailable => true;
        public string Version => "stub-1.0";
        public int TimeoutMs => 1000;
        public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions, Expression extra) => SmtOutcome.Sat;
        public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions) => SmtOutcome.Sat;
        public IReadOnlyDictionary<string, object>? BuildWitness(IReadOnlyList<Expression> conditions) => new Dictionary<string, object>();
        public BigInteger? ConcretizeInt(IReadOnlyList<Expression> conditions, Expression target,
                                          BigInteger? lo = null, BigInteger? hi = null) => _next;
        public SmtStats GetStats() => new(1, 0, 0, 0, 1, 0);
    }
}
