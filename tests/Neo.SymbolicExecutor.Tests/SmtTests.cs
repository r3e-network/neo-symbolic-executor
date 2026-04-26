using System.Collections.Generic;
using System.Linq;
using Neo.SymbolicExecutor.Smt;
using Neo.SymbolicExecutor.Smt.Z3;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Z3 round-trip tests. Each test creates a fresh backend; if libz3 native loading fails we
/// skip via Skip.If — this matches the audit SMT plan's "smt_available marker" testing contract.
/// </summary>
public class SmtTests
{
    private static (Z3Backend? backend, bool available) TryNew()
    {
        var b = new Z3Backend();
        return (b, b.IsAvailable);
    }

    [SkippableFact]
    public void Z3_ReportsAvailable()
    {
        var (b, ok) = TryNew(); using var _ = b!;
        Skip.IfNot(ok, "Z3 native library not available");
        b!.IsAvailable.Should().BeTrue();
        b.Version.Should().NotBeNullOrEmpty();
    }

    [SkippableFact]
    public void Z3_TrivialContradictionUnsat()
    {
        var (b, ok) = TryNew(); using var _ = b!;
        Skip.IfNot(ok, "Z3 native library not available");
        var x = Expr.Sym(Sort.Int, "x");
        var conds = new List<Expression> { Expr.Eq(x, Expr.Int(0)), Expr.Gt(x, Expr.Int(0)) };
        b!.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [SkippableFact]
    public void Z3_TrivialSatProducesWitness()
    {
        var (b, ok) = TryNew(); using var _ = b!;
        Skip.IfNot(ok, "Z3 native library not available");
        var x = Expr.Sym(Sort.Int, "x");
        var conds = new List<Expression> { Expr.Gt(x, Expr.Int(0)), Expr.Lt(x, Expr.Int(10)) };
        b!.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
        var witness = b.BuildWitness(conds);
        witness.Should().NotBeNull();
        witness!.Should().ContainKey("x");
        ((System.Numerics.BigInteger)witness!["x"]).Should().BeInRange(1, 9);
    }

    [SkippableFact]
    public void Z3_QueryCacheCounted()
    {
        var (b, ok) = TryNew(); using var _ = b!;
        Skip.IfNot(ok, "Z3 native library not available");
        var x = Expr.Sym(Sort.Int, "x");
        var conds = new List<Expression> { Expr.Gt(x, Expr.Int(0)) };
        b!.IsSatisfiable(conds);
        b.IsSatisfiable(conds);  // identical -> cache hit
        var stats = b.GetStats();
        stats.Queries.Should().BeGreaterThanOrEqualTo(1);
        stats.CacheHits.Should().BeGreaterThanOrEqualTo(1);
    }

    [SkippableFact]
    public void Engine_PrunesUnreachableBranchUnderSmt()
    {
        var (backend, ok) = TryNew(); using var _ = backend!;
        Skip.IfNot(ok, "Z3 native library not available");

        // Layout: 0:NOP 1:JMPIF +4 (cond) ... fall-through:PUSH1 RET ... taken:PUSH2 RET
        // We seed a state with cond = (x > 0) AND a path condition x == 0. The taken branch is
        // unsatisfiable; the engine should prune to one final state.
        byte[] script =
        {
            (byte)NeoVm.OpCode.NOP,
            (byte)NeoVm.OpCode.JMPIF, 0x04,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = 1;
        var x = Expr.Sym(Sort.Int, "x");
        state.PathConditions = state.PathConditions.Add(Expr.Eq(x, Expr.Int(0)));
        state.Push(SymbolicValue.Of(Expr.Gt(x, Expr.Int(0))));

        var engine = new SymbolicEngine(program, new ExecutionOptions { SmtBackend = backend });
        var result = engine.Run(state);
        result.FinalStates.Length.Should().Be(1);
        result.FinalStates[0].EvaluationStack.Single().AsConcreteInt().Should().Be(System.Numerics.BigInteger.One);
        result.FinalStates[0].Telemetry.SmtPrunedBranches.Should().Be(1);
    }

    [SkippableFact]
    public void Engine_NoPruneWithoutBackend()
    {
        // Same setup as above but no backend; the engine should fork into both branches.
        byte[] script =
        {
            (byte)NeoVm.OpCode.NOP,
            (byte)NeoVm.OpCode.JMPIF, 0x04,
            (byte)NeoVm.OpCode.PUSH1,
            (byte)NeoVm.OpCode.RET,
            (byte)NeoVm.OpCode.PUSH2,
            (byte)NeoVm.OpCode.RET,
        };
        var program = ScriptDecoder.Decode(script);
        var state = new ExecutionState();
        state.CallStack.Add(new CallFrame(returnPc: -1));
        state.Pc = 1;
        var x = Expr.Sym(Sort.Int, "x");
        state.PathConditions = state.PathConditions.Add(Expr.Eq(x, Expr.Int(0)));
        state.Push(SymbolicValue.Of(Expr.Gt(x, Expr.Int(0))));

        var result = new SymbolicEngine(program).Run(state);
        result.FinalStates.Length.Should().Be(2);
    }
}
