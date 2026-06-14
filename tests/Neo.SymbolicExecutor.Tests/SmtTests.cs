using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Neo.SymbolicExecutor.Smt;
using Neo.SymbolicExecutor.Smt.Z3;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// SMT round-trip tests. The backend uses z3 when available and a conservative portable fallback
/// for simple integer constraints when z3 is missing.
/// </summary>
public class SmtTests
{
    [Fact]
    public void Z3_ReportsAvailable()
    {
        using var backend = new Z3Backend();
        backend.IsAvailable.Should().BeTrue();
        backend.Version.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public void Z3_TrivialContradictionUnsat()
    {
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var conds = new List<Expression> { Expr.Eq(x, Expr.Int(0)), Expr.Gt(x, Expr.Int(0)) };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Z3_TrivialSatProducesWitness()
    {
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var conds = new List<Expression> { Expr.Gt(x, Expr.Int(0)), Expr.Lt(x, Expr.Int(10)) };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(conds);
        witness.Should().NotBeNull();
        witness!.Should().ContainKey("x");
        ((System.Numerics.BigInteger)witness!["x"]).Should().BeInRange(1, 9);
    }

    [Fact]
    public void Z3_SymbolicAdditionUsesMathematicalIntegerSemantics()
    {
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var max = (System.Numerics.BigInteger.One << 255) - System.Numerics.BigInteger.One;
        var conds = new List<Expression>
        {
            Expr.Gt(Expr.Add(Expr.Int(max), x), Expr.Int(max)),
        };

        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(conds);
        witness.Should().NotBeNull();
        witness!.Should().ContainKey("x");
        ((System.Numerics.BigInteger)witness["x"]).Should().BeGreaterThan(System.Numerics.BigInteger.Zero);
    }

    [Fact]
    public void Z3_NonNegativeSymbolicAdditionCannotUnderflowBelowNeoIntegerMinimum()
    {
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var min = -(System.Numerics.BigInteger.One << 255);
        var max = (System.Numerics.BigInteger.One << 255) - System.Numerics.BigInteger.One;
        var conds = new List<Expression>
        {
            Expr.Ge(x, Expr.Int(0)),
            Expr.Lt(Expr.Add(Expr.Int(max), x), Expr.Int(min)),
        };

        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Z3_ReusesOpaqueSymbolForRepeatedUnsupportedExpression()
    {
        using var backend = new Z3Backend();
        if (!backend.IsExternalSolver)
            return;

        var x = Expr.Sym(Sort.Int, "x");
        var opaque = new TernaryExpr(Sort.Int, "modmul", Expr.Int(2), Expr.Int(3), x);
        var conds = new List<Expression>
        {
            Expr.Le(opaque, Expr.Int(10)),
            Expr.Gt(opaque, Expr.Int(10)),
        };

        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_SymbolicAdditionUsesMathematicalIntegerSemantics_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var max = (System.Numerics.BigInteger.One << 255) - System.Numerics.BigInteger.One;
        var conds = new List<Expression>
        {
            Expr.Gt(Expr.Add(Expr.Int(max), x), Expr.Int(max)),
        };

        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(conds);
        witness.Should().NotBeNull();
        witness!.Should().ContainKey("x");
        ((System.Numerics.BigInteger)witness["x"]).Should().BeGreaterThan(System.Numerics.BigInteger.Zero);
    }

    [Fact]
    public void Fallback_ReusesOpaqueSymbolForRepeatedUnsupportedExpression_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var opaque = new TernaryExpr(Sort.Int, "modmul", Expr.Int(2), Expr.Int(3), x);
        var conds = new List<Expression>
        {
            Expr.Le(opaque, Expr.Int(10)),
            Expr.Gt(opaque, Expr.Int(10)),
        };

        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_ProvesBasicConstraints_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();

        backend.IsAvailable.Should().BeTrue();
        backend.Version.Should().Contain("fallback");

        var x = Expr.Sym(Sort.Int, "x");
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(x, Expr.Int(0)),
            Expr.Gt(x, Expr.Int(0)),
        }).Should().Be(SmtOutcome.Unsat);

        var satisfiable = new List<Expression> { Expr.Gt(x, Expr.Int(0)), Expr.Lt(x, Expr.Int(10)) };
        backend.IsSatisfiable(satisfiable).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(satisfiable);
        witness.Should().NotBeNull();
        ((System.Numerics.BigInteger)witness!["x"]).Should().BeInRange(1, 9);
    }

    [Fact]
    public void Fallback_ProvesSimpleLinearArithmetic_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(Expr.Add(x, Expr.Int(1)), Expr.Int(4)),
            Expr.Ne(x, Expr.Int(3)),
        }).Should().Be(SmtOutcome.Unsat);

        var satisfiable = new List<Expression>
        {
            Expr.Gt(Expr.Add(x, Expr.Int(2)), Expr.Int(5)),
            Expr.Le(Expr.Sub(x, Expr.Int(1)), Expr.Int(9)),
        };
        backend.IsSatisfiable(satisfiable).Should().Be(SmtOutcome.Sat);
        var value = backend.ConcretizeInt(satisfiable, Expr.Add(x, Expr.Int(1)), lo: 5, hi: 11);
        value.Should().NotBeNull();
        value!.Value.Should().BeInRange(5, 11);
    }

    [Fact]
    public void Fallback_BuildsWitnessForUpperOnlyNegativeDomain_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var conditions = new List<Expression> { Expr.Lt(x, Expr.Int(-5)) };

        backend.IsSatisfiable(conditions).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(conditions);

        witness.Should().NotBeNull();
        ((System.Numerics.BigInteger)witness!["x"]).Should().BeLessThan(-5);
    }

    [Fact]
    public void Fallback_PropagatesSymbolEqualities_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var y = Expr.Sym(Sort.Int, "y");

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(x, y),
            Expr.Eq(x, Expr.Int(0)),
            Expr.Gt(y, Expr.Int(0)),
        }).Should().Be(SmtOutcome.Unsat);

        var satisfiable = new List<Expression>
        {
            Expr.Eq(Expr.Add(x, Expr.Int(2)), y),
            Expr.Eq(x, Expr.Int(3)),
        };
        backend.IsSatisfiable(satisfiable).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(satisfiable);
        witness.Should().NotBeNull();
        ((System.Numerics.BigInteger)witness!["x"]).Should().Be(3);
        ((System.Numerics.BigInteger)witness!["y"]).Should().Be(5);
    }

    [Fact]
    public void Fallback_ProvesScaledLinearArithmetic_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(Expr.Add(x, x), Expr.Int(5)),
        }).Should().Be(SmtOutcome.Unsat);

        var satisfiable = new List<Expression>
        {
            Expr.Eq(Expr.Mul(x, Expr.Int(3)), Expr.Int(12)),
            Expr.Lt(Expr.Mul(x, Expr.Int(2)), Expr.Int(9)),
        };
        backend.IsSatisfiable(satisfiable).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(satisfiable);
        witness.Should().NotBeNull();
        ((System.Numerics.BigInteger)witness!["x"]).Should().Be(4);

        var value = backend.ConcretizeInt(
            new List<Expression> { Expr.Gt(Expr.Mul(x, Expr.Int(3)), Expr.Int(10)) },
            Expr.Mul(x, Expr.Int(2)),
            lo: 8,
            hi: 20);
        value.Should().NotBeNull();
        value!.Value.Should().BeInRange(8, 20);
    }

    [Fact]
    public void Fallback_ProvesTwoSymbolLinearRelations_WhenZ3ExecutableMissing()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var y = Expr.Sym(Sort.Int, "y");

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(Expr.Add(x, y), Expr.Int(5)),
            Expr.Eq(x, Expr.Int(2)),
            Expr.Ne(y, Expr.Int(3)),
        }).Should().Be(SmtOutcome.Unsat);

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ge(x, Expr.Int(0)),
            Expr.Ge(y, Expr.Int(0)),
            Expr.Lt(Expr.Add(x, y), Expr.Int(0)),
        }).Should().Be(SmtOutcome.Unsat);

        var satisfiable = new List<Expression>
        {
            Expr.Eq(Expr.Add(x, y), Expr.Int(5)),
            Expr.Eq(x, Expr.Int(2)),
        };
        backend.IsSatisfiable(satisfiable).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(satisfiable);
        witness.Should().NotBeNull();
        ((System.Numerics.BigInteger)witness!["x"]).Should().Be(2);
        ((System.Numerics.BigInteger)witness!["y"]).Should().Be(3);
    }

    [Fact]
    public void Fallback_PreservesExistingBounds_WhenExactValueArrivesLater()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Gt(x, Expr.Int(5)),
            Expr.Eq(x, Expr.Int(2)),
        }).Should().Be(SmtOutcome.Unsat);

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(x, Expr.Int(2)),
            Expr.Gt(x, Expr.Int(5)),
        }).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_RejectsExcludedSingletonBound()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ge(x, Expr.Int(0)),
            Expr.Le(x, Expr.Int(0)),
            Expr.Ne(x, Expr.Int(0)),
        }).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Z3_QueryCacheCounted()
    {
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var conds = new List<Expression> { Expr.Gt(x, Expr.Int(0)) };
        backend.IsSatisfiable(conds);
        backend.IsSatisfiable(conds);  // identical -> cache hit
        var stats = backend.GetStats();
        stats.Queries.Should().BeGreaterThanOrEqualTo(1);
        stats.CacheHits.Should().BeGreaterThanOrEqualTo(1);
    }

    [Fact]
    public void Z3_ConcretizeIntRequestsDeclaredAuxiliaryTarget()
    {
        if (OperatingSystem.IsWindows())
            return;

        var fakeZ3 = Path.Combine(Path.GetTempPath(), $"fake-z3-{Guid.NewGuid():N}.sh");
        File.WriteAllText(fakeZ3, """
#!/usr/bin/env bash
if [[ "$*" == *"-version"* ]]; then
  echo "Z3 version fake"
  exit 0
fi

input="$(cat)"
if [[ "$input" == *"(get-value (|__target_0|))"* ]]; then
  echo "sat"
  echo "((|__target_0| (_ bv7 256)))"
else
  echo "sat"
  echo "((|wrong| (_ bv0 256)))"
fi
""");
        File.SetUnixFileMode(fakeZ3, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        try
        {
            using var restore = SetZ3Path(fakeZ3);
            using var backend = new Z3Backend();
            var x = Expr.Sym(Sort.Int, "x");

            backend.ConcretizeInt(new List<Expression> { Expr.Eq(x, Expr.Int(7)) }, x)
                .Should().Be(new System.Numerics.BigInteger(7));
        }
        finally
        {
            File.Delete(fakeZ3);
        }
    }

    [Fact]
    public void Z3_ConcreteBytePickIsTranslatedWithoutOpaqueFallback()
    {
        if (OperatingSystem.IsWindows())
            return;

        var fakeZ3 = Path.Combine(Path.GetTempPath(), $"fake-z3-{Guid.NewGuid():N}.sh");
        File.WriteAllText(fakeZ3, """
#!/usr/bin/env bash
if [[ "$*" == *"-version"* ]]; then
  echo "Z3 version fake"
  exit 0
fi

input="$(cat)"
if [[ "$input" == *"__opaque_int"* ]]; then
  echo "unknown"
elif [[ "$input" == *"(not (= 66 66))"* ]]; then
  echo "unsat"
else
  echo "unknown"
fi
""");
        File.SetUnixFileMode(fakeZ3, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

        try
        {
            using var restore = SetZ3Path(fakeZ3);
            using var backend = new Z3Backend();
            var picked = new BinaryExpr(
                Sort.Int,
                "pick",
                Expr.Bytes(new byte[] { 65, 66 }),
                Expr.Int(1));

            backend.IsSatisfiable(new List<Expression>
            {
                Expr.Ne(picked, Expr.Int(66)),
            }).Should().Be(SmtOutcome.Unsat);
        }
        finally
        {
            File.Delete(fakeZ3);
        }
    }

    [Fact]
    public void Engine_PrunesUnreachableBranchUnderSmt()
    {
        using var backend = new Z3Backend();

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

    [Fact]
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

    private static IDisposable ForceMissingZ3()
    {
        return SetZ3Path("/definitely/not/a/z3/executable");
    }

    private static IDisposable SetZ3Path(string path)
    {
        const string variable = "NEO_SYMBOLIC_EXECUTOR_Z3";
        var previous = Environment.GetEnvironmentVariable(variable);
        Environment.SetEnvironmentVariable(variable, path);
        return new RestoreEnvironmentVariable(variable, previous);
    }

    private sealed class RestoreEnvironmentVariable : IDisposable
    {
        private readonly string _name;
        private readonly string? _value;

        public RestoreEnvironmentVariable(string name, string? value)
        {
            _name = name;
            _value = value;
        }

        public void Dispose() => Environment.SetEnvironmentVariable(_name, _value);
    }
}
