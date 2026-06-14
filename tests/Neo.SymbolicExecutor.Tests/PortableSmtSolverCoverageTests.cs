using System;
using System.Collections.Generic;
using Neo.SymbolicExecutor.Smt;
using Neo.SymbolicExecutor.Smt.Z3;

namespace Neo.SymbolicExecutor.Tests;

/// <summary>
/// Coverage tests for PortableSmtSolver paths that the existing SmtTests miss. Added before
/// the TryLinearTerm/TryAffineTerm dedup so any refactor regression on these paths surfaces
/// as a test failure rather than silent precision loss.
///
/// All tests force the portable fallback via NEO_SYMBOLIC_EXECUTOR_Z3 so the assertions
/// exercise the in-process solver — running them through external z3 would test z3, not us.
/// </summary>
public class PortableSmtSolverCoverageTests
{
    // ---- affine != (IsAffineKnownNotEqual 3-state path) ----------------------------

    [Fact]
    public void Fallback_AffineNotEqual_KnownTrueFromBoundsBelow()
    {
        // `x + 5 != 0` is provably true when x >= 0 (because x + 5 >= 5 > 0).
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        // Establish x >= 0, then assert the inequality. Conjoining `(x + 5) != 0` with `x >= 0`
        // is satisfiable (any x >= 0 satisfies both), and the portable solver should reach SAT,
        // not Unknown.
        var conds = new List<Expression>
        {
            Expr.Ge(x, Expr.Int(0)),
            Expr.Ne(Expr.Add(x, Expr.Int(5)), Expr.Int(0)),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
    }

    [Fact]
    public void Fallback_AffineNotEqual_KnownTrueFromBoundsAbove()
    {
        // `x - 5 != 0` is provably true when x <= 0. Symmetric to the above.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        var conds = new List<Expression>
        {
            Expr.Le(x, Expr.Int(0)),
            Expr.Ne(Expr.Sub(x, Expr.Int(5)), Expr.Int(0)),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
    }

    [Fact]
    public void Fallback_AffineNotEqual_ContradictsExactZero()
    {
        // `(x + 1) != 0` with x = -1 is unsatisfiable.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        var conds = new List<Expression>
        {
            Expr.Eq(x, Expr.Int(-1)),
            Expr.Ne(Expr.Add(x, Expr.Int(1)), Expr.Int(0)),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    // ---- review #27: anti-false-UNSAT pins (must never return a false UNSAT) --------

    [Fact]
    public void Fallback_SatisfiableNonlinearProduct_IsNeverUnsat()
    {
        // Review fix (#27): the portable solver must NEVER return a false UNSAT on a satisfiable
        // formula — a false UNSAT would let the verifier declare a vulnerable path infeasible
        // (unsound "proven safe"). A nonlinear product it cannot reason about precisely must
        // degrade to Unknown/Sat, never Unsat.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var y = Expr.Sym(Sort.Int, "y");
        backend.IsSatisfiable(new List<Expression> { Expr.Gt(Expr.Mul(x, y), Expr.Int(0)) })
            .Should().NotBe(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_SatisfiableMultiSymbolSum_IsNeverUnsat()
    {
        // x + y + z == 7 is satisfiable (e.g. 1 + 2 + 4); a regression that mis-folds the
        // multi-symbol affine term into a false contradiction would surface here as an UNSAT.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var y = Expr.Sym(Sort.Int, "y");
        var z = Expr.Sym(Sort.Int, "z");
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(Expr.Add(Expr.Add(x, y), z), Expr.Int(7)),
        }).Should().NotBe(SmtOutcome.Unsat);
    }

    // ---- disjoint-range UNSAT (new precision win) ----------------------------------

    [Fact]
    public void Fallback_SymbolEquality_KnownFalseWhenRangesDisjoint()
    {
        // x bounded to [10, 20], y bounded to [0, 5]; assert x == y. The disjoint bounds prove
        // UNSAT without either side being Exact. Prior to the bounds-strengthen in v0.6.0 this
        // returned Unknown and the engine could not prune the path.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var y = Expr.Sym(Sort.Int, "y");

        var conds = new List<Expression>
        {
            Expr.Ge(x, Expr.Int(10)),
            Expr.Le(x, Expr.Int(20)),
            Expr.Ge(y, Expr.Int(0)),
            Expr.Le(y, Expr.Int(5)),
            Expr.Eq(x, y),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_SymbolEquality_KnownFalseWhenRangesDisjointReversed()
    {
        // Mirror: x in [0, 5], y in [10, 20]; covers the other branch of the disjoint check.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var y = Expr.Sym(Sort.Int, "y");

        var conds = new List<Expression>
        {
            Expr.Ge(x, Expr.Int(0)),
            Expr.Le(x, Expr.Int(5)),
            Expr.Ge(y, Expr.Int(10)),
            Expr.Le(y, Expr.Int(20)),
            Expr.Eq(x, y),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_SymbolEquality_StillSatWhenRangesOverlap()
    {
        // Negative pin: when bounds overlap, the disjoint-range optimisation must not fire.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");
        var y = Expr.Sym(Sort.Int, "y");

        var conds = new List<Expression>
        {
            Expr.Ge(x, Expr.Int(0)),
            Expr.Le(x, Expr.Int(20)),
            Expr.Ge(y, Expr.Int(10)),
            Expr.Le(y, Expr.Int(30)),
            Expr.Eq(x, y),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(conds);
        witness.Should().NotBeNull();
        ((System.Numerics.BigInteger)witness!["x"]).Should().BeInRange(10, 20);
    }

    [Fact]
    public void Fallback_IntDomain_IsUnsatWhenFiniteIntervalIsFullyExcludedByNotEquals()
    {
        // x in [0, 1] with both possible values excluded has no integer solution. The portable
        // solver used to only notice the single-point version and reported SAT here, which can
        // make infeasible verification requires look reachable when z3 is unavailable.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        var conds = new List<Expression>
        {
            Expr.Ge(x, Expr.Int(0)),
            Expr.Le(x, Expr.Int(1)),
            Expr.Ne(x, Expr.Int(0)),
            Expr.Ne(x, Expr.Int(1)),
        };

        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_Or_IsUnsatWhenEveryDisjunctContradictsCurrentDomain()
    {
        // Fault obligations often arrive as `(x < lo || x > hi)` under already-known bounds.
        // Without OR splitting the fallback returned Unknown here, so no-z3 proof runs could not
        // discharge simple enum/range safety checks such as Neo call flags.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var flags = Expr.Sym(Sort.Int, "flags");

        var conds = new List<Expression>
        {
            Expr.Ge(flags, Expr.Int(0)),
            Expr.Le(flags, Expr.Int(15)),
            Expr.BoolOr(
                Expr.Lt(flags, Expr.Int(0)),
                Expr.Gt(flags, Expr.Int(15))),
        };

        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    // ---- multi-step witness fixup (the _ints.Count round-bound fix) ---------------

    [Fact]
    public void Fallback_Witness_FixesUpDeepEqualityChain()
    {
        // Build a chain a == b + 1, b == c + 1, c == d + 1, d in [0, 0]. The witness loop has
        // to propagate the d=0 fact through three rounds to land on a=3. Before the
        // MaxPropagationRounds fix the bound was equality-count + 1 (missing _ints.Count),
        // which on a chain with many domains could terminate early.
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var a = Expr.Sym(Sort.Int, "a");
        var b = Expr.Sym(Sort.Int, "b");
        var c = Expr.Sym(Sort.Int, "c");
        var d = Expr.Sym(Sort.Int, "d");

        var conds = new List<Expression>
        {
            Expr.Eq(a, Expr.Add(b, Expr.Int(1))),
            Expr.Eq(b, Expr.Add(c, Expr.Int(1))),
            Expr.Eq(c, Expr.Add(d, Expr.Int(1))),
            Expr.Eq(d, Expr.Int(0)),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(conds);
        witness.Should().NotBeNull();
        ((System.Numerics.BigInteger)witness!["a"]).Should().Be(3);
        ((System.Numerics.BigInteger)witness!["b"]).Should().Be(2);
        ((System.Numerics.BigInteger)witness!["c"]).Should().Be(1);
        ((System.Numerics.BigInteger)witness!["d"]).Should().Be(0);
    }

    // ---- bool-typed constraint pass-through ----------------------------------------

    [Fact]
    public void Fallback_BoolConst_TrueIsTriviallySat()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        backend.IsSatisfiable(new List<Expression> { BoolConst.True }).Should().Be(SmtOutcome.Sat);
    }

    [Fact]
    public void Fallback_BoolConst_FalseIsTriviallyUnsat()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        backend.IsSatisfiable(new List<Expression> { BoolConst.False }).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_OpaqueBoolPredicate_ContradictsItsNegation()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var bytes = Expr.Sym(Sort.Bytes, "message");
        var validUtf8 = new UnaryExpr(Sort.Bool, "utf8", bytes);

        backend.IsSatisfiable(new List<Expression>
        {
            validUtf8,
            Expr.Not(validUtf8),
        }).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_BoolSymbol_ContradictsItsNegation()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var exists = Expr.Sym(Sort.Bool, "storage_exists_39");

        backend.IsSatisfiable(new List<Expression>
        {
            exists,
            Expr.Not(exists),
        }).Should().Be(SmtOutcome.Unsat);
    }

    // ---- redundant double-negation -------------------------------------------------

    [Fact]
    public void Fallback_DoubleNegation_CollapsesToOriginal()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var x = Expr.Sym(Sort.Int, "x");

        // not(not(x > 0)) AND x == 0 should be UNSAT, just like x > 0 AND x == 0.
        var conds = new List<Expression>
        {
            Expr.Not(Expr.Not(Expr.Gt(x, Expr.Int(0)))),
            Expr.Eq(x, Expr.Int(0)),
        };
        backend.IsSatisfiable(conds).Should().Be(SmtOutcome.Unsat);
    }

    // ---- NeoVM byte-to-integer conversion ------------------------------------------

    [Fact]
    public void Fallback_ByteToIntegerSymbol_ProvesZeroContradiction()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var account = Expr.Sym(Sort.Bytes, "account");
        var accountInt = new UnaryExpr(Sort.Int, "b2i", account);

        var contradictory = new List<Expression>
        {
            Expr.Ne(accountInt, Expr.Int(0)),
            Expr.Eq(accountInt, Expr.Int(0)),
        };
        backend.IsSatisfiable(contradictory).Should().Be(SmtOutcome.Unsat);

        var zeroReachable = new List<Expression>
        {
            Expr.Eq(accountInt, Expr.Int(0)),
        };
        backend.IsSatisfiable(zeroReachable).Should().Be(SmtOutcome.Sat);
        var witness = backend.BuildWitness(zeroReachable);
        witness.Should().NotBeNull();
        witness.Should().ContainKey("b2i:account");
    }

    [Fact]
    public void Fallback_RawByteEquality_DoesNotUseNumericConversion()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var bytes = Expr.Sym(Sort.Bytes, "bytes");

        var rawByteConditions = new List<Expression>
        {
            Expr.Eq(bytes, Expr.Bytes(new byte[] { 1, 0 })),
            Expr.Ne(bytes, Expr.Bytes(new byte[] { 1 })),
        };
        backend.IsSatisfiable(rawByteConditions).Should().Be(
            SmtOutcome.Sat,
            "raw ByteString equality is byte-level, so [01 00] and [01] are numerically equal but byte-distinct");

        var contradictoryRawByteConditions = new List<Expression>
        {
            Expr.Eq(bytes, Expr.Bytes(new byte[] { 1, 0 })),
            Expr.Eq(bytes, Expr.Bytes(new byte[] { 1 })),
        };
        backend.IsSatisfiable(contradictoryRawByteConditions).Should().Be(
            SmtOutcome.Unsat,
            "byte-sequence equality must include length, not just numeric ByteString conversion");

        var numericByteConditions = new List<Expression>
        {
            Expr.NumEq(bytes, Expr.Int(1)),
            Expr.NumNe(bytes, Expr.Int(1)),
        };
        backend.IsSatisfiable(numericByteConditions).Should().Be(
            SmtOutcome.Unsat,
            "numeric byte comparisons deliberately use NeoVM GetInteger semantics");
    }

    [Fact]
    public void Fallback_ByteSize_KnowsConcreteLengthSpliceExpressions()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var data = Expr.Sym(Sort.Bytes, "data");
        var substr = new TernaryExpr(Sort.Bytes, "substr", data, Expr.Int(1), Expr.Int(2));
        var left = new BinaryExpr(Sort.Bytes, "left", data, Expr.Int(3));
        var right = new BinaryExpr(Sort.Bytes, "right", data, Expr.Int(4));

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new UnaryExpr(Sort.Int, "size", substr), Expr.Int(2)),
        }).Should().Be(SmtOutcome.Unsat);
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new UnaryExpr(Sort.Int, "size", left), Expr.Int(3)),
        }).Should().Be(SmtOutcome.Unsat);
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new UnaryExpr(Sort.Int, "size", right), Expr.Int(4)),
        }).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_ByteSize_KnowsSymbolicLengthSpliceExpressions()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var data = Expr.Sym(Sort.Bytes, "data");
        var n = Expr.Sym(Sort.Int, "n");
        var substr = new TernaryExpr(Sort.Bytes, "substr", data, Expr.Int(1), n);
        var left = new BinaryExpr(Sort.Bytes, "left", data, n);
        var right = new BinaryExpr(Sort.Bytes, "right", data, n);

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new UnaryExpr(Sort.Int, "size", substr), n),
        }).Should().Be(SmtOutcome.Unsat);
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new UnaryExpr(Sort.Int, "size", left), n),
        }).Should().Be(SmtOutcome.Unsat);
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new UnaryExpr(Sort.Int, "size", right), n),
        }).Should().Be(SmtOutcome.Unsat);
    }

    [Fact]
    public void Fallback_ByteSize_FixedAbiLengthExcludesNeoVmIntegerLimitFault()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var account = Expr.Sym(Sort.Bytes, "arg_account");
        var size = new UnaryExpr(Sort.Int, "size", account);

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Eq(size, Expr.Int(20)),
            Expr.Gt(size, Expr.Int(32)),
        }).Should().Be(
            SmtOutcome.Unsat,
            "Hash160 ABI entry constraints must discharge NeoVM GetInteger's 32-byte input guard");
    }

    [Fact]
    public void Fallback_BytePick_KnowsConcreteAndSpliceBytes()
    {
        using var _ = ForceMissingZ3();
        using var backend = new Z3Backend();
        var concrete = Expr.Bytes(new byte[] { 65, 66, 67 });
        var concat = new BinaryExpr(
            Sort.Bytes,
            "cat",
            Expr.Bytes(new byte[] { 1, 2 }),
            Expr.Bytes(new byte[] { 3, 4 }));
        var substr = new TernaryExpr(Sort.Bytes, "substr", concrete, Expr.Int(1), Expr.Int(2));
        var right = new BinaryExpr(Sort.Bytes, "right", concrete, Expr.Int(2));

        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new BinaryExpr(Sort.Int, "pick", concrete, Expr.Int(1)), Expr.Int(66)),
        }).Should().Be(SmtOutcome.Unsat);
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new BinaryExpr(Sort.Int, "pick", concat, Expr.Int(2)), Expr.Int(3)),
        }).Should().Be(SmtOutcome.Unsat);
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new BinaryExpr(Sort.Int, "pick", substr, Expr.Int(0)), Expr.Int(66)),
        }).Should().Be(SmtOutcome.Unsat);
        backend.IsSatisfiable(new List<Expression>
        {
            Expr.Ne(new BinaryExpr(Sort.Int, "pick", right, Expr.Int(0)), Expr.Int(66)),
        }).Should().Be(SmtOutcome.Unsat);
    }

    // ---- helpers --------------------------------------------------------------------

    private static IDisposable ForceMissingZ3() =>
        SetZ3Path("/definitely/not/a/z3/executable");

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
        public RestoreEnvironmentVariable(string name, string? value) { _name = name; _value = value; }
        public void Dispose() => Environment.SetEnvironmentVariable(_name, _value);
    }
}
