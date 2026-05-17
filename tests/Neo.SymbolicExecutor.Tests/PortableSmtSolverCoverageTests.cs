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
