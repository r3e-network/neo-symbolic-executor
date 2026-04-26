using System;
using System.Numerics;

namespace Neo.SymbolicExecutor.Fuzzer.Generators;

/// <summary>Random Expression IR generator. Used to stress simplifiers and SMT translator.</summary>
public static class ExpressionGen
{
    public static Expression RandomInt(Random rng, int depth = 3)
    {
        if (depth <= 0 || rng.Next(3) == 0)
        {
            return rng.Next(3) switch
            {
                0 => Expr.Int(rng.Next()),
                1 => Expr.Int(new BigInteger(rng.Next()) * new BigInteger(rng.Next())),
                _ => Expr.Sym(Sort.Int, $"i{rng.Next() & 0xFFF}"),
            };
        }
        var unary = new Func<Expression, Expression>[] { Expr.Neg, Expr.Abs, Expr.Sign, Expr.Invert, Expr.Inc, Expr.Dec };
        var binary = new Func<Expression, Expression, Expression>[]
        {
            Expr.Add, Expr.Sub, Expr.Mul, Expr.And, Expr.Or, Expr.Xor, Expr.Min, Expr.Max,
        };
        if (rng.Next(2) == 0)
            return unary[rng.Next(unary.Length)](RandomInt(rng, depth - 1));
        return binary[rng.Next(binary.Length)](RandomInt(rng, depth - 1), RandomInt(rng, depth - 1));
    }

    public static Expression RandomBool(Random rng, int depth = 3)
    {
        if (depth <= 0 || rng.Next(3) == 0)
        {
            return rng.Next(3) switch
            {
                0 => Expr.Bool(rng.Next(2) == 0),
                1 => Expr.Sym(Sort.Bool, $"b{rng.Next() & 0xFFF}"),
                _ => Expr.Eq(RandomInt(rng, 1), RandomInt(rng, 1)),
            };
        }
        return rng.Next(6) switch
        {
            0 => Expr.Eq(RandomInt(rng, depth - 1), RandomInt(rng, depth - 1)),
            1 => Expr.Lt(RandomInt(rng, depth - 1), RandomInt(rng, depth - 1)),
            2 => Expr.Le(RandomInt(rng, depth - 1), RandomInt(rng, depth - 1)),
            3 => Expr.Gt(RandomInt(rng, depth - 1), RandomInt(rng, depth - 1)),
            4 => Expr.BoolAnd(RandomBool(rng, depth - 1), RandomBool(rng, depth - 1)),
            _ => Expr.Not(RandomBool(rng, depth - 1)),
        };
    }
}
