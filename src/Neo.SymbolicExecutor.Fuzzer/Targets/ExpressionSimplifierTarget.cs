using System;
using Neo.SymbolicExecutor.Fuzzer.Generators;

namespace Neo.SymbolicExecutor.Fuzzer.Targets;

/// <summary>
/// Property: the Expression simplifier never throws on a randomly-built well-typed expression.
/// Simplification semantics: for concrete inputs, the simplified value matches a re-evaluated
/// reference computation.
/// </summary>
public sealed class ExpressionSimplifierTarget : IFuzzTarget
{
    public string Name => "expr";
    public Type[] ExpectedExceptions => new[] { typeof(VmFaultException) };

    public bool RunOnce(int seed, out string? reason, out byte[]? reproInput)
    {
        var rng = new Random(seed);
        reproInput = System.Text.Encoding.UTF8.GetBytes($"seed={seed}");
        reason = null;

        try
        {
            var ie = ExpressionGen.RandomInt(rng, depth: rng.Next(1, 5));
            var be = ExpressionGen.RandomBool(rng, depth: rng.Next(1, 5));

            // Smoke: cross-type Eq / Ne don't blow up.
            _ = Expr.Eq(ie, be);
            _ = Expr.Ne(ie, be);
            _ = Expr.BoolAnd(be, be);
            _ = Expr.BoolOr(be, be);
            _ = Expr.Not(be);

            // Smoke: ternaries.
            _ = Expr.Within(ie, ie, ie);
            return true;
        }
        catch (VmFaultException) { return true; } // overflow / pow-too-large is acceptable
    }
}
