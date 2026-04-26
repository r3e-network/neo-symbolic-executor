using System.Numerics;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    /// <summary>
    /// Resolve a runtime-supplied integer operand into a concrete <see cref="BigInteger"/>:
    /// 1. If the value is already concrete, return it.
    /// 2. Otherwise, if SMT is configured and the per-state concretization budget allows, ask
    ///    the solver for one concrete value satisfying the path conditions and an optional
    ///    [lo, hi] range. Append `value == solved` to the path conditions and return.
    /// 3. Otherwise return null (caller should terminate the state with Stopped).
    ///
    /// Phase 5 of the SMT integration plan. <see cref="ExecutionOptions.MaxConcretizations"/>
    /// caps per-state concretization to prevent path explosion.
    /// </summary>
    private BigInteger? TryConcretizeIndex(ExecutionState state, SymbolicValue value,
                                            BigInteger? lo = null, BigInteger? hi = null)
    {
        var concrete = value.AsConcreteInt();
        if (concrete is not null) return concrete;

        var backend = _options.SmtBackend;
        if (backend is null || !backend.IsAvailable) return null;
        if (state.Telemetry.SmtConcretizations >= _options.MaxConcretizations) return null;

        var solved = backend.ConcretizeInt(state.PathConditions, value.Expression, lo, hi);
        if (solved is null) return null;

        state.Telemetry.SmtConcretizations++;
        state.PathConditions = state.PathConditions.Add(Expr.Eq(value.Expression, Expr.Int(solved.Value)));
        return solved.Value;
    }
}
