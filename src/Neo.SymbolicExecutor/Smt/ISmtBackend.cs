using System.Collections.Generic;

namespace Neo.SymbolicExecutor.Smt;

public enum SmtOutcome
{
    Sat,
    Unsat,
    Unknown,
}

/// <summary>
/// Decoupling interface so the engine can call into an optional SMT layer without taking a hard
/// dependency on Z3. The Neo.SymbolicExecutor.Smt project provides an SMT-LIB implementation
/// backed by external Z3 when available, plus a conservative portable fallback.
///
/// Soundness invariant: <see cref="SmtOutcome.Unknown"/> MUST be treated as "could be SAT" by
/// callers — the engine never prunes on UNKNOWN, only on UNSAT. This preserves over-approximation:
/// the path set with SMT enabled is a strict subset of the path set without it.
/// </summary>
public interface ISmtBackend
{
    /// <summary>True iff the backend is functional and can answer solver queries.</summary>
    bool IsAvailable { get; }

    string Version { get; }

    /// <summary>Per-query timeout in milliseconds.</summary>
    int TimeoutMs { get; }

    /// <summary>Test the satisfiability of <paramref name="conditions"/> conjoined with <paramref name="extra"/>.</summary>
    SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions, Expression extra);

    /// <summary>Test the satisfiability of <paramref name="conditions"/> alone.</summary>
    SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions);

    /// <summary>
    /// Produce a witness model: each free symbol mapped to a concrete value. Returns null when
    /// the constraint set is UNSAT or the solver returned UNKNOWN.
    /// </summary>
    IReadOnlyDictionary<string, object>? BuildWitness(IReadOnlyList<Expression> conditions);

    /// <summary>
    /// Phase 5 of the SMT integration plan: concretization. Find one concrete BigInteger value
    /// for <paramref name="target"/> consistent with <paramref name="conditions"/>, optionally
    /// bounded by [<paramref name="lo"/>, <paramref name="hi"/>] inclusive. Used by the engine
    /// when an opcode needs a concrete index but receives a symbolic one (PICK/ROLL/CALLA/NEWARRAY).
    /// Returns null on UNSAT or UNKNOWN.
    /// </summary>
    System.Numerics.BigInteger? ConcretizeInt(
        IReadOnlyList<Expression> conditions,
        Expression target,
        System.Numerics.BigInteger? lo = null,
        System.Numerics.BigInteger? hi = null);

    /// <summary>Diagnostics: query count, cache hits, unknowns. Surfaced in JSON reports.</summary>
    SmtStats GetStats();
}

public sealed record SmtStats(
    long Queries,
    long CacheHits,
    long Unknowns,
    long Timeouts,
    long Sat,
    long Unsat,
    // Number of times the SMT-LIB translator replaced an unsupported expression node with a
    // fresh unconstrained aux variable (e.g. bytes-typed predicates, modpow, ashr without an
    // integer encoding). Sound — the constraint set is over-approximated, never under — but a
    // non-zero value means SAT/UNSAT outcomes for queries on this run lost precision. Surfaced
    // in JSON reports so consumers can tell when SMT verdicts depend on opacified subterms.
    long OpaqueTranslations = 0);
