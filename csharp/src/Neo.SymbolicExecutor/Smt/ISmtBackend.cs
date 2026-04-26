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
/// dependency on Z3. The Neo.SymbolicExecutor.Smt project provides the Z3-backed implementation.
///
/// Soundness invariant: <see cref="SmtOutcome.Unknown"/> MUST be treated as "could be SAT" by
/// callers — the engine never prunes on UNKNOWN, only on UNSAT. This preserves over-approximation:
/// the path set with SMT enabled is a strict subset of the path set without it.
/// </summary>
public interface ISmtBackend
{
    /// <summary>True iff the backend is functional (z3 native libs loaded successfully).</summary>
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

    /// <summary>Diagnostics: query count, cache hits, unknowns. Surfaced in JSON reports.</summary>
    SmtStats GetStats();
}

public sealed record SmtStats(
    long Queries,
    long CacheHits,
    long Unknowns,
    long Timeouts,
    long Sat,
    long Unsat);
