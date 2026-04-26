using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using Microsoft.Z3;
using Neo.SymbolicExecutor;
using Neo.SymbolicExecutor.Smt;

namespace Neo.SymbolicExecutor.Smt.Z3;

/// <summary>
/// Z3-backed implementation of <see cref="ISmtBackend"/>. Translates the engine's
/// <see cref="Expression"/> IR into Z3 BitVec/Bool/Array sorts and answers SAT queries with a
/// per-query timeout.
///
/// Sort mapping (per the audit's SMT integration plan):
///   Sort.Int   -> BitVec(256), signed comparisons via SLT/SLE/SGT/SGE
///   Sort.Bool  -> z3 Bool
///   Sort.Bytes -> bounded Array(BitVec(32), BitVec(8)) + companion length symbol
///   Sort.Null  -> a fresh uninterpreted sort with a single inhabitant
///   HeapRef    -> uninterpreted sort with object-id integer field (equality-only)
///
/// Soundness: any expression we can't translate is wrapped in a fresh symbol of the right sort.
/// That degrades the query's precision (the solver may return UNKNOWN) but never makes a UNSAT
/// answer wrong. The engine treats UNKNOWN as "could be SAT" and never prunes on it.
/// </summary>
public sealed class Z3Backend : ISmtBackend, IDisposable
{
    public const int IntegerBits = 256;
    public const int BytesIndexBits = 32;

    private readonly Context _ctx;
    private readonly int _timeoutMs;
    private readonly int _bytesBound;
    // _timeouts is folded into _unknowns since Z3 reports timeout as Status.UNKNOWN.
    private long _queries, _cacheHits, _unknowns, _sat, _unsat;
    private readonly Dictionary<long, SmtOutcome> _queryCache = new();
    private bool _disposed;

    public bool IsAvailable { get; }
    public string Version { get; }
    public int TimeoutMs => _timeoutMs;
    public int BytesBound => _bytesBound;

    public Z3Backend(int timeoutMs = 5000, int bytesBound = 64)
    {
        _timeoutMs = timeoutMs;
        _bytesBound = bytesBound;
        try
        {
            _ctx = new Context();
            Version = Microsoft.Z3.Version.FullVersion;
            IsAvailable = true;
        }
        catch (DllNotFoundException ex)
        {
            // libz3 native lib missing: degrade gracefully.
            _ctx = null!;
            Version = $"unavailable ({ex.Message})";
            IsAvailable = false;
        }
        catch (Exception ex)
        {
            _ctx = null!;
            Version = $"unavailable ({ex.GetType().Name}: {ex.Message})";
            IsAvailable = false;
        }
    }

    public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions, Expression extra)
    {
        if (!IsAvailable) return SmtOutcome.Unknown;
        var all = new List<Expression>(conditions.Count + 1);
        all.AddRange(conditions);
        all.Add(extra);
        return IsSatisfiable(all);
    }

    public SmtOutcome IsSatisfiable(IReadOnlyList<Expression> conditions)
    {
        if (!IsAvailable) return SmtOutcome.Unknown;
        if (conditions.Count == 0) return SmtOutcome.Sat;

        long key = HashConstraintSet(conditions);
        if (_queryCache.TryGetValue(key, out var cached))
        {
            _cacheHits++;
            return cached;
        }

        var translator = new Translator(_ctx);
        var solver = _ctx.MkSolver();
        var p = _ctx.MkParams();
        p.Add("timeout", (uint)_timeoutMs);
        solver.Parameters = p;
        try
        {
            foreach (var c in conditions)
            {
                var z = translator.TranslateBool(c);
                solver.Assert(z);
            }
            _queries++;
            var result = solver.Check();
            var outcome = result switch
            {
                Status.SATISFIABLE => SmtOutcome.Sat,
                Status.UNSATISFIABLE => SmtOutcome.Unsat,
                _ => SmtOutcome.Unknown,
            };
            switch (outcome)
            {
                case SmtOutcome.Sat: _sat++; break;
                case SmtOutcome.Unsat: _unsat++; break;
                case SmtOutcome.Unknown: _unknowns++; break;
            }
            _queryCache[key] = outcome;
            return outcome;
        }
        catch (Z3Exception)
        {
            _unknowns++;
            return SmtOutcome.Unknown;
        }
    }

    public IReadOnlyDictionary<string, object>? BuildWitness(IReadOnlyList<Expression> conditions)
    {
        if (!IsAvailable) return null;
        if (conditions.Count == 0) return new Dictionary<string, object>();
        var translator = new Translator(_ctx);
        var solver = _ctx.MkSolver();
        var p = _ctx.MkParams();
        p.Add("timeout", (uint)_timeoutMs);
        solver.Parameters = p;
        try
        {
            foreach (var c in conditions)
                solver.Assert(translator.TranslateBool(c));
            if (solver.Check() != Status.SATISFIABLE) return null;
            var model = solver.Model;
            var witness = new Dictionary<string, object>();
            foreach (var (name, expr) in translator.IntSymbols)
            {
                var ev = model.Evaluate(expr, completion: true);
                if (ev is BitVecNum bv)
                    witness[name] = ToSignedBigInteger(bv);
            }
            foreach (var (name, expr) in translator.BoolSymbols)
            {
                var ev = model.Evaluate(expr, completion: true);
                if (ev is BoolExpr be) witness[name] = be.IsTrue;
            }
            foreach (var (name, expr) in translator.BytesLengthSymbols)
            {
                var ev = model.Evaluate(expr, completion: true);
                if (ev is BitVecNum bn) witness[name + ".length"] = (long)bn.UInt;
            }
            return witness;
        }
        catch (Z3Exception)
        {
            return null;
        }
    }

    public SmtStats GetStats() => new(_queries, _cacheHits, _unknowns, /*timeouts*/ 0, _sat, _unsat);

    private static long HashConstraintSet(IReadOnlyList<Expression> conditions)
    {
        unchecked
        {
            long h = 1469598103934665603L;
            foreach (var c in conditions.OrderBy(c => c.GetHashCode()))
                h = (h * 1099511628211L) ^ c.GetHashCode();
            return h;
        }
    }

    private static BigInteger ToSignedBigInteger(BitVecNum bv)
    {
        var value = bv.BigInteger;
        var size = bv.SortSize;
        var halfRange = BigInteger.One << (int)(size - 1);
        if (value >= halfRange) value -= BigInteger.One << (int)size;
        return value;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (IsAvailable) _ctx?.Dispose();
    }
}
