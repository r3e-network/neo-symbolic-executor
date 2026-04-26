using System;
using System.Collections.Generic;
using System.Numerics;
using Microsoft.Z3;
using Neo.SymbolicExecutor;

namespace Neo.SymbolicExecutor.Smt.Z3;

/// <summary>
/// Per-query translator: walks the engine's <see cref="Expression"/> IR and emits z3
/// <see cref="Expr"/>. Caches by structural identity.
///
/// The translator is single-use per Solver invocation: symbol bindings are recorded so the
/// caller can extract a witness model.
/// </summary>
internal sealed class Translator
{
    private readonly Context _ctx;
    private readonly Dictionary<string, BitVecExpr> _intSymbols = new();
    private readonly Dictionary<string, BoolExpr> _boolSymbols = new();
    private readonly Dictionary<string, ArrayExpr> _bytesArrays = new();
    private readonly Dictionary<string, BitVecExpr> _bytesLengths = new();

    public IReadOnlyDictionary<string, BitVecExpr> IntSymbols => _intSymbols;
    public IReadOnlyDictionary<string, BoolExpr> BoolSymbols => _boolSymbols;
    public IReadOnlyDictionary<string, BitVecExpr> BytesLengthSymbols => _bytesLengths;

    public Translator(Context ctx) { _ctx = ctx; }

    public BoolExpr TranslateBool(Expression e) => e switch
    {
        BoolConst b => _ctx.MkBool(b.Value),
        IntConst i => _ctx.MkNot(_ctx.MkEq(MkInt(i.Value), MkInt(0))),  // truthy
        NullConst => _ctx.MkFalse(),
        BinaryExpr be when be.Sort == Sort.Bool => TranslateBoolBinary(be),
        UnaryExpr ue when ue.Sort == Sort.Bool => TranslateBoolUnary(ue),
        TernaryExpr te when te.Sort == Sort.Bool => TranslateBoolTernary(te),
        Symbol s when s.Sort == Sort.Bool => GetBoolSymbol(s.Name),
        _ => MkOpaqueBool(e),  // fallback: fresh symbol; degrades to Unknown rather than wrong
    };

    public BitVecExpr TranslateInt(Expression e) => e switch
    {
        IntConst i => MkInt(i.Value),
        BoolConst b => _ctx.MkITE(_ctx.MkBool(b.Value), MkInt(1), MkInt(0)) is BitVecExpr bv ? bv : MkInt(0),
        NullConst => MkInt(0),
        BinaryExpr be when be.Sort == Sort.Int => TranslateIntBinary(be),
        UnaryExpr ue when ue.Sort == Sort.Int => TranslateIntUnary(ue),
        TernaryExpr te when te.Sort == Sort.Int => TranslateIntTernary(te),
        Symbol s when s.Sort == Sort.Int => GetIntSymbol(s.Name),
        _ => GetIntSymbol("__opaque_" + e.GetHashCode()),
    };

    private BoolExpr TranslateBoolBinary(BinaryExpr e) => e.Op switch
    {
        "and" => _ctx.MkAnd(TranslateBool(e.Left), TranslateBool(e.Right)),
        "or"  => _ctx.MkOr(TranslateBool(e.Left), TranslateBool(e.Right)),
        "==" => TranslateEq(e.Left, e.Right),
        "!=" => _ctx.MkNot(TranslateEq(e.Left, e.Right)),
        "<"  => _ctx.MkBVSLT(TranslateInt(e.Left), TranslateInt(e.Right)),
        "<=" => _ctx.MkBVSLE(TranslateInt(e.Left), TranslateInt(e.Right)),
        ">"  => _ctx.MkBVSGT(TranslateInt(e.Left), TranslateInt(e.Right)),
        ">=" => _ctx.MkBVSGE(TranslateInt(e.Left), TranslateInt(e.Right)),
        _ => MkOpaqueBool(e),
    };

    private BoolExpr TranslateBoolUnary(UnaryExpr e) => e.Op switch
    {
        "not" => _ctx.MkNot(TranslateBool(e.Operand)),
        "nz"  => _ctx.MkNot(_ctx.MkEq(TranslateInt(e.Operand), MkInt(0))),
        "tobool" => TranslateBool(e.Operand),
        _ => MkOpaqueBool(e),
    };

    private BoolExpr TranslateBoolTernary(TernaryExpr e) => e.Op switch
    {
        "within" => _ctx.MkAnd(
            _ctx.MkBVSLE(TranslateInt(e.B), TranslateInt(e.A)),
            _ctx.MkBVSLT(TranslateInt(e.A), TranslateInt(e.C))),
        _ => MkOpaqueBool(e),
    };

    private BoolExpr TranslateEq(Expression a, Expression b)
    {
        // Cross-type primitive equality (audit HIGH-2): when both are concrete primitives use the
        // canonical-bytes equality already baked into Expr.Eq during simplification. The translator
        // sees that as a BoolConst. For mixed sorts where one is symbolic, fall back to opaque.
        if (a.Sort == Sort.Int && b.Sort == Sort.Int)
            return _ctx.MkEq(TranslateInt(a), TranslateInt(b));
        if (a.Sort == Sort.Bool && b.Sort == Sort.Bool)
            return _ctx.MkEq(TranslateBool(a), TranslateBool(b));
        return MkOpaqueBool(new BinaryExpr(Sort.Bool, "==", a, b));
    }

    private BitVecExpr TranslateIntBinary(BinaryExpr e) => e.Op switch
    {
        "+" => _ctx.MkBVAdd(TranslateInt(e.Left), TranslateInt(e.Right)),
        "-" => _ctx.MkBVSub(TranslateInt(e.Left), TranslateInt(e.Right)),
        "*" => _ctx.MkBVMul(TranslateInt(e.Left), TranslateInt(e.Right)),
        "/" => _ctx.MkBVSDiv(TranslateInt(e.Left), TranslateInt(e.Right)),
        "%" => _ctx.MkBVSRem(TranslateInt(e.Left), TranslateInt(e.Right)),
        "&" => _ctx.MkBVAND(TranslateInt(e.Left), TranslateInt(e.Right)),
        "|" => _ctx.MkBVOR(TranslateInt(e.Left), TranslateInt(e.Right)),
        "^" => _ctx.MkBVXOR(TranslateInt(e.Left), TranslateInt(e.Right)),
        "<<" => _ctx.MkBVSHL(TranslateInt(e.Left), TranslateInt(e.Right)),
        ">>" => _ctx.MkBVASHR(TranslateInt(e.Left), TranslateInt(e.Right)),
        "min" => MkIntMin(e.Left, e.Right),
        "max" => MkIntMax(e.Left, e.Right),
        _ => GetIntSymbol("__opaque_int_" + e.GetHashCode()),
    };

    private BitVecExpr TranslateIntUnary(UnaryExpr e) => e.Op switch
    {
        "neg" => _ctx.MkBVNeg(TranslateInt(e.Operand)),
        "abs" => MkIntAbs(e.Operand),
        "sign" => MkIntSign(e.Operand),
        "~" => _ctx.MkBVNot(TranslateInt(e.Operand)),
        _ => GetIntSymbol("__opaque_int_u_" + e.GetHashCode()),
    };

    private BitVecExpr TranslateIntTernary(TernaryExpr e) => e.Op switch
    {
        "modmul" => _ctx.MkBVSMod(_ctx.MkBVMul(TranslateInt(e.A), TranslateInt(e.B)), TranslateInt(e.C)),
        _ => GetIntSymbol("__opaque_int_t_" + e.GetHashCode()),
    };

    private BitVecExpr MkIntAbs(Expression e)
    {
        var x = TranslateInt(e);
        var zero = MkInt(0);
        return (BitVecExpr)_ctx.MkITE(_ctx.MkBVSLT(x, zero), _ctx.MkBVNeg(x), x);
    }

    private BitVecExpr MkIntSign(Expression e)
    {
        var x = TranslateInt(e);
        var zero = MkInt(0);
        var neg = (BitVecExpr)_ctx.MkITE(_ctx.MkBVSLT(x, zero), MkInt(-1), MkInt(1));
        return (BitVecExpr)_ctx.MkITE(_ctx.MkEq(x, zero), MkInt(0), neg);
    }

    private BitVecExpr MkIntMin(Expression a, Expression b)
    {
        var x = TranslateInt(a);
        var y = TranslateInt(b);
        return (BitVecExpr)_ctx.MkITE(_ctx.MkBVSLE(x, y), x, y);
    }

    private BitVecExpr MkIntMax(Expression a, Expression b)
    {
        var x = TranslateInt(a);
        var y = TranslateInt(b);
        return (BitVecExpr)_ctx.MkITE(_ctx.MkBVSGE(x, y), x, y);
    }

    private BitVecExpr MkInt(BigInteger value) => _ctx.MkBV(value.ToString(), Z3Backend.IntegerBits);
    private BitVecExpr MkInt(int value) => _ctx.MkBV(value, Z3Backend.IntegerBits);

    private BitVecExpr GetIntSymbol(string name)
    {
        if (_intSymbols.TryGetValue(name, out var s)) return s;
        var fresh = _ctx.MkBVConst(name, Z3Backend.IntegerBits);
        _intSymbols[name] = fresh;
        return fresh;
    }

    private BoolExpr GetBoolSymbol(string name)
    {
        if (_boolSymbols.TryGetValue(name, out var s)) return s;
        var fresh = _ctx.MkBoolConst(name);
        _boolSymbols[name] = fresh;
        return fresh;
    }

    /// <summary>Synthesize a fresh boolean symbol for an expression we can't translate.</summary>
    private BoolExpr MkOpaqueBool(Expression e) => GetBoolSymbol("__opaque_bool_" + e.GetHashCode());
}
