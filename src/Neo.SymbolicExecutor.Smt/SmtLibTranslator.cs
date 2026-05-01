using System;
using System.Collections.Generic;
using System.Globalization;
using System.Numerics;
using System.Text;
using Neo.SymbolicExecutor;

namespace Neo.SymbolicExecutor.Smt.Z3;

/// <summary>
/// Translates the executor expression IR into the SMT-LIB fragment consumed by z3.
/// Unsupported expressions become fresh symbols, preserving soundness by reducing precision.
/// </summary>
internal sealed class SmtLibTranslator
{
    private readonly Dictionary<string, Sort> _userSymbols = new();
    private readonly Dictionary<string, Sort> _auxSymbols = new();
    private int _nextAux;

    public IReadOnlyDictionary<string, Sort> UserSymbols => _userSymbols;

    public string TranslateBool(Expression e) => e switch
    {
        BoolConst b => b.Value ? "true" : "false",
        IntConst i => $"(not (= {TranslateInt(i)} {Bv(0)}))",
        NullConst => "false",
        BinaryExpr be when be.Sort == Sort.Bool => TranslateBoolBinary(be),
        UnaryExpr ue when ue.Sort == Sort.Bool => TranslateBoolUnary(ue),
        TernaryExpr te when te.Sort == Sort.Bool => TranslateBoolTernary(te),
        Symbol s when s.Sort == Sort.Bool => UserSymbol(s.Name, Sort.Bool),
        _ => AuxSymbol("__opaque_bool", Sort.Bool),
    };

    public string TranslateInt(Expression e) => e switch
    {
        IntConst i => Bv(i.Value),
        BoolConst b => Bv(b.Value ? 1 : 0),
        NullConst => Bv(0),
        BinaryExpr be when be.Sort == Sort.Int => TranslateIntBinary(be),
        UnaryExpr ue when ue.Sort == Sort.Int => TranslateIntUnary(ue),
        TernaryExpr te when te.Sort == Sort.Int => TranslateIntTernary(te),
        Symbol s when s.Sort == Sort.Int => UserSymbol(s.Name, Sort.Int),
        _ => AuxSymbol("__opaque_int", Sort.Int),
    };

    public string NewAuxInt(string prefix, out string name)
    {
        name = NextAuxName(prefix);
        _auxSymbols[name] = Sort.Int;
        return Atom(name);
    }

    public IEnumerable<string> Declarations()
    {
        foreach (var (name, sort) in _userSymbols)
            yield return Declare(name, sort);
        foreach (var (name, sort) in _auxSymbols)
            yield return Declare(name, sort);
    }

    public static string Atom(string name)
    {
        var escaped = name.Replace("\\", "\\\\", StringComparison.Ordinal)
                          .Replace("|", "\\|", StringComparison.Ordinal);
        return $"|{escaped}|";
    }

    public static string Bv(BigInteger value)
    {
        var modulus = BigInteger.One << Z3Backend.IntegerBits;
        var normalized = value % modulus;
        if (normalized.Sign < 0) normalized += modulus;
        return $"(_ bv{normalized.ToString(CultureInfo.InvariantCulture)} {Z3Backend.IntegerBits})";
    }

    private string TranslateBoolBinary(BinaryExpr e) => e.Op switch
    {
        "and" => $"(and {TranslateBool(e.Left)} {TranslateBool(e.Right)})",
        "or" => $"(or {TranslateBool(e.Left)} {TranslateBool(e.Right)})",
        "==" => TranslateEq(e.Left, e.Right),
        "!=" => $"(not {TranslateEq(e.Left, e.Right)})",
        "num==" => $"(= {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "num!=" => $"(not (= {TranslateInt(e.Left)} {TranslateInt(e.Right)}))",
        "<" => $"(bvslt {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "<=" => $"(bvsle {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        ">" => $"(bvsgt {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        ">=" => $"(bvsge {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        _ => AuxSymbol("__opaque_bool", Sort.Bool),
    };

    private string TranslateBoolUnary(UnaryExpr e) => e.Op switch
    {
        "not" => $"(not {TranslateBool(e.Operand)})",
        "nz" => $"(not (= {TranslateInt(e.Operand)} {Bv(0)}))",
        "tobool" => TranslateBool(e.Operand),
        _ => AuxSymbol("__opaque_bool", Sort.Bool),
    };

    private string TranslateBoolTernary(TernaryExpr e) => e.Op switch
    {
        "within" => $"(and (bvsle {TranslateInt(e.B)} {TranslateInt(e.A)}) (bvslt {TranslateInt(e.A)} {TranslateInt(e.C)}))",
        _ => AuxSymbol("__opaque_bool", Sort.Bool),
    };

    private string TranslateEq(Expression a, Expression b)
    {
        if (a.Sort == Sort.Int && b.Sort == Sort.Int)
            return $"(= {TranslateInt(a)} {TranslateInt(b)})";
        if (a.Sort == Sort.Bool && b.Sort == Sort.Bool)
            return $"(= {TranslateBool(a)} {TranslateBool(b)})";
        return AuxSymbol("__opaque_bool", Sort.Bool);
    }

    private string TranslateIntBinary(BinaryExpr e) => e.Op switch
    {
        "+" => $"(bvadd {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "-" => $"(bvsub {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "*" => $"(bvmul {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "/" => $"(bvsdiv {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "%" => $"(bvsrem {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "&" => $"(bvand {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "|" => $"(bvor {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "^" => $"(bvxor {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "<<" => $"(bvshl {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        ">>" => $"(bvashr {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "min" => IntMin(e.Left, e.Right),
        "max" => IntMax(e.Left, e.Right),
        _ => AuxSymbol("__opaque_int", Sort.Int),
    };

    private string TranslateIntUnary(UnaryExpr e) => e.Op switch
    {
        "neg" => $"(bvneg {TranslateInt(e.Operand)})",
        "abs" => IntAbs(e.Operand),
        "sign" => IntSign(e.Operand),
        "~" => $"(bvnot {TranslateInt(e.Operand)})",
        _ => AuxSymbol("__opaque_int", Sort.Int),
    };

    private string TranslateIntTernary(TernaryExpr e) => e.Op switch
    {
        "modmul" => $"(bvsmod (bvmul {TranslateInt(e.A)} {TranslateInt(e.B)}) {TranslateInt(e.C)})",
        _ => AuxSymbol("__opaque_int", Sort.Int),
    };

    private string IntAbs(Expression e)
    {
        var value = TranslateInt(e);
        return $"(ite (bvslt {value} {Bv(0)}) (bvneg {value}) {value})";
    }

    private string IntSign(Expression e)
    {
        var value = TranslateInt(e);
        var negOrPos = $"(ite (bvslt {value} {Bv(0)}) {Bv(-1)} {Bv(1)})";
        return $"(ite (= {value} {Bv(0)}) {Bv(0)} {negOrPos})";
    }

    private string IntMin(Expression a, Expression b)
    {
        var left = TranslateInt(a);
        var right = TranslateInt(b);
        return $"(ite (bvsle {left} {right}) {left} {right})";
    }

    private string IntMax(Expression a, Expression b)
    {
        var left = TranslateInt(a);
        var right = TranslateInt(b);
        return $"(ite (bvsge {left} {right}) {left} {right})";
    }

    private string UserSymbol(string name, Sort sort)
    {
        _userSymbols.TryAdd(name, sort);
        return Atom(name);
    }

    private string AuxSymbol(string prefix, Sort sort)
    {
        var name = NextAuxName(prefix);
        _auxSymbols[name] = sort;
        return Atom(name);
    }

    private string NextAuxName(string prefix)
    {
        string name;
        do
        {
            name = $"{prefix}_{_nextAux++}";
        }
        while (_userSymbols.ContainsKey(name) || _auxSymbols.ContainsKey(name));

        return name;
    }

    private static string Declare(string name, Sort sort) =>
        sort switch
        {
            Sort.Bool => $"(declare-const {Atom(name)} Bool)",
            Sort.Int => $"(declare-const {Atom(name)} (_ BitVec {Z3Backend.IntegerBits}))",
            _ => throw new InvalidOperationException($"Unsupported SMT-LIB declaration sort: {sort}"),
        };
}
