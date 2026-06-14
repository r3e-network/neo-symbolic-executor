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
///
/// Precision note (review #46): integer bitwise (&amp; | ^) and shift (shl/shr) operations over
/// SYMBOLIC operands are opacified to fresh unconstrained Int aux variables (constant-folded cases
/// are translated precisely by the expression factory before reaching here). This is sound — an
/// unconstrained aux variable only relaxes the formula and is counted in
/// <see cref="SmtStats.OpaqueTranslations"/> — but proofs/queries that depend on bitmask, packed-
/// field, or shift reasoning over symbolic values lose precision (and a bug-finder counterexample
/// query over such a term can read as spuriously SAT). Full QF_BV modeling would recover precision.
/// </summary>
internal sealed class SmtLibTranslator
{
    private const string OpaquePrefixInt = "__opaque_int";
    private const string OpaquePrefixBool = "__opaque_bool";

    private readonly Dictionary<string, Sort> _userSymbols = new();
    private readonly Dictionary<string, Sort> _auxSymbols = new();
    private readonly Dictionary<Expression, string> _opaqueSymbols = new();
    private int _nextAux;
    private int _opaqueTranslations;

    public IReadOnlyDictionary<string, Sort> UserSymbols => _userSymbols;

    /// <summary>
    /// Count of times the translator emitted an opaque (unconstrained) aux symbol because the
    /// expression node had no faithful SMT-LIB encoding. Read by <see cref="Z3Backend"/> after
    /// each query and accumulated into <see cref="SmtStats.OpaqueTranslations"/>.
    /// </summary>
    public int OpaqueTranslations => _opaqueTranslations;

    public string TranslateBool(Expression e) => e switch
    {
        BoolConst b => b.Value ? "true" : "false",
        IntConst i => $"(not (= {TranslateInt(i)} {IntLiteral(0)}))",
        NullConst => "false",
        BinaryExpr be when be.Sort == Sort.Bool => TranslateBoolBinary(be),
        UnaryExpr ue when ue.Sort == Sort.Bool => TranslateBoolUnary(ue),
        TernaryExpr te when te.Sort == Sort.Bool => TranslateBoolTernary(te),
        Symbol s when s.Sort == Sort.Bool => UserSymbol(s.Name, Sort.Bool),
        _ => OpaqueSymbol(OpaquePrefixBool, Sort.Bool, e),
    };

    public string TranslateInt(Expression e) => e switch
    {
        IntConst i => IntLiteral(i.Value),
        BoolConst b => IntLiteral(b.Value ? 1 : 0),
        BytesConst bytes => IntLiteral(Expr.BytesToInteger(bytes.Value)),
        NullConst => IntLiteral(0),
        BinaryExpr be when be.Sort == Sort.Int => TranslateIntBinary(be),
        UnaryExpr ue when ue.Sort == Sort.Int => TranslateIntUnary(ue),
        TernaryExpr te when te.Sort == Sort.Int => TranslateIntTernary(te),
        Symbol s when s.Sort == Sort.Int => UserSymbol(s.Name, Sort.Int),
        Symbol s when s.Sort == Sort.Bytes => UserSymbol(ByteIntSymbolName(s.Name), Sort.Int),
        _ => OpaqueSymbol(OpaquePrefixInt, Sort.Int, e),
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

    public static string IntLiteral(BigInteger value) =>
        value.Sign < 0
            ? $"(- {BigInteger.Abs(value).ToString(CultureInfo.InvariantCulture)})"
            : value.ToString(CultureInfo.InvariantCulture);

    private string TranslateBoolBinary(BinaryExpr e) => e.Op switch
    {
        "and" => $"(and {TranslateBool(e.Left)} {TranslateBool(e.Right)})",
        "or" => $"(or {TranslateBool(e.Left)} {TranslateBool(e.Right)})",
        "==" => TranslateEq(e.Left, e.Right),
        "!=" => $"(not {TranslateEq(e.Left, e.Right)})",
        "num==" => $"(= {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "num!=" => $"(not (= {TranslateInt(e.Left)} {TranslateInt(e.Right)}))",
        "<" => $"(< {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "<=" => $"(<= {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        ">" => $"(> {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        ">=" => $"(>= {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        _ => OpaqueSymbol(OpaquePrefixBool, Sort.Bool, e),
    };

    private string TranslateBoolUnary(UnaryExpr e) => e.Op switch
    {
        "not" => $"(not {TranslateBool(e.Operand)})",
        "nz" => $"(not (= {TranslateInt(e.Operand)} {IntLiteral(0)}))",
        "tobool" => TranslateBool(e.Operand),
        _ => OpaqueSymbol(OpaquePrefixBool, Sort.Bool, e),
    };

    private string TranslateBoolTernary(TernaryExpr e) => e.Op switch
    {
        "ite" => $"(ite {TranslateBool(e.A)} {TranslateBool(e.B)} {TranslateBool(e.C)})",
        "within" => $"(and (<= {TranslateInt(e.B)} {TranslateInt(e.A)}) (< {TranslateInt(e.A)} {TranslateInt(e.C)}))",
        _ => OpaqueSymbol(OpaquePrefixBool, Sort.Bool, e),
    };

    private string TranslateEq(Expression a, Expression b)
    {
        if (a.Sort == Sort.Int && b.Sort == Sort.Int)
            return $"(= {TranslateInt(a)} {TranslateInt(b)})";
        if (a.Sort == Sort.Bool && b.Sort == Sort.Bool)
            return $"(= {TranslateBool(a)} {TranslateBool(b)})";
        if (a.Sort == Sort.Bytes && b.Sort == Sort.Bytes)
            return TranslateByteSequenceEq(a, b);
        return OpaqueSymbol(OpaquePrefixBool, Sort.Bool, new BinaryExpr(Sort.Bool, "==", a, b));
    }

    private string TranslateByteSequenceEq(Expression a, Expression b)
    {
        var sizeEq = $"(= {TranslateByteSize(a)} {TranslateByteSize(b)})";
        var valueEq = $"(= {TranslateInt(new UnaryExpr(Sort.Int, "b2i", a))} {TranslateInt(new UnaryExpr(Sort.Int, "b2i", b))})";
        return $"(and {sizeEq} {valueEq})";
    }

    private string TranslateIntBinary(BinaryExpr e) => e.Op switch
    {
        "+" => $"(+ {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "-" => $"(- {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "*" => $"(* {TranslateInt(e.Left)} {TranslateInt(e.Right)})",
        "min" => IntMin(e.Left, e.Right),
        "max" => IntMax(e.Left, e.Right),
        "pick" => TranslateBytePick(e.Left, e.Right),
        _ => OpaqueSymbol(OpaquePrefixInt, Sort.Int, e),
    };

    private string TranslateIntUnary(UnaryExpr e) => e.Op switch
    {
        "neg" => $"(- {TranslateInt(e.Operand)})",
        "abs" => IntAbs(e.Operand),
        "sign" => IntSign(e.Operand),
        "b2i" => TranslateInt(e.Operand),
        "size" => TranslateByteSize(e.Operand),
        _ => OpaqueSymbol(OpaquePrefixInt, Sort.Int, e),
    };

    private string TranslateIntTernary(TernaryExpr e) => e.Op switch
    {
        "ite" => $"(ite {TranslateBool(e.A)} {TranslateInt(e.B)} {TranslateInt(e.C)})",
        _ => OpaqueSymbol(OpaquePrefixInt, Sort.Int, e),
    };

    private string IntAbs(Expression e)
    {
        var value = TranslateInt(e);
        return $"(ite (< {value} {IntLiteral(0)}) (- {value}) {value})";
    }

    private string IntSign(Expression e)
    {
        var value = TranslateInt(e);
        var negOrPos = $"(ite (< {value} {IntLiteral(0)}) {IntLiteral(-1)} {IntLiteral(1)})";
        return $"(ite (= {value} {IntLiteral(0)}) {IntLiteral(0)} {negOrPos})";
    }

    private string IntMin(Expression a, Expression b)
    {
        var left = TranslateInt(a);
        var right = TranslateInt(b);
        return $"(ite (<= {left} {right}) {left} {right})";
    }

    private string IntMax(Expression a, Expression b)
    {
        var left = TranslateInt(a);
        var right = TranslateInt(b);
        return $"(ite (>= {left} {right}) {left} {right})";
    }

    private string TranslateByteSize(Expression operand)
    {
        if (Expr.FixedByteSize(operand) is { } fixedByteSize)
            return IntLiteral(fixedByteSize);

        if (Expr.CanonicalBytes(operand) is { } bytes)
            return IntLiteral(bytes.Length);

        return operand switch
        {
            Symbol { Sort: Sort.Bytes } symbol => UserSymbol(ByteSizeSymbolName(symbol.Name), Sort.Int),
            BinaryExpr { Sort: Sort.Bytes, Op: "cat" } binary =>
                $"(+ {TranslateByteSize(binary.Left)} {TranslateByteSize(binary.Right)})",
            BinaryExpr { Sort: Sort.Bytes, Op: "left" or "right" } binary =>
                TranslateInt(binary.Right),
            TernaryExpr { Sort: Sort.Bytes, Op: "substr" } ternary =>
                TranslateInt(ternary.C),
            _ => OpaqueSymbol(OpaquePrefixInt, Sort.Int, operand),
        };
    }

    private string TranslateBytePick(Expression bytes, Expression index)
    {
        if (Expr.ConcreteByteAt(bytes, index) is { } value)
            return IntLiteral(value);

        return OpaqueSymbol(OpaquePrefixInt, Sort.Int, new BinaryExpr(Sort.Int, "pick", bytes, index));
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
        if (prefix == OpaquePrefixInt || prefix == OpaquePrefixBool)
            _opaqueTranslations++;
        return Atom(name);
    }

    private string OpaqueSymbol(string prefix, Sort sort, Expression expression)
    {
        if (_opaqueSymbols.TryGetValue(expression, out var existing))
            return Atom(existing);

        var name = NextAuxName(prefix);
        _auxSymbols[name] = sort;
        _opaqueSymbols[expression] = name;
        _opaqueTranslations++;
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

    private static string ByteIntSymbolName(string name) => "b2i:" + name;
    private static string ByteSizeSymbolName(string name) => "size:" + name;

    private static string Declare(string name, Sort sort) =>
        sort switch
        {
            Sort.Bool => $"(declare-const {Atom(name)} Bool)",
            Sort.Int => $"(declare-const {Atom(name)} Int)",
            _ => throw new InvalidOperationException($"Unsupported SMT-LIB declaration sort: {sort}"),
        };
}
