using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Constant folding + light simplification for <see cref="Expression"/> construction.
///
/// This is the fast path that runs every time. The optional Z3 layer (Neo.SymbolicExecutor.Smt)
/// adds full SMT-backed reasoning on top.
///
/// IMPORTANT: cross-type equality follows NeoVM's PrimitiveType.GetSpan().SequenceEqual rule
/// (audit HIGH-2). Integer(0) == ByteString(b"") and Boolean(false) == Integer(0) when their
/// canonical byte encodings match. We do NOT short-circuit cross-sort equality to false.
/// </summary>
public static class Expr
{
    public static IntConst Int(BigInteger value) => new(value);
    public static IntConst Int(long value) => new(new BigInteger(value));
    public static BoolConst Bool(bool value) => value ? BoolConst.True : BoolConst.False;
    public static BytesConst Bytes(byte[] value) => new(value);
    public static BytesConst Bytes(ReadOnlySpan<byte> value) => new(value.ToArray());
    public static NullConst Null() => NullConst.Instance;
    public static Symbol Sym(Sort sort, string name) => new(sort, name);
    public static HeapRef Ref(Sort sort, int id) => new(sort, id);

    // ---- Comparison: byte-wise canonical equality matching NeoVM's PrimitiveType.GetSpan().
    public static byte[]? CanonicalBytes(Expression e) => e switch
    {
        IntConst i => IntegerToBytes(i.Value),
        BoolConst b => b.Value ? new byte[] { 1 } : Array.Empty<byte>(),
        BytesConst by => by.Value,
        _ => null,
    };

    public static bool PrimitiveEqualsConcrete(Expression a, Expression b)
    {
        var ab = CanonicalBytes(a);
        var bb = CanonicalBytes(b);
        if (ab is null || bb is null) return false;
        return ab.AsSpan().SequenceEqual(bb);
    }

    public static byte[] IntegerToBytes(BigInteger value)
    {
        if (value.IsZero) return Array.Empty<byte>();
        return value.ToByteArray(isUnsigned: false, isBigEndian: false);
    }

    public static BigInteger BytesToInteger(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0) return BigInteger.Zero;
        return new BigInteger(bytes, isUnsigned: false, isBigEndian: false);
    }

    // ---- Boolean / truthiness
    public static bool? Truthy(Expression e) => e switch
    {
        IntConst i => !i.Value.IsZero,
        BoolConst b => b.Value,
        BytesConst by => by.Value.Length > 0,
        NullConst => false,
        _ => null,
    };

    // ---- Arithmetic
    public static Expression Add(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value + bi.Value);
        if (a is IntConst z1 && z1.Value.IsZero) return b;
        if (b is IntConst z2 && z2.Value.IsZero) return a;
        return new BinaryExpr(Sort.Int, "+", a, b);
    }

    public static Expression Sub(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value - bi.Value);
        if (b is IntConst z && z.Value.IsZero) return a;
        return new BinaryExpr(Sort.Int, "-", a, b);
    }

    public static Expression Mul(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value * bi.Value);
        if (a is IntConst z && z.Value.IsZero) return Int(0);
        if (b is IntConst z2 && z2.Value.IsZero) return Int(0);
        if (a is IntConst o && o.Value == 1) return b;
        if (b is IntConst o2 && o2.Value == 1) return a;
        return new BinaryExpr(Sort.Int, "*", a, b);
    }

    public static Expression Div(Expression a, Expression b)
    {
        if (b is IntConst bz && bz.Value.IsZero)
            throw new VmFaultException("DIV by zero");
        if (a is IntConst ai && b is IntConst bi)
            return Int(NeoTruncatedDivide(ai.Value, bi.Value));
        return new BinaryExpr(Sort.Int, "/", a, b);
    }

    public static Expression Mod(Expression a, Expression b)
    {
        if (b is IntConst bz && bz.Value.IsZero)
            throw new VmFaultException("MOD by zero");
        if (a is IntConst ai && b is IntConst bi)
            return Int(NeoTruncatedModulo(ai.Value, bi.Value));
        return new BinaryExpr(Sort.Int, "%", a, b);
    }

    /// <summary>
    /// NeoVM uses C# truncated division (rounds toward zero), NOT Python floor division.
    /// Audit identified this as a Python-side bug: -7/2 == -3 in NeoVM (truncate),
    /// but Python's // gives -4. C# BigInteger / and % already do truncated divmod, so
    /// we use them directly.
    /// </summary>
    public static BigInteger NeoTruncatedDivide(BigInteger a, BigInteger b) => a / b;
    public static BigInteger NeoTruncatedModulo(BigInteger a, BigInteger b) => a % b;

    public static Expression Neg(Expression a)
    {
        if (a is IntConst ai) return Int(-ai.Value);
        return new UnaryExpr(Sort.Int, "neg", a);
    }

    public static Expression Abs(Expression a)
    {
        if (a is IntConst ai) return Int(BigInteger.Abs(ai.Value));
        return new UnaryExpr(Sort.Int, "abs", a);
    }

    public static Expression Sign(Expression a)
    {
        if (a is IntConst ai) return Int(ai.Value.Sign);
        return new UnaryExpr(Sort.Int, "sign", a);
    }

    public static Expression Inc(Expression a) => Add(a, Int(1));
    public static Expression Dec(Expression a) => Sub(a, Int(1));

    public static Expression Pow(Expression a, Expression b, int maxExponent = 256)
    {
        if (a is IntConst ai && b is IntConst bi)
        {
            if (bi.Value < 0) throw new VmFaultException("POW negative exponent");
            if (bi.Value > maxExponent) throw new VmFaultException("POW exponent too large");
            return Int(BigInteger.Pow(ai.Value, (int)bi.Value));
        }
        return new BinaryExpr(Sort.Int, "pow", a, b);
    }

    public static Expression Sqrt(Expression a)
    {
        if (a is IntConst ai)
        {
            if (ai.Value < 0) throw new VmFaultException("SQRT negative input");
            return Int(IntegerSquareRoot(ai.Value));
        }
        return new UnaryExpr(Sort.Int, "sqrt", a);
    }

    private static BigInteger IntegerSquareRoot(BigInteger n)
    {
        if (n < 2) return n;
        BigInteger x = n;
        BigInteger y = (x + 1) / 2;
        while (y < x)
        {
            x = y;
            y = (x + n / x) / 2;
        }
        return x;
    }

    public static Expression ModMul(Expression a, Expression b, Expression m)
    {
        if (a is IntConst ai && b is IntConst bi && m is IntConst mi)
        {
            if (mi.Value.IsZero) throw new VmFaultException("MODMUL with zero modulus");
            return Int((ai.Value * bi.Value) % mi.Value);
        }
        return new TernaryExpr(Sort.Int, "modmul", a, b, m);
    }

    public static Expression ModPow(Expression a, Expression b, Expression m)
    {
        if (a is IntConst ai && b is IntConst bi && m is IntConst mi)
        {
            if (mi.Value.IsZero) throw new VmFaultException("MODPOW with zero modulus");
            if (bi.Value < 0)
                throw new VmFaultException("MODPOW with negative exponent (modular inverse) not modeled concretely");
            return Int(BigInteger.ModPow(ai.Value, bi.Value, mi.Value));
        }
        return new TernaryExpr(Sort.Int, "modpow", a, b, m);
    }

    public static Expression Shl(Expression a, Expression b, int maxShift = 256)
    {
        if (a is IntConst ai && b is IntConst bi)
        {
            if (bi.Value < 0) throw new VmFaultException("SHL by negative count");
            if (bi.Value > maxShift) throw new VmFaultException("SHL count too large");
            return Int(ai.Value << (int)bi.Value);
        }
        return new BinaryExpr(Sort.Int, "<<", a, b);
    }

    public static Expression Shr(Expression a, Expression b, int maxShift = 256)
    {
        if (a is IntConst ai && b is IntConst bi)
        {
            if (bi.Value < 0) throw new VmFaultException("SHR by negative count");
            if (bi.Value > maxShift) throw new VmFaultException("SHR count too large");
            return Int(ai.Value >> (int)bi.Value);
        }
        return new BinaryExpr(Sort.Int, ">>", a, b);
    }

    // ---- Bitwise
    public static Expression And(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value & bi.Value);
        return new BinaryExpr(Sort.Int, "&", a, b);
    }

    public static Expression Or(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value | bi.Value);
        return new BinaryExpr(Sort.Int, "|", a, b);
    }

    public static Expression Xor(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value ^ bi.Value);
        return new BinaryExpr(Sort.Int, "^", a, b);
    }

    public static Expression Invert(Expression a)
    {
        if (a is IntConst ai) return Int(~ai.Value);
        return new UnaryExpr(Sort.Int, "~", a);
    }

    // ---- Comparison
    public static Expression Eq(Expression a, Expression b)
    {
        // Cross-type primitive equality (audit HIGH-2): use canonical bytes.
        if (a.Sort.IsCrossTypeEqualityCandidate() && b.Sort.IsCrossTypeEqualityCandidate())
        {
            if (a.IsConcrete && b.IsConcrete)
                return Bool(PrimitiveEqualsConcrete(a, b));
        }
        if (a is NullConst && b is NullConst) return BoolConst.True;
        if ((a is NullConst) != (b is NullConst))
        {
            // Null compared to non-null primitive is false; null compared to heap is also false.
            return BoolConst.False;
        }
        if (a is HeapRef ah && b is HeapRef bh)
            return Bool(ah.RefSort == bh.RefSort && ah.ObjectId == bh.ObjectId);
        if (a is BoolConst ab && b is BoolConst bb) return Bool(ab.Value == bb.Value);
        return new BinaryExpr(Sort.Bool, "==", a, b);
    }

    public static Expression Ne(Expression a, Expression b)
    {
        var eq = Eq(a, b);
        if (eq is BoolConst be) return Bool(!be.Value);
        return Not(eq);
    }

    public static Expression Lt(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Bool(ai.Value < bi.Value);
        return new BinaryExpr(Sort.Bool, "<", a, b);
    }

    public static Expression Le(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Bool(ai.Value <= bi.Value);
        return new BinaryExpr(Sort.Bool, "<=", a, b);
    }

    public static Expression Gt(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Bool(ai.Value > bi.Value);
        return new BinaryExpr(Sort.Bool, ">", a, b);
    }

    public static Expression Ge(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Bool(ai.Value >= bi.Value);
        return new BinaryExpr(Sort.Bool, ">=", a, b);
    }

    public static Expression Min(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(BigInteger.Min(ai.Value, bi.Value));
        return new BinaryExpr(Sort.Int, "min", a, b);
    }

    public static Expression Max(Expression a, Expression b)
    {
        if (a is IntConst ai && b is IntConst bi) return Int(BigInteger.Max(ai.Value, bi.Value));
        return new BinaryExpr(Sort.Int, "max", a, b);
    }

    public static Expression Within(Expression x, Expression lo, Expression hi)
    {
        if (x is IntConst xi && lo is IntConst li && hi is IntConst hi2)
            return Bool(li.Value <= xi.Value && xi.Value < hi2.Value);
        return new TernaryExpr(Sort.Bool, "within", x, lo, hi);
    }

    // ---- Logic
    public static Expression Not(Expression a)
    {
        if (a is BoolConst b) return Bool(!b.Value);
        if (a is IntConst i) return Bool(i.Value.IsZero);  // NOT on int treats 0/1 as bool per NeoVM
        if (a is UnaryExpr u && u.Op == "not") return u.Operand;
        return new UnaryExpr(Sort.Bool, "not", a);
    }

    public static Expression BoolAnd(Expression a, Expression b)
    {
        var ta = Truthy(a);
        var tb = Truthy(b);
        if (ta == false || tb == false) return BoolConst.False;
        if (ta == true && tb == true) return BoolConst.True;
        return new BinaryExpr(Sort.Bool, "and", a, b);
    }

    public static Expression BoolOr(Expression a, Expression b)
    {
        var ta = Truthy(a);
        var tb = Truthy(b);
        if (ta == true || tb == true) return BoolConst.True;
        if (ta == false && tb == false) return BoolConst.False;
        return new BinaryExpr(Sort.Bool, "or", a, b);
    }

    public static Expression Nz(Expression a)
    {
        if (a is IntConst i) return Bool(!i.Value.IsZero);
        return new UnaryExpr(Sort.Bool, "nz", a);
    }

    /// <summary>Convert to a Boolean per NeoVM truthiness rules.</summary>
    public static Expression ToBool(Expression a)
    {
        var t = Truthy(a);
        if (t.HasValue) return Bool(t.Value);
        return new UnaryExpr(Sort.Bool, "tobool", a);
    }
}
