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
/// IMPORTANT: the EQUAL opcode (<see cref="Eq"/>) follows NeoVM's TYPE-STRICT StackItem.Equals —
/// only same-type primitives can be equal, so Integer vs ByteString is always false. The numeric
/// cross-type comparison (NUMEQUAL / JMP*) is GetInteger-based and lives in <see cref="NumEq"/>.
/// </summary>
public static class Expr
{
    public const string CryptoSha256Op = "crypto.sha256";
    public const string CryptoRipemd160Op = "crypto.ripemd160";
    public const string CryptoKeccak256Op = "crypto.keccak256";
    public const string CryptoMurmur32Op = "crypto.murmur32";
    public const string CryptoRecoverSecp256K1Op = "crypto.recover_secp256k1";
    public const string CryptoBlsAddG1Op = "crypto.bls12381.add.g1";
    public const string CryptoBlsAddG2Op = "crypto.bls12381.add.g2";
    public const string CryptoBlsAddGtOp = "crypto.bls12381.add.gt";
    public const string CryptoBlsMulG1Op = "crypto.bls12381.mul.g1";
    public const string CryptoBlsMulG2Op = "crypto.bls12381.mul.g2";
    public const string CryptoBlsMulGtOp = "crypto.bls12381.mul.gt";
    public const string CryptoBlsPairingOp = "crypto.bls12381.pairing";
    public const string CryptoBlsValidG1Op = "crypto.bls12381.valid.g1";
    public const string CryptoBlsValidG2Op = "crypto.bls12381.valid.g2";
    public const string CryptoBlsValidGtOp = "crypto.bls12381.valid.gt";
    public const string CryptoBlsValidScalarOp = "crypto.bls12381.valid.scalar";
    public static readonly BigInteger NeoVmIntegerMin = -(BigInteger.One << 255);
    public static readonly BigInteger NeoVmIntegerMax = (BigInteger.One << 255) - BigInteger.One;
    private static readonly System.Text.UTF8Encoding StrictUtf8 = new(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true);

    public static IntConst Int(BigInteger value) => new(value);
    public static IntConst Int(long value) => new(new BigInteger(value));
    public static BoolConst Bool(bool value) => value ? BoolConst.True : BoolConst.False;
    public static BytesConst Bytes(byte[] value) => new(value);
    public static BytesConst Bytes(ReadOnlySpan<byte> value) => new(value.ToArray());
    public static PointerConst Pointer(int targetOffset) => new(targetOffset);
    public static NullConst Null() => NullConst.Instance;
    public static Symbol Sym(Sort sort, string name) => new(sort, name);
    public static HeapRef Ref(Sort sort, int id) => new(sort, id);
    public static Expression IsStrictUtf8(Expression value)
    {
        if (CanonicalBytes(value) is not { } bytes)
            return new UnaryExpr(Sort.Bool, "utf8", value);

        try
        {
            _ = StrictUtf8.GetString(bytes);
            return BoolConst.True;
        }
        catch (System.Text.DecoderFallbackException)
        {
            return BoolConst.False;
        }
    }

    public static Expression IsValidEcPoint(Expression value)
    {
        if (CanonicalBytes(value) is not { } bytes)
            return new UnaryExpr(Sort.Bool, "ecpoint", value);

        return Bool(NeoEcPoint.IsValidEncoding(bytes));
    }

    // ---- Comparison: byte-wise canonical equality matching NeoVM's PrimitiveType.GetSpan().
    public static byte[]? CanonicalBytes(Expression e) => e switch
    {
        IntConst i => IntegerToBytes(i.Value),
        BoolConst b => b.Value ? new byte[] { 1 } : Array.Empty<byte>(),
        BytesConst by => by.Value,
        _ => null,
    };

    public static int? FixedByteSize(Expression e) => e switch
    {
        UnaryExpr { Sort: Sort.Bytes, Op: CryptoSha256Op or CryptoKeccak256Op } => 32,
        UnaryExpr { Sort: Sort.Bytes, Op: CryptoRipemd160Op } => 20,
        BinaryExpr { Sort: Sort.Bytes, Op: CryptoMurmur32Op } => 4,
        BinaryExpr { Sort: Sort.Bytes, Op: CryptoRecoverSecp256K1Op } => 33,
        BinaryExpr { Sort: Sort.Bytes, Op: CryptoBlsAddG1Op } => 48,
        BinaryExpr { Sort: Sort.Bytes, Op: CryptoBlsAddG2Op } => 96,
        BinaryExpr { Sort: Sort.Bytes, Op: CryptoBlsAddGtOp } => 576,
        TernaryExpr { Sort: Sort.Bytes, Op: CryptoBlsMulG1Op } => 48,
        TernaryExpr { Sort: Sort.Bytes, Op: CryptoBlsMulG2Op } => 96,
        TernaryExpr { Sort: Sort.Bytes, Op: CryptoBlsMulGtOp } => 576,
        BinaryExpr { Sort: Sort.Bytes, Op: CryptoBlsPairingOp } => 576,
        _ => null,
    };

    /// <summary>
    /// Audit fix (iter-2 wakeup-5 differential): NeoVM's `Pop().GetInteger()` converts Boolean
    /// (false=0, true=1) and ByteString (little-endian signed) to BigInteger. The numeric
    /// comparison branches and arithmetic ops need to fold the same cross-type semantics or
    /// they fail to resolve concrete comparisons like JMPGE (11, false) → fork instead of
    /// concretely true.
    /// </summary>
    public static BigInteger? ConcreteInt(Expression e) => e switch
    {
        IntConst i => i.Value,
        BoolConst b => b.Value ? BigInteger.One : BigInteger.Zero,
        BytesConst by => BytesToInteger(by.Value),
        _ => null,
    };

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

    public static BigInteger? ConcreteByteAt(Expression bytesExpression, Expression indexExpression)
    {
        if (ConcreteInt(indexExpression) is not { } rawIndex
            || rawIndex.Sign < 0
            || rawIndex > int.MaxValue)
        {
            return null;
        }

        return TryConcreteByteAt(bytesExpression, (int)rawIndex, out byte value)
            ? value
            : null;
    }

    private static bool TryConcreteByteAt(Expression expression, int index, out byte value)
    {
        value = default;
        if (index < 0)
            return false;
        if (CanonicalBytes(expression) is { } bytes)
        {
            if (index >= bytes.Length)
                return false;
            value = bytes[index];
            return true;
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } cat
            && TryKnownByteLength(cat.Left, out int leftLength))
        {
            return index < leftLength
                ? TryConcreteByteAt(cat.Left, index, out value)
                : TryConcreteByteAt(cat.Right, index - leftLength, out value);
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "left" } left
            && ConcreteInt(left.Right) is { } leftCount
            && leftCount >= 0
            && leftCount <= int.MaxValue
            && index < leftCount)
        {
            return TryConcreteByteAt(left.Left, index, out value);
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "right" } right
            && ConcreteInt(right.Right) is { } rightCount
            && rightCount >= 0
            && rightCount <= int.MaxValue
            && index < rightCount
            && TryKnownByteLength(right.Left, out int sourceLength))
        {
            long sourceIndex = (long)sourceLength - (int)rightCount + index;
            return sourceIndex is >= 0 and <= int.MaxValue
                && TryConcreteByteAt(right.Left, (int)sourceIndex, out value);
        }

        if (expression is TernaryExpr { Sort: Sort.Bytes, Op: "substr" } substr
            && ConcreteInt(substr.B) is { } start
            && ConcreteInt(substr.C) is { } count
            && start >= 0
            && start <= int.MaxValue
            && count >= 0
            && count <= int.MaxValue
            && index < count)
        {
            long sourceIndex = (int)start + (long)index;
            return sourceIndex <= int.MaxValue
                && TryConcreteByteAt(substr.A, (int)sourceIndex, out value);
        }

        return false;
    }

    public static bool TryKnownByteLength(Expression expression, out int length)
    {
        if (CanonicalBytes(expression) is { } bytes)
        {
            length = bytes.Length;
            return true;
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "cat" } cat
            && TryKnownByteLength(cat.Left, out int leftLength)
            && TryKnownByteLength(cat.Right, out int rightLength))
        {
            length = leftLength + rightLength;
            return true;
        }

        if (expression is BinaryExpr { Sort: Sort.Bytes, Op: "left" or "right" } side
            && ConcreteInt(side.Right) is { } sideLength
            && sideLength >= 0
            && sideLength <= int.MaxValue)
        {
            length = (int)sideLength;
            return true;
        }

        if (expression is TernaryExpr { Sort: Sort.Bytes, Op: "substr" } substr
            && ConcreteInt(substr.C) is { } substrLength
            && substrLength >= 0
            && substrLength <= int.MaxValue)
        {
            length = (int)substrLength;
            return true;
        }

        length = 0;
        return false;
    }

    // ---- Boolean / truthiness
    // Audit fix (iter-2 wakeup-5 differential): NeoVM's GetBoolean has type-specific rules:
    //   ByteString → any-nonzero-byte (NOT just non-empty — `[0]` is FALSE)
    //   CompoundType (Array/Struct/Map) → always TRUE
    //   Buffer → always TRUE
    //   Null → FALSE
    // Our engine previously treated ByteString as length>0 (wrong for `[0,0,0]`) and
    // returned null for HeapRef (causing NOT/SHR fast-paths to fall through to Pop).
    public static bool? Truthy(Expression e) => e switch
    {
        IntConst i => !i.Value.IsZero,
        BoolConst b => b.Value,
        BytesConst by => HasNonZeroByte(by.Value),
        NullConst => false,
        HeapRef => true,
        // Review fix (#35): NeoVM's Pointer.GetBoolean() and InteropInterface.GetBoolean() always
        // return true (both are non-null references; only Null is falsy). A bare PointerConst or a
        // symbolic Pointer/InteropInterface value previously fell through to `null`, forcing an
        // unnecessary symbolic branch on ASSERT/JMPIF. HeapRef-wrapped interops already returned
        // true via the HeapRef arm; this covers the non-HeapRef forms.
        PointerConst => true,
        Symbol { Sort: Sort.Pointer or Sort.InteropInterface } => true,
        _ => null,
    };

    private static bool HasNonZeroByte(byte[] bytes)
    {
        foreach (var b in bytes) if (b != 0) return true;
        return false;
    }

    // ---- Arithmetic
    // Audit fix (iter-2 wakeup-5 differential): every numeric simplifier should canonicalize
    // Bool/Bytes/Int via ConcreteInt before deciding if it can fold concretely. NeoVM's
    // Pop().GetInteger() does this implicit conversion; we have to mirror it or `false ABS`
    // becomes a UnaryExpr that downstream comparisons can't fold to a known branch.

    public static Expression Add(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } ax && ConcreteInt(b) is { } bx) return Int(ax + bx);
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value + bi.Value);
        if (a is IntConst z1 && z1.Value.IsZero) return b;
        if (b is IntConst z2 && z2.Value.IsZero) return a;
        return new BinaryExpr(Sort.Int, "+", a, b);
    }

    public static Expression Sub(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } ax2 && ConcreteInt(b) is { } bx2) return Int(ax2 - bx2);
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value - bi.Value);
        if (b is IntConst z && z.Value.IsZero) return a;
        return new BinaryExpr(Sort.Int, "-", a, b);
    }

    public static Expression Mul(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } ax3 && ConcreteInt(b) is { } bx3) return Int(ax3 * bx3);
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value * bi.Value);
        if (a is IntConst z && z.Value.IsZero) return Int(0);
        if (b is IntConst z2 && z2.Value.IsZero) return Int(0);
        if (a is IntConst o && o.Value == 1) return b;
        if (b is IntConst o2 && o2.Value == 1) return a;
        return new BinaryExpr(Sort.Int, "*", a, b);
    }

    public static Expression Div(Expression a, Expression b)
    {
        if (ConcreteInt(b) is { } div_b && div_b.IsZero)
            throw new VmFaultException("DIV by zero");
        if (ConcreteInt(a) is { } div_a && ConcreteInt(b) is { } div_b2)
            return Int(NeoTruncatedDivide(div_a, div_b2));
        return new BinaryExpr(Sort.Int, "/", a, b);
    }

    public static Expression Mod(Expression a, Expression b)
    {
        if (ConcreteInt(b) is { } mod_b && mod_b.IsZero)
            throw new VmFaultException("MOD by zero");
        if (ConcreteInt(a) is { } mod_a && ConcreteInt(b) is { } mod_b2)
            return Int(NeoTruncatedModulo(mod_a, mod_b2));
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
    public static bool IsWithinNeoVmIntegerRange(BigInteger value) =>
        value >= NeoVmIntegerMin && value <= NeoVmIntegerMax;

    public static Expression Neg(Expression a)
    {
        if (ConcreteInt(a) is { } ax) return Int(-ax);
        return new UnaryExpr(Sort.Int, "neg", a);
    }

    public static Expression Abs(Expression a)
    {
        if (ConcreteInt(a) is { } ax) return Int(BigInteger.Abs(ax));
        return new UnaryExpr(Sort.Int, "abs", a);
    }

    public static Expression Sign(Expression a)
    {
        if (ConcreteInt(a) is { } ax) return Int(ax.Sign);
        return new UnaryExpr(Sort.Int, "sign", a);
    }

    public static Expression Inc(Expression a) => Add(a, Int(1));
    public static Expression Dec(Expression a) => Sub(a, Int(1));

    public static Expression Pow(Expression a, Expression b, int maxExponent = 256)
    {
        if (ConcreteInt(a) is { } pow_a && ConcreteInt(b) is { } pow_b)
        {
            if (pow_b < 0) throw new VmFaultException("POW negative exponent");
            if (pow_b > maxExponent) throw new VmFaultException("POW exponent too large");
            return Int(BigInteger.Pow(pow_a, (int)pow_b));
        }
        return new BinaryExpr(Sort.Int, "pow", a, b);
    }

    public static Expression Sqrt(Expression a)
    {
        if (ConcreteInt(a) is { } sqrt_a)
        {
            if (sqrt_a < 0) throw new VmFaultException("SQRT negative input");
            return Int(IntegerSquareRoot(sqrt_a));
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
        if (ConcreteInt(a) is { } mm_a && ConcreteInt(b) is { } mm_b && ConcreteInt(m) is { } mm_m)
        {
            if (mm_m.IsZero) throw new VmFaultException("MODMUL with zero modulus");
            return Int((mm_a * mm_b) % mm_m);
        }
        return new TernaryExpr(Sort.Int, "modmul", a, b, m);
    }

    public static Expression ModPow(Expression a, Expression b, Expression m)
    {
        if (ConcreteInt(a) is { } mp_a && ConcreteInt(b) is { } mp_b && ConcreteInt(m) is { } mp_m)
        {
            if (mp_m.IsZero) throw new VmFaultException("MODPOW with zero modulus");
            // Audit fix (iter-2 wakeup-5 differential): NeoVM treats exp == -1 as modular
            // inverse via extended Euclidean. Any other negative exp throws. Match exactly.
            if (mp_b == -1)
                return Int(ModInverse(mp_a, mp_m));
            if (mp_b < 0)
                throw new VmFaultException($"MODPOW with negative exponent {mp_b}");
            // Round-3 audit fix: NeoVM's MODPOW has NO exponent cap (verified by executing
            // `2^300 mod 1000` on the real VM => 376). BigInteger.ModPow is O(log exponent), so even a
            // 255-bit exponent is cheap; the prior 256-exponent fault pruned feasible paths.
            return Int(BigInteger.ModPow(mp_a, mp_b, mp_m));
        }
        return new TernaryExpr(Sort.Int, "modpow", a, b, m);
    }

    /// <summary>
    /// Modular inverse via extended Euclidean. Mirrors Neo.VM.Utility.ModInverse exactly so
    /// MODPOW with exp == -1 produces bit-identical output. Throws on invalid inputs (value
    /// non-positive, modulus &lt; 2, or no inverse exists).
    /// </summary>
    private static BigInteger ModInverse(BigInteger value, BigInteger modulus)
    {
        if (value <= 0)
            throw new VmFaultException($"MODPOW.ModInverse: value {value} must be positive");
        if (modulus < 2)
            throw new VmFaultException($"MODPOW.ModInverse: modulus {modulus} must be >= 2");
        BigInteger r = value, old_r = modulus, s = 1, old_s = 0;
        while (r > 0)
        {
            BigInteger q = old_r / r;
            (old_r, r) = (r, old_r % r);
            (old_s, s) = (s, old_s - q * s);
        }
        BigInteger result = old_s % modulus;
        if (result < 0) result += modulus;
        if (!(value * result % modulus).IsOne)
            throw new VmFaultException($"MODPOW.ModInverse: no inverse for {value} mod {modulus}");
        return result;
    }

    public static Expression Shl(Expression a, Expression b, int maxShift = 256)
    {
        // Round-3 audit fix: NeoVM validates the shift count before the value, so a concrete
        // out-of-range shift faults even when the value operand is symbolic. The prior `&&` guard
        // checked the bound only when BOTH operands were concrete, letting a symbolic-value shift by a
        // concrete >maxShift count slip past the fault.
        if (ConcreteInt(b) is { } shl_b)
        {
            if (shl_b < 0) throw new VmFaultException("SHL by negative count");
            if (shl_b > maxShift) throw new VmFaultException("SHL count too large");
            if (ConcreteInt(a) is { } shl_a) return Int(shl_a << (int)shl_b);
        }
        return new BinaryExpr(Sort.Int, "<<", a, b);
    }

    public static Expression Shr(Expression a, Expression b, int maxShift = 256)
    {
        // Round-3 audit fix: validate the concrete shift count regardless of whether the value is
        // concrete (see Shl).
        if (ConcreteInt(b) is { } shr_b)
        {
            if (shr_b < 0) throw new VmFaultException("SHR by negative count");
            if (shr_b > maxShift) throw new VmFaultException("SHR count too large");
            if (ConcreteInt(a) is { } shr_a) return Int(shr_a >> (int)shr_b);
        }
        return new BinaryExpr(Sort.Int, ">>", a, b);
    }

    // ---- Bitwise
    // Audit C# #5: bool↔bool fold via int promotion so the result has consistent sort with
    // NeoVM's coercion behavior. Without this, AND(true, false) returned a BinaryExpr(Sort.Int)
    // with non-int operands — a sort-lattice inconsistency.
    public static Expression And(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } and_a && ConcreteInt(b) is { } and_b) return Int(and_a & and_b);
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value & bi.Value);
        if (a is BoolConst ab && b is BoolConst bb) return Int((ab.Value ? 1 : 0) & (bb.Value ? 1 : 0));
        return new BinaryExpr(Sort.Int, "&", a, b);
    }

    public static Expression Or(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } or_a && ConcreteInt(b) is { } or_b) return Int(or_a | or_b);
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value | bi.Value);
        if (a is BoolConst ab && b is BoolConst bb) return Int((ab.Value ? 1 : 0) | (bb.Value ? 1 : 0));
        return new BinaryExpr(Sort.Int, "|", a, b);
    }

    public static Expression Xor(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } xor_a && ConcreteInt(b) is { } xor_b) return Int(xor_a ^ xor_b);
        if (a is IntConst ai && b is IntConst bi) return Int(ai.Value ^ bi.Value);
        if (a is BoolConst ab && b is BoolConst bb) return Int((ab.Value ? 1 : 0) ^ (bb.Value ? 1 : 0));
        return new BinaryExpr(Sort.Int, "^", a, b);
    }

    public static Expression Invert(Expression a)
    {
        if (ConcreteInt(a) is { } ax) return Int(~ax);
        return new UnaryExpr(Sort.Int, "~", a);
    }

    // ---- Comparison
    public static Expression Eq(Expression a, Expression b)
    {
        if (a.Equals(b)) return BoolConst.True;

        // NeoVM's EQUAL opcode is StackItem.Equals, which is TYPE-STRICT for every primitive:
        // Boolean.Equals/Integer.Equals/ByteString.Equals each `isinst`-check the operand and return
        // false for any other StackItem type. So the only EQUAL-true pairs are same-type:
        //   (Bool, Bool)   : compare values
        //   (Int, Int)     : compare values
        //   (Bytes, Bytes) : compare bytes
        // and EVERY cross-type concrete pair — including Integer vs ByteString — is FALSE. Verified by
        // decompiling Neo.VM 3.10.0 (Integer.Equals: `if (other is Integer) value-compare else false`;
        // ByteString.Equals symmetric) and by executing EQUAL on the real VM: Int(0) vs Bytes(b""),
        // Int(5) vs Bytes(b"\x05") both push False in both stack orderings. (The numeric cross-type
        // compare NeoVM uses for NUMEQUAL/JMP* is GetInteger-based and lives in NumEq, not here.)
        if (a.IsConcrete && b.IsConcrete && a is not NullConst && b is not NullConst)
        {
            if (a is BoolConst aBoolC && b is BoolConst bBoolC) return Bool(aBoolC.Value == bBoolC.Value);
            if (a is IntConst aIntC && b is IntConst bIntC) return Bool(aIntC.Value == bIntC.Value);
            if (a is BytesConst aBytesC && b is BytesConst bBytesC)
                return Bool(aBytesC.Value.AsSpan().SequenceEqual(bBytesC.Value));
            // Any cross-type concrete pair (Bool/Int/Bytes mixed): different StackItem types => false.
            return BoolConst.False;
        }
        if (a is NullConst && b is NullConst) return BoolConst.True;
        if ((a is NullConst) != (b is NullConst))
            return BoolConst.False;
        if (a is HeapRef ah && b is HeapRef bh)
            return Bool(ah.RefSort == bh.RefSort && ah.ObjectId == bh.ObjectId);
        // Audit fix (iter-2 wakeup-5 differential): a HeapRef compared to a concrete primitive
        // (Int/Bool/Bytes) reduces to BoolConst.False per NeoVM — they are different StackItem
        // types and Equals returns false. The prior code emitted a BinaryExpr that downstream
        // ops couldn't reduce, causing e.g. NEWMAP PUSH12 EQUAL SHR to underflow on the SHR
        // because EQUAL's BinaryExpr result couldn't fold to 0 for the shift==0 fast path.
        if (a is HeapRef && b.IsConcrete && b is not NullConst) return BoolConst.False;
        if (b is HeapRef && a.IsConcrete && a is not NullConst) return BoolConst.False;
        if (a is BoolConst ab && b is BoolConst bb) return Bool(ab.Value == bb.Value);
        return new BinaryExpr(Sort.Bool, "==", a, b);
    }

    /// <summary>
    /// Numeric equality matching NeoVM's `NumEqual` and JMPEQ semantics: both operands are
    /// converted via `Pop().GetInteger()` (Bool→0/1, Bytes→signed-LE int) before comparing.
    /// Distinct from <see cref="Eq"/> which uses StackItem-Equals semantics (Boolean.Equals(
    /// Integer) always returns false). The differential target found this in iter-2 wakeup-10:
    /// `JMPEQ true 1` jumps in NeoVM (1 == 1) but our prior code didn't (different StackItem).
    /// </summary>
    public static Expression NumEq(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } na && ConcreteInt(b) is { } nb) return Bool(na == nb);
        return new BinaryExpr(Sort.Bool, "num==", a, b);
    }

    public static Expression NumNe(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } na && ConcreteInt(b) is { } nb) return Bool(na != nb);
        return new BinaryExpr(Sort.Bool, "num!=", a, b);
    }

    public static Expression Ne(Expression a, Expression b)
    {
        var eq = Eq(a, b);
        if (eq is BoolConst be) return Bool(!be.Value);
        return Not(eq);
    }

    // Audit fix (iter-2 wakeup-5 differential): NeoVM's numeric comparisons (LT/LE/GT/GE)
    // explicitly handle null on either side by pushing false, BEFORE attempting GetInteger.
    // Our prior implementation fell through to a BinaryExpr that downstream ops couldn't fold.
    public static Expression Lt(Expression a, Expression b)
    {
        if (a is NullConst || b is NullConst) return BoolConst.False;
        if (ConcreteInt(a) is { } ax && ConcreteInt(b) is { } bx) return Bool(ax < bx);
        return new BinaryExpr(Sort.Bool, "<", a, b);
    }

    public static Expression Le(Expression a, Expression b)
    {
        if (a is NullConst || b is NullConst) return BoolConst.False;
        if (ConcreteInt(a) is { } ax && ConcreteInt(b) is { } bx) return Bool(ax <= bx);
        return new BinaryExpr(Sort.Bool, "<=", a, b);
    }

    public static Expression Gt(Expression a, Expression b)
    {
        if (a is NullConst || b is NullConst) return BoolConst.False;
        if (ConcreteInt(a) is { } ax && ConcreteInt(b) is { } bx) return Bool(ax > bx);
        return new BinaryExpr(Sort.Bool, ">", a, b);
    }

    public static Expression Ge(Expression a, Expression b)
    {
        if (a is NullConst || b is NullConst) return BoolConst.False;
        if (ConcreteInt(a) is { } ax && ConcreteInt(b) is { } bx) return Bool(ax >= bx);
        return new BinaryExpr(Sort.Bool, ">=", a, b);
    }

    public static Expression Min(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } min_a && ConcreteInt(b) is { } min_b) return Int(BigInteger.Min(min_a, min_b));
        if (a is IntConst ai && b is IntConst bi) return Int(BigInteger.Min(ai.Value, bi.Value));
        return new BinaryExpr(Sort.Int, "min", a, b);
    }

    public static Expression Max(Expression a, Expression b)
    {
        if (ConcreteInt(a) is { } max_a && ConcreteInt(b) is { } max_b) return Int(BigInteger.Max(max_a, max_b));
        if (a is IntConst ai && b is IntConst bi) return Int(BigInteger.Max(ai.Value, bi.Value));
        return new BinaryExpr(Sort.Int, "max", a, b);
    }

    public static Expression Within(Expression x, Expression lo, Expression hi)
    {
        if (ConcreteInt(x) is { } w_x && ConcreteInt(lo) is { } w_lo && ConcreteInt(hi) is { } w_hi)
            return Bool(w_lo <= w_x && w_x < w_hi);
        return new TernaryExpr(Sort.Bool, "within", x, lo, hi);
    }

    public static Expression Ite(Expression condition, Expression whenTrue, Expression whenFalse)
    {
        if (whenTrue.Sort != whenFalse.Sort)
            throw new InvalidOperationException("ITE branches must have the same sort");

        if (Truthy(condition) is { } concreteCondition)
            return concreteCondition ? whenTrue : whenFalse;
        if (whenTrue.Equals(whenFalse))
            return whenTrue;

        return new TernaryExpr(whenTrue.Sort, "ite", condition, whenTrue, whenFalse);
    }

    // ---- Logic
    public static Expression Not(Expression a)
    {
        // Audit fix (iter-2 wakeup-5 differential): use Truthy() so NOT(HeapRef)/NOT(NullConst)/
        // NOT(BytesConst) all reduce concretely. Prior code only handled BoolConst and IntConst,
        // so NEWARRAY0 NOT produced a UnaryExpr that downstream SHR couldn't fold to shift==0.
        var t = Truthy(a);
        if (t.HasValue) return Bool(!t.Value);
        if (a is UnaryExpr u && u.Op == "not") return u.Operand;
        return new UnaryExpr(Sort.Bool, "not", a);
    }

    public static Expression BoolAnd(Expression a, Expression b)
    {
        var ta = Truthy(a);
        var tb = Truthy(b);
        if (ta == false || tb == false) return BoolConst.False;
        if (ta == true && tb == true) return BoolConst.True;
        // Audit fix (engine M3): when one side is concretely true, BoolAnd reduces to ToBool(other).
        // Prior code kept a known-true operand inside the BinaryExpr, bloating path conditions and
        // making the SMT layer enumerate redundant clauses. ToBool collapses the wrapped form when
        // it can (else returns a tobool node, which is still smaller than `and(true, x)`).
        if (ta == true) return ToBool(b);
        if (tb == true) return ToBool(a);
        return new BinaryExpr(Sort.Bool, "and", a, b);
    }

    public static Expression BoolOr(Expression a, Expression b)
    {
        var ta = Truthy(a);
        var tb = Truthy(b);
        if (ta == true || tb == true) return BoolConst.True;
        if (ta == false && tb == false) return BoolConst.False;
        // Audit fix (engine M3): when one side is concretely false, BoolOr reduces to ToBool(other).
        if (ta == false) return ToBool(b);
        if (tb == false) return ToBool(a);
        return new BinaryExpr(Sort.Bool, "or", a, b);
    }

    public static Expression Nz(Expression a)
    {
        if (ConcreteInt(a) is { } v) return Bool(!v.IsZero);
        return new UnaryExpr(Sort.Bool, "nz", a);
    }

    /// <summary>Convert to a Boolean per NeoVM truthiness rules.</summary>
    public static Expression ToBool(Expression a)
    {
        var t = Truthy(a);
        if (t.HasValue) return Bool(t.Value);
        if (a.Sort == Sort.Bool) return a;
        if (a.Sort is Sort.Int or Sort.Bytes) return Nz(a);
        return new UnaryExpr(Sort.Bool, "tobool", a);
    }
}
