using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Symbolic expression IR. Immutable record hierarchy.
///
/// Concrete leaves: <see cref="IntConst"/>, <see cref="BoolConst"/>, <see cref="BytesConst"/>, <see cref="PointerConst"/>, <see cref="NullConst"/>.
/// Symbolic leaves: <see cref="Symbol"/>.
/// Heap leaves: <see cref="HeapRef"/> (object identity for arrays/structs/maps/buffers).
/// Composites: <see cref="UnaryExpr"/>, <see cref="BinaryExpr"/>, <see cref="TernaryExpr"/>.
/// </summary>
public abstract record Expression(Sort Sort)
{
    public bool IsConcrete => this is IntConst or BoolConst or BytesConst or PointerConst or NullConst;

    /// <summary>Approximate complexity score used by path-uncertainty calibration.</summary>
    public abstract int Complexity { get; }

    /// <summary>Recursively gather names of all <see cref="Symbol"/> leaves, in depth-first order.</summary>
    public IEnumerable<string> FreeSymbols()
    {
        // Review fix (#71): accumulate into a single list rather than building nested LINQ Concat
        // iterator chains (which allocate an iterator per composite node and re-enumerate on each
        // access). The produced sequence is identical — same depth-first order, same duplicates — so
        // all existing call sites (membership checks, ToArray, etc.) are unaffected.
        var acc = new List<string>();
        CollectSymbolsInto(this, acc);
        return acc;
    }

    private static void CollectSymbolsInto(Expression expr, List<string> acc)
    {
        switch (expr)
        {
            case Symbol s: acc.Add(s.Name); break;
            case UnaryExpr u: CollectSymbolsInto(u.Operand, acc); break;
            case BinaryExpr b:
                CollectSymbolsInto(b.Left, acc);
                CollectSymbolsInto(b.Right, acc);
                break;
            case TernaryExpr t:
                CollectSymbolsInto(t.A, acc);
                CollectSymbolsInto(t.B, acc);
                CollectSymbolsInto(t.C, acc);
                break;
        }
    }
}

public sealed record IntConst(BigInteger Value) : Expression(Sort.Int)
{
    public override int Complexity => 1;
}

public sealed record BoolConst(bool Value) : Expression(Sort.Bool)
{
    public override int Complexity => 1;
    public static readonly BoolConst True = new(true);
    public static readonly BoolConst False = new(false);
}

public sealed record BytesConst : Expression
{
    public byte[] Value { get; }

    public BytesConst(byte[] value) : base(Sort.Bytes)
    {
        Value = value;
    }

    public override int Complexity => 1;

    public bool ValueEquals(BytesConst other) => Value.AsSpan().SequenceEqual(other.Value);

    public bool Equals(BytesConst? other) =>
        other is not null && Sort == other.Sort && Value.AsSpan().SequenceEqual(other.Value);

    public override int GetHashCode()
    {
        unchecked
        {
            int h = (int)2166136261;
            foreach (var b in Value) h = (h ^ b) * 16777619;
            return h;
        }
    }
}

public sealed record NullConst() : Expression(Sort.Null)
{
    public override int Complexity => 1;
    public static readonly NullConst Instance = new();
}

public sealed record PointerConst(int TargetOffset) : Expression(Sort.Pointer)
{
    public override int Complexity => 1;
}

public sealed record HeapRef(Sort RefSort, int ObjectId) : Expression(RefSort)
{
    public override int Complexity => 1;
}

public sealed record Symbol(Sort Sort, string Name) : Expression(Sort)
{
    public override int Complexity => 2;
}

public sealed record UnaryExpr(Sort Sort, string Op, Expression Operand) : Expression(Sort)
{
    public override int Complexity => 1 + Operand.Complexity;
}

public sealed record BinaryExpr(Sort Sort, string Op, Expression Left, Expression Right) : Expression(Sort)
{
    public override int Complexity => 1 + Left.Complexity + Right.Complexity;
}

public sealed record TernaryExpr(Sort Sort, string Op, Expression A, Expression B, Expression C) : Expression(Sort)
{
    public override int Complexity => 1 + A.Complexity + B.Complexity + C.Complexity;
}
