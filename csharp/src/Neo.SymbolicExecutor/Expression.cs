using System.Collections.Generic;
using System.Linq;
using System.Numerics;

namespace Neo.SymbolicExecutor;

/// <summary>
/// Symbolic expression IR. Immutable record hierarchy.
///
/// Concrete leaves: <see cref="IntConst"/>, <see cref="BoolConst"/>, <see cref="BytesConst"/>, <see cref="NullConst"/>.
/// Symbolic leaves: <see cref="Symbol"/>.
/// Heap leaves: <see cref="HeapRef"/> (object identity for arrays/structs/maps/buffers).
/// Composites: <see cref="UnaryExpr"/>, <see cref="BinaryExpr"/>, <see cref="TernaryExpr"/>.
/// </summary>
public abstract record Expression(Sort Sort)
{
    public bool IsConcrete => this is IntConst or BoolConst or BytesConst or NullConst;

    /// <summary>Approximate complexity score used by path-uncertainty calibration.</summary>
    public abstract int Complexity { get; }

    /// <summary>Recursively gather names of all <see cref="Symbol"/> leaves.</summary>
    public IEnumerable<string> FreeSymbols() => CollectSymbols(this);

    private static IEnumerable<string> CollectSymbols(Expression expr) => expr switch
    {
        Symbol s => new[] { s.Name },
        UnaryExpr u => CollectSymbols(u.Operand),
        BinaryExpr b => CollectSymbols(b.Left).Concat(CollectSymbols(b.Right)),
        TernaryExpr t => CollectSymbols(t.A).Concat(CollectSymbols(t.B)).Concat(CollectSymbols(t.C)),
        _ => Enumerable.Empty<string>(),
    };
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
