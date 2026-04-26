using System.Collections.Generic;
using System.Collections.Immutable;
using System.Numerics;

namespace Neo.SymbolicExecutor;

/// <summary>
/// A value flowing through the symbolic stack. Wraps an <see cref="Expression"/>
/// with a taint set (free-form labels propagated through operations).
///
/// Equality is structural (record), but the stack uses reference comparison for heap-backed
/// values via the <see cref="HeapRef"/> wrapped inside <see cref="Expression"/>.
/// </summary>
public sealed record SymbolicValue(Expression Expression, ImmutableHashSet<string> Taints)
{
    public Sort Sort => Expression.Sort;
    public bool IsConcrete => Expression.IsConcrete;

    public BigInteger? AsConcreteInt() => Expression is IntConst i ? i.Value : null;
    public bool? AsConcreteBool() => Expression is BoolConst b ? b.Value : null;
    public byte[]? AsConcreteBytes() => Expression is BytesConst by ? by.Value : null;
    public bool IsConcreteNull => Expression is NullConst;

    public static SymbolicValue Of(Expression expr) =>
        new(expr, ImmutableHashSet<string>.Empty);

    public static SymbolicValue Of(Expression expr, IEnumerable<string> taints) =>
        new(expr, taints.ToImmutableHashSet());

    public static SymbolicValue Int(BigInteger value) => Of(Expr.Int(value));
    public static SymbolicValue Int(long value) => Of(Expr.Int(value));
    public static SymbolicValue Bool(bool value) => Of(Expr.Bool(value));
    public static SymbolicValue Bytes(byte[] value) => Of(Expr.Bytes(value));
    public static SymbolicValue Null() => Of(Expr.Null());
    public static SymbolicValue Symbol(Sort sort, string name) => Of(Expr.Sym(sort, name));
    public static SymbolicValue HeapRef(Sort sort, int id) => Of(Expr.Ref(sort, id));

    public SymbolicValue WithTaints(ImmutableHashSet<string> taints) => this with { Taints = taints };

    public SymbolicValue UnionTaints(SymbolicValue other) =>
        this with { Taints = Taints.Union(other.Taints) };

    public SymbolicValue WithTaint(string taint) =>
        this with { Taints = Taints.Add(taint) };

    /// <summary>
    /// Truthiness per NeoVM: true if not null, not zero, and (for bytes) non-empty.
    /// Returns null if the truthiness cannot be statically determined.
    /// </summary>
    public bool? Truthy() => Expr.Truthy(Expression);
}
