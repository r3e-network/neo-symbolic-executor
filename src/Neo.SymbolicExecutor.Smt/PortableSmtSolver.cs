using System;
using System.Collections.Generic;
using System.Numerics;
using Neo.SymbolicExecutor;

namespace Neo.SymbolicExecutor.Smt.Z3;

/// <summary>
/// Conservative in-process fallback for hosts without a z3 executable. It proves scaled single-
/// symbol linear constraints, bounded two-symbol affine constraints, symbol-offset equalities,
/// and bounds; unsupported formulas return Unknown unless a contradiction has already been proven.
/// </summary>
internal sealed class PortableSmtSolver
{
    public PortableSmtResult IsSatisfiable(IReadOnlyList<Expression> conditions)
    {
        var model = new ConstraintModel();
        var outcome = Analyze(conditions, model);
        return new PortableSmtResult(outcome, Value: null, Witness: null);
    }

    public PortableSmtResult BuildWitness(IReadOnlyList<Expression> conditions)
    {
        var model = new ConstraintModel();
        var outcome = Analyze(conditions, model);
        if (outcome != SmtOutcome.Sat)
            return new PortableSmtResult(outcome, Value: null, Witness: null);

        return model.TryBuildWitness(out var witness)
            ? new PortableSmtResult(SmtOutcome.Sat, Value: null, Witness: witness)
            : new PortableSmtResult(SmtOutcome.Unknown, Value: null, Witness: null);
    }

    public PortableSmtResult ConcretizeInt(
        IReadOnlyList<Expression> conditions,
        Expression target,
        BigInteger? lo,
        BigInteger? hi)
    {
        var model = new ConstraintModel();
        var outcome = Analyze(conditions, model);
        if (outcome != SmtOutcome.Sat)
            return new PortableSmtResult(outcome, Value: null, Witness: null);

        if (!model.TryConcretize(target, lo, hi, out var value))
            return new PortableSmtResult(SmtOutcome.Unknown, Value: null, Witness: null);

        if (value is null)
            return new PortableSmtResult(SmtOutcome.Unsat, Value: null, Witness: null);
        return new PortableSmtResult(SmtOutcome.Sat, value.Value, null);
    }

    private static SmtOutcome Analyze(IReadOnlyList<Expression> conditions, ConstraintModel model)
    {
        var sawUnsupported = false;
        foreach (var condition in conditions)
        {
            var status = model.Apply(condition, negated: false);
            if (status == ConstraintStatus.Contradiction)
                return SmtOutcome.Unsat;
            if (status == ConstraintStatus.Unsupported)
                sawUnsupported = true;
        }

        return sawUnsupported ? SmtOutcome.Unknown : SmtOutcome.Sat;
    }

    private sealed class ConstraintModel
    {
        private const int MaxAffineSymbols = 2;

        private readonly Dictionary<string, IntDomain> _ints = new(StringComparer.Ordinal);
        private readonly List<SymbolEquality> _equalities = new();
        private readonly List<AffineTerm> _affineEqualities = new();

        public IntDomain GetIntDomain(string name)
        {
            if (!_ints.TryGetValue(name, out var domain))
            {
                domain = new IntDomain();
                _ints[name] = domain;
            }
            return domain;
        }

        public ConstraintStatus Apply(Expression expression, bool negated)
        {
            return expression switch
            {
                BoolConst b => ApplyBool(b.Value, negated),
                UnaryExpr { Op: "not" } unary => Apply(unary.Operand, !negated),
                BinaryExpr { Op: "and" } binary when !negated => ApplyAnd(binary),
                BinaryExpr { Sort: Sort.Bool } binary => ApplyPredicate(binary, negated),
                _ => ConstraintStatus.Unsupported,
            };
        }

        private ConstraintStatus ApplyAnd(BinaryExpr binary)
        {
            var left = Apply(binary.Left, negated: false);
            if (left == ConstraintStatus.Contradiction) return left;

            var right = Apply(binary.Right, negated: false);
            if (right == ConstraintStatus.Contradiction) return right;

            return left == ConstraintStatus.Unsupported || right == ConstraintStatus.Unsupported
                ? ConstraintStatus.Unsupported
                : ConstraintStatus.Supported;
        }

        /// <summary>
        /// Apply a relational predicate to the solver state in three phases:
        ///   1. Negate the op if the caller passed `negated`. Unknown ops escape as Unsupported.
        ///   2. Affine path: if both sides parse as affine terms, take the difference and
        ///      apply the relation via <see cref="ApplyAffineRelation"/>. This handles
        ///      multi-symbol linear forms that the legacy linear path can't.
        ///   3. Linear fallback: parse each side as a single-symbol <see cref="LinearTerm"/>.
        ///      If the difference reduces (same symbol, possibly scaled), apply via
        ///      <see cref="ApplyRelation"/>; otherwise try the symbol-equality path that
        ///      handles `x == y + k` shapes.
        /// Soundness invariant: each phase that returns a definite Supported/Contradiction
        /// answer terminates dispatch; only Unsupported falls through to the next phase. The
        /// final return is Unsupported (over-approximation) — never silent UNSAT.
        /// </summary>
        private ConstraintStatus ApplyPredicate(BinaryExpr binary, bool negated)
        {
            var op = negated ? Negate(binary.Op) : binary.Op;
            if (op is null) return ConstraintStatus.Unsupported;

            var affineStatus = TryApplyAffinePath(binary, op);
            if (affineStatus != ConstraintStatus.Unsupported)
                return affineStatus;

            return ApplyLinearPath(binary, op);
        }

        private ConstraintStatus TryApplyAffinePath(BinaryExpr binary, string op)
        {
            if (!TryAffineTerm(binary.Left, out var affineLeft)) return ConstraintStatus.Unsupported;
            if (!TryAffineTerm(binary.Right, out var affineRight)) return ConstraintStatus.Unsupported;
            if (!affineLeft.TrySubtract(affineRight, out var affineRelation)) return ConstraintStatus.Unsupported;
            if (!TryRelationOp(op, out var affineOp)) return ConstraintStatus.Unsupported;
            return ApplyAffineRelation(affineRelation, affineOp);
        }

        private ConstraintStatus ApplyLinearPath(BinaryExpr binary, string op)
        {
            if (!TryAsLinearTerm(binary.Left, out var left) || !TryAsLinearTerm(binary.Right, out var right))
                return ConstraintStatus.Unsupported;
            if (!left.TrySubtract(right, out var relation))
            {
                if (!TrySymbolEquality(left, right, out var equality))
                    return ConstraintStatus.Unsupported;
                return op switch
                {
                    "==" or "num==" => AddEquality(equality)
                        ? ConstraintStatus.Supported
                        : ConstraintStatus.Contradiction,
                    "!=" or "num!=" => IsEqualityKnownFalse(equality)
                        ? ConstraintStatus.Supported
                        : ConstraintStatus.Unsupported,
                    _ => ConstraintStatus.Unsupported,
                };
            }

            return op switch
            {
                "==" or "num==" => ApplyRelation(relation, RelationOp.Equal),
                "!=" or "num!=" => ApplyRelation(relation, RelationOp.NotEqual),
                "<" => ApplyRelation(relation, RelationOp.Less),
                "<=" => ApplyRelation(relation, RelationOp.LessOrEqual),
                ">" => ApplyRelation(relation, RelationOp.Greater),
                ">=" => ApplyRelation(relation, RelationOp.GreaterOrEqual),
                _ => ConstraintStatus.Unsupported,
            };
        }

        public bool TryConcretize(Expression target, BigInteger? lo, BigInteger? hi, out BigInteger? value)
        {
            value = null;
            if (!TryAsLinearTerm(target, out var term))
                return false;

            if (term.Symbol is null || term.Coefficient.IsZero)
            {
                if (lo.HasValue && term.Constant < lo.Value)
                    return true;
                if (hi.HasValue && term.Constant > hi.Value)
                    return true;
                value = term.Constant;
                return true;
            }

            var domain = GetIntDomain(term.Symbol).Clone();
            if (lo.HasValue && !ApplyScaledRelation(domain, term.Coefficient, RelationOp.GreaterOrEqual, lo.Value - term.Constant))
                return true;
            if (hi.HasValue && !ApplyScaledRelation(domain, term.Coefficient, RelationOp.LessOrEqual, hi.Value - term.Constant))
                return true;

            if (!domain.TryChoose(out var symbolValue))
                return true;

            value = term.Coefficient * symbolValue + term.Constant;
            return true;
        }

        public bool TryBuildWitness(out IReadOnlyDictionary<string, object> witness)
        {
            var values = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
            foreach (var (name, domain) in _ints)
            {
                if (!domain.TryChoose(out var value))
                {
                    witness = new Dictionary<string, object>();
                    return false;
                }
                values[name] = value;
            }

            // Bound matches PropagateEqualities (line 377). The asymmetric absence of
            // `_ints.Count` here was a latent bug — the witness loop could terminate one or
            // more rounds early on dense chains involving many symbol domains.
            int maxRounds = MaxPropagationRounds();
            for (var i = 0; i < maxRounds; i++)
            {
                foreach (var equality in _equalities)
                {
                    if (!values.TryGetValue(equality.Left, out var left))
                        continue;
                    var right = left - equality.Offset;
                    if (GetIntDomain(equality.Right).Contains(right))
                    {
                        values[equality.Right] = right;
                        continue;
                    }

                    if (!values.TryGetValue(equality.Right, out var existingRight))
                        continue;
                    var adjustedLeft = existingRight + equality.Offset;
                    if (!GetIntDomain(equality.Left).Contains(adjustedLeft))
                    {
                        witness = new Dictionary<string, object>();
                        return false;
                    }
                    values[equality.Left] = adjustedLeft;
                }

                foreach (var equality in _affineEqualities)
                {
                    if (!AdjustWitnessForAffineEquality(equality, values))
                    {
                        witness = new Dictionary<string, object>();
                        return false;
                    }
                }
            }

            foreach (var equality in _affineEqualities)
            {
                if (EvaluateWitness(equality, values) != BigInteger.Zero)
                {
                    witness = new Dictionary<string, object>();
                    return false;
                }
            }

            var result = new Dictionary<string, object>(StringComparer.Ordinal);
            foreach (var (name, value) in values)
                result[name] = value;
            witness = result;
            return true;
        }

        private bool AdjustWitnessForAffineEquality(
            AffineTerm equality,
            Dictionary<string, BigInteger> values)
        {
            var sum = EvaluateWitness(equality, values);
            if (sum.IsZero)
                return true;

            foreach (var (symbol, coefficient) in equality.Coefficients)
            {
                if (coefficient.IsZero || !values.TryGetValue(symbol, out var current))
                    continue;
                if (!TryDivideExactly(-sum, coefficient, out var delta))
                    continue;

                var candidate = current + delta;
                if (!GetIntDomain(symbol).Contains(candidate))
                    continue;

                values[symbol] = candidate;
                return true;
            }

            return false;
        }

        private static BigInteger EvaluateWitness(
            AffineTerm relation,
            IReadOnlyDictionary<string, BigInteger> values)
        {
            var sum = relation.Constant;
            foreach (var (symbol, coefficient) in relation.Coefficients)
            {
                if (values.TryGetValue(symbol, out var value))
                    sum += coefficient * value;
            }
            return sum;
        }

        private ConstraintStatus ApplyAffineRelation(AffineTerm relation, RelationOp op)
        {
            if (relation.TryAsLinearTerm(out var linear))
                return ApplyRelation(linear, op);

            return op switch
            {
                RelationOp.Equal => AddAffineEquality(relation)
                    ? ConstraintStatus.Supported
                    : ConstraintStatus.Contradiction,
                RelationOp.NotEqual => IsAffineKnownNotEqual(relation) switch
                {
                    true => ConstraintStatus.Supported,
                    false when IsAffineKnownEqual(relation) => ConstraintStatus.Contradiction,
                    _ => ConstraintStatus.Unsupported,
                },
                RelationOp.Less or RelationOp.LessOrEqual or RelationOp.Greater or RelationOp.GreaterOrEqual =>
                    ApplyAffineInequality(relation, op),
                _ => ConstraintStatus.Unsupported,
            };
        }

        private ConstraintStatus ApplyRelation(LinearTerm relation, RelationOp op)
        {
            if (relation.Symbol is null || relation.Coefficient.IsZero)
                return Compare(relation.Constant, BigInteger.Zero, op)
                    ? ConstraintStatus.Supported
                    : ConstraintStatus.Contradiction;

            return ApplySymbolRelation(relation.Symbol, relation.Coefficient, op, -relation.Constant);
        }

        private ConstraintStatus ApplySymbolRelation(string symbol, BigInteger coefficient, RelationOp op, BigInteger bound)
        {
            var domain = GetIntDomain(symbol);
            var ok = ApplyScaledRelation(domain, coefficient, op, bound);
            return ok && PropagateEqualities() ? ConstraintStatus.Supported : ConstraintStatus.Contradiction;
        }

        private static bool ApplyScaledRelation(
            IntDomain domain,
            BigInteger coefficient,
            RelationOp op,
            BigInteger bound)
        {
            if (coefficient.IsZero)
                return Compare(BigInteger.Zero, bound, op);

            if (coefficient.Sign < 0)
                return ApplyScaledRelation(domain, -coefficient, Reverse(op), -bound);

            return op switch
            {
                RelationOp.Equal => TryDivideExactly(bound, coefficient, out var exact)
                    ? domain.SetExact(exact)
                    : false,
                RelationOp.NotEqual => TryDivideExactly(bound, coefficient, out var excluded)
                    ? domain.AddNotEqual(excluded)
                    : true,
                RelationOp.Less => domain.AddUpper(FloorDiv(bound - BigInteger.One, coefficient)),
                RelationOp.LessOrEqual => domain.AddUpper(FloorDiv(bound, coefficient)),
                RelationOp.Greater => domain.AddLower(FloorDiv(bound, coefficient) + BigInteger.One),
                RelationOp.GreaterOrEqual => domain.AddLower(CeilDiv(bound, coefficient)),
                _ => false,
            };
        }

        private bool AddEquality(SymbolEquality equality)
        {
            GetIntDomain(equality.Left);
            GetIntDomain(equality.Right);
            _equalities.Add(equality);
            return PropagateEqualities();
        }

        private bool AddAffineEquality(AffineTerm equality)
        {
            foreach (var symbol in equality.Coefficients.Keys)
                GetIntDomain(symbol);
            _affineEqualities.Add(equality);
            return PropagateEqualities();
        }

        /// <summary>
        /// Upper bound on propagation/witness fixup rounds. One round propagates one hop
        /// across the equality chain; with N equalities + N affines + N domains the longest
        /// chain that can require sequential propagation is bounded by their sum + 1.
        /// </summary>
        private int MaxPropagationRounds() =>
            _equalities.Count + _affineEqualities.Count + _ints.Count + 1;

        private bool PropagateEqualities()
        {
            for (var i = 0; i < MaxPropagationRounds(); i++)
            {
                foreach (var equality in _equalities)
                {
                    var left = GetIntDomain(equality.Left);
                    var right = GetIntDomain(equality.Right);
                    if (!left.ApplyShiftedFrom(right, equality.Offset))
                        return false;
                    if (!right.ApplyShiftedFrom(left, -equality.Offset))
                        return false;
                }

                foreach (var equality in _affineEqualities)
                {
                    if (!PropagateAffineEquality(equality))
                        return false;
                }
            }
            return true;
        }

        private bool PropagateAffineEquality(AffineTerm equality)
        {
            if (!HasIntegerSolution(equality))
                return false;

            var sum = equality.Constant;
            string? unknownSymbol = null;
            var unknownCoefficient = BigInteger.Zero;
            var unknowns = 0;
            foreach (var (symbol, coefficient) in equality.Coefficients)
            {
                var domain = GetIntDomain(symbol);
                if (domain.Exact.HasValue)
                {
                    sum += coefficient * domain.Exact.Value;
                    continue;
                }

                unknowns++;
                unknownSymbol = symbol;
                unknownCoefficient = coefficient;
            }

            if (unknowns == 0)
                return sum.IsZero;

            if (unknowns == 1)
            {
                if (!TryDivideExactly(-sum, unknownCoefficient, out var value))
                    return false;
                return GetIntDomain(unknownSymbol!).SetExact(value);
            }

            var (min, max) = BoundsFor(equality);
            if (min.HasValue && min.Value > BigInteger.Zero)
                return false;
            if (max.HasValue && max.Value < BigInteger.Zero)
                return false;
            return true;
        }

        private bool IsEqualityKnownFalse(SymbolEquality equality)
        {
            if (!PropagateEqualities()) return true;
            var left = GetIntDomain(equality.Left);
            var right = GetIntDomain(equality.Right);
            if (left.Exact.HasValue && right.Exact.HasValue)
                return left.Exact.Value != right.Exact.Value + equality.Offset;
            // Disjoint-range precision: `left == right + offset` is UNSAT when the bounds prove
            // the intervals cannot overlap. Previously we only returned true on Exact/Exact;
            // strengthening to the bounds case is a pure precision win (Unsupported -> UNSAT)
            // with no soundness risk — we still return false when bounds are missing or overlap.
            if (left.Lower.HasValue && right.Upper.HasValue
                && left.Lower.Value > right.Upper.Value + equality.Offset)
                return true;
            if (left.Upper.HasValue && right.Lower.HasValue
                && left.Upper.Value < right.Lower.Value + equality.Offset)
                return true;
            return false;
        }

        private bool? IsAffineKnownNotEqual(AffineTerm relation)
        {
            if (TryEvaluateExact(relation, out var value))
                return value != BigInteger.Zero;

            var (min, max) = BoundsFor(relation);
            if (min.HasValue && min.Value > BigInteger.Zero)
                return true;
            if (max.HasValue && max.Value < BigInteger.Zero)
                return true;
            return null;
        }

        private bool IsAffineKnownEqual(AffineTerm relation) =>
            TryEvaluateExact(relation, out var value) && value.IsZero;

        private ConstraintStatus ApplyAffineInequality(AffineTerm relation, RelationOp op)
        {
            var (min, max) = BoundsFor(relation);
            return op switch
            {
                RelationOp.Less when min.HasValue && min.Value >= BigInteger.Zero => ConstraintStatus.Contradiction,
                RelationOp.Less when max.HasValue && max.Value < BigInteger.Zero => ConstraintStatus.Supported,
                RelationOp.LessOrEqual when min.HasValue && min.Value > BigInteger.Zero => ConstraintStatus.Contradiction,
                RelationOp.LessOrEqual when max.HasValue && max.Value <= BigInteger.Zero => ConstraintStatus.Supported,
                RelationOp.Greater when max.HasValue && max.Value <= BigInteger.Zero => ConstraintStatus.Contradiction,
                RelationOp.Greater when min.HasValue && min.Value > BigInteger.Zero => ConstraintStatus.Supported,
                RelationOp.GreaterOrEqual when max.HasValue && max.Value < BigInteger.Zero => ConstraintStatus.Contradiction,
                RelationOp.GreaterOrEqual when min.HasValue && min.Value >= BigInteger.Zero => ConstraintStatus.Supported,
                _ => ConstraintStatus.Unsupported,
            };
        }

        private bool TryEvaluateExact(AffineTerm relation, out BigInteger value)
        {
            value = relation.Constant;
            foreach (var (symbol, coefficient) in relation.Coefficients)
            {
                var domain = GetIntDomain(symbol);
                if (!domain.Exact.HasValue)
                    return false;
                value += coefficient * domain.Exact.Value;
            }
            return true;
        }

        private (BigInteger? Min, BigInteger? Max) BoundsFor(AffineTerm relation)
        {
            BigInteger? min = relation.Constant;
            BigInteger? max = relation.Constant;
            foreach (var (symbol, coefficient) in relation.Coefficients)
            {
                var domain = GetIntDomain(symbol);
                if (coefficient.Sign >= 0)
                {
                    min = AddBound(min, domain.Lower, coefficient);
                    max = AddBound(max, domain.Upper, coefficient);
                }
                else
                {
                    min = AddBound(min, domain.Upper, coefficient);
                    max = AddBound(max, domain.Lower, coefficient);
                }
            }
            return (min, max);
        }

        private static BigInteger? AddBound(BigInteger? accumulator, BigInteger? value, BigInteger coefficient) =>
            accumulator.HasValue && value.HasValue
                ? accumulator.Value + coefficient * value.Value
                : null;

        private static bool HasIntegerSolution(AffineTerm equality)
        {
            var gcd = BigInteger.Zero;
            foreach (var coefficient in equality.Coefficients.Values)
                gcd = BigInteger.GreatestCommonDivisor(BigInteger.Abs(gcd), BigInteger.Abs(coefficient));
            return gcd.IsZero || equality.Constant % gcd == BigInteger.Zero;
        }

        private static ConstraintStatus ApplyBool(bool value, bool negated)
        {
            var truth = negated ? !value : value;
            return truth ? ConstraintStatus.Supported : ConstraintStatus.Contradiction;
        }

        /// <summary>
        /// Thin wrapper that parses <paramref name="expression"/> via the multi-symbol-aware
        /// <see cref="TryAffineTerm"/> and collapses the result to a single-symbol
        /// <see cref="LinearTerm"/> when possible. Returns false for any expression that the
        /// affine parser rejects (sort mismatch, unsupported op, too many symbols) OR that
        /// parses successfully but ends up with more than one symbol (out of LinearTerm's
        /// representation).
        ///
        /// Replaces a near-duplicate of <see cref="TryAffineTerm"/>. Equivalent behavior
        /// because the legacy TryLinearTerm's add/sub paths failed on any two-symbol sum
        /// (different symbols → TryAdd false), exactly matching this wrapper's collapse-or-fail.
        /// </summary>
        private static bool TryAsLinearTerm(Expression expression, out LinearTerm term)
        {
            if (!TryAffineTerm(expression, out var affine))
            {
                term = default;
                return false;
            }
            return TryCollapseToLinear(affine, out term);
        }

        private static bool TryCollapseToLinear(AffineTerm affine, out LinearTerm term)
        {
            if (affine.Coefficients.Count == 0)
            {
                term = LinearTerm.ConstantTerm(affine.Constant);
                return true;
            }
            if (affine.Coefficients.Count == 1)
            {
                var (symbol, coefficient) = affine.Coefficients.First();
                term = new LinearTerm(symbol, coefficient, affine.Constant);
                return true;
            }
            term = default;
            return false;
        }

        private static bool TryAffineTerm(Expression expression, out AffineTerm term)
        {
            if (Expr.ConcreteInt(expression) is { } concrete)
            {
                term = AffineTerm.ConstantTerm(concrete);
                return true;
            }

            if (expression is Symbol { Sort: Sort.Int } symbol)
            {
                term = AffineTerm.SymbolTerm(symbol.Name);
                return true;
            }

            if (expression is UnaryExpr { Sort: Sort.Int, Op: "neg" } unary &&
                TryAffineTerm(unary.Operand, out var operand))
            {
                term = operand.Negate();
                return true;
            }

            if (expression is BinaryExpr { Sort: Sort.Int } binary)
            {
                if (binary.Op == "+" &&
                    TryAffineTerm(binary.Left, out var left) &&
                    TryAffineTerm(binary.Right, out var right) &&
                    left.TryAdd(right, MaxAffineSymbols, out term))
                {
                    return true;
                }

                if (binary.Op == "-" &&
                    TryAffineTerm(binary.Left, out left) &&
                    TryAffineTerm(binary.Right, out right) &&
                    left.TryAdd(right.Negate(), MaxAffineSymbols, out term))
                {
                    return true;
                }

                if (binary.Op == "*" &&
                    TryAffineTerm(binary.Left, out left) &&
                    TryAffineTerm(binary.Right, out right) &&
                    left.TryMultiply(right, MaxAffineSymbols, out term))
                {
                    return true;
                }
            }

            term = default!;
            return false;
        }


        private static bool TrySymbolEquality(LinearTerm left, LinearTerm right, out SymbolEquality equality)
        {
            equality = default;
            if (left.Symbol is null || right.Symbol is null)
                return false;
            if (!left.Coefficient.TryInvertSign(out var leftSign) ||
                !right.Coefficient.TryInvertSign(out var rightSign) ||
                leftSign != rightSign)
            {
                return false;
            }

            var offset = rightSign > 0
                ? right.Constant - left.Constant
                : left.Constant - right.Constant;
            equality = new SymbolEquality(left.Symbol, right.Symbol, offset);
            return true;
        }

        private static string? Negate(string op) => op switch
        {
            "==" => "!=",
            "!=" => "==",
            "num==" => "num!=",
            "num!=" => "num==",
            "<" => ">=",
            "<=" => ">",
            ">" => "<=",
            ">=" => "<",
            _ => null,
        };

        private static bool TryRelationOp(string op, out RelationOp relation)
        {
            relation = op switch
            {
                "==" or "num==" => RelationOp.Equal,
                "!=" or "num!=" => RelationOp.NotEqual,
                "<" => RelationOp.Less,
                "<=" => RelationOp.LessOrEqual,
                ">" => RelationOp.Greater,
                ">=" => RelationOp.GreaterOrEqual,
                _ => default,
            };
            return op is "==" or "num==" or "!=" or "num!=" or "<" or "<=" or ">" or ">=";
        }

        private static RelationOp Reverse(RelationOp op) => op switch
        {
            RelationOp.Less => RelationOp.Greater,
            RelationOp.LessOrEqual => RelationOp.GreaterOrEqual,
            RelationOp.Greater => RelationOp.Less,
            RelationOp.GreaterOrEqual => RelationOp.LessOrEqual,
            _ => op,
        };

        private static bool Compare(BigInteger left, BigInteger right, RelationOp op) =>
            op switch
            {
                RelationOp.Equal => left == right,
                RelationOp.NotEqual => left != right,
                RelationOp.Less => left < right,
                RelationOp.LessOrEqual => left <= right,
                RelationOp.Greater => left > right,
                RelationOp.GreaterOrEqual => left >= right,
                _ => false,
            };

        private static bool TryDivideExactly(BigInteger dividend, BigInteger divisor, out BigInteger quotient)
        {
            quotient = dividend / divisor;
            return dividend % divisor == BigInteger.Zero;
        }

        private static BigInteger FloorDiv(BigInteger dividend, BigInteger divisor)
        {
            var quotient = dividend / divisor;
            var remainder = dividend % divisor;
            if (remainder != BigInteger.Zero && dividend.Sign != divisor.Sign)
                quotient -= BigInteger.One;
            return quotient;
        }

        private static BigInteger CeilDiv(BigInteger dividend, BigInteger divisor) =>
            -FloorDiv(-dividend, divisor);
    }

    internal sealed class IntDomain
    {
        private readonly HashSet<BigInteger> _notEquals = new();
        private BigInteger? _lower;
        private BigInteger? _upper;
        private BigInteger? _exact;

        public BigInteger? Lower => _lower;
        public BigInteger? Upper => _upper;
        public BigInteger? Exact => _exact;

        public IntDomain Clone()
        {
            var clone = new IntDomain
            {
                _lower = _lower,
                _upper = _upper,
                _exact = _exact,
            };
            foreach (var value in _notEquals)
                clone._notEquals.Add(value);
            return clone;
        }

        public bool SetExact(BigInteger value)
        {
            if (_lower.HasValue && value < _lower.Value)
                return false;
            if (_upper.HasValue && value > _upper.Value)
                return false;
            if (_notEquals.Contains(value))
                return false;

            _exact = value;
            _lower = value;
            _upper = value;
            return true;
        }

        public bool AddLower(BigInteger value)
        {
            if (!_lower.HasValue || value > _lower.Value)
                _lower = value;
            return IsConsistent();
        }

        public bool AddUpper(BigInteger value)
        {
            if (!_upper.HasValue || value < _upper.Value)
                _upper = value;
            return IsConsistent();
        }

        public bool AddNotEqual(BigInteger value)
        {
            _notEquals.Add(value);
            return IsConsistent();
        }

        public bool ApplyShiftedFrom(IntDomain source, BigInteger offset)
        {
            if (source._exact.HasValue && !SetExact(source._exact.Value + offset))
                return false;
            if (source._lower.HasValue && !AddLower(source._lower.Value + offset))
                return false;
            if (source._upper.HasValue && !AddUpper(source._upper.Value + offset))
                return false;
            foreach (var value in source._notEquals)
            {
                if (!AddNotEqual(value + offset))
                    return false;
            }
            return IsConsistent();
        }

        public bool Contains(BigInteger value)
        {
            if (_lower.HasValue && value < _lower.Value)
                return false;
            if (_upper.HasValue && value > _upper.Value)
                return false;
            if (_exact.HasValue && value != _exact.Value)
                return false;
            if (_notEquals.Contains(value))
                return false;
            return true;
        }

        public bool TryChoose(out BigInteger value)
        {
            if (!IsConsistent())
            {
                value = BigInteger.Zero;
                return false;
            }

            if (_exact.HasValue)
            {
                value = _exact.Value;
                return !_notEquals.Contains(value);
            }

            var start = _lower ?? (_upper.HasValue && _upper.Value < BigInteger.Zero
                ? _upper.Value
                : BigInteger.Zero);
            for (var offset = BigInteger.Zero; offset <= _notEquals.Count; offset += BigInteger.One)
            {
                if (TryCandidate(start + offset, out value) ||
                    (offset > BigInteger.Zero && TryCandidate(start - offset, out value)))
                {
                    return true;
                }
            }

            value = BigInteger.Zero;
            return false;
        }

        private bool TryCandidate(BigInteger candidate, out BigInteger value)
        {
            value = candidate;
            if (_lower.HasValue && candidate < _lower.Value)
                return false;
            if (_upper.HasValue && candidate > _upper.Value)
                return false;
            if (_notEquals.Contains(candidate))
                return false;
            return true;
        }

        private bool IsConsistent()
        {
            if (_lower.HasValue && _upper.HasValue && _lower.Value > _upper.Value)
                return false;
            if (_exact.HasValue && _notEquals.Contains(_exact.Value))
                return false;
            if (_lower.HasValue && _upper.HasValue && _lower.Value == _upper.Value &&
                _notEquals.Contains(_lower.Value))
                return false;
            return true;
        }
    }

    // LinearTerm represents a single-symbol affine form `Coefficient * Symbol + Constant`
    // (or a pure constant when Symbol is null). It is the simpler shape consumed by
    // TryConcretize and ApplyLinearPath; the more general AffineTerm (multi-symbol) is the
    // parser-side primitive. TryAsLinearTerm wraps TryAffineTerm + collapses.
    private readonly record struct LinearTerm(string? Symbol, BigInteger Coefficient, BigInteger Constant)
    {
        public static LinearTerm ConstantTerm(BigInteger value) => new(null, BigInteger.Zero, value);

        public LinearTerm Negate() => new(Symbol, -Coefficient, -Constant);

        public bool TrySubtract(LinearTerm other, out LinearTerm result) =>
            TryAdd(other.Negate(), out result);

        public bool TryAdd(LinearTerm other, out LinearTerm result)
        {
            if (Symbol is null)
            {
                result = new LinearTerm(other.Symbol, other.Coefficient, Constant + other.Constant);
                return true;
            }

            if (other.Symbol is null)
            {
                result = new LinearTerm(Symbol, Coefficient, Constant + other.Constant);
                return true;
            }

            if (StringComparer.Ordinal.Equals(Symbol, other.Symbol))
            {
                result = new LinearTerm(Symbol, Coefficient + other.Coefficient, Constant + other.Constant);
                return true;
            }

            result = default;
            return false;
        }
    }

    private readonly record struct SymbolEquality(string Left, string Right, BigInteger Offset);

    private sealed class AffineTerm
    {
        private readonly Dictionary<string, BigInteger> _coefficients;

        private AffineTerm(Dictionary<string, BigInteger> coefficients, BigInteger constant)
        {
            _coefficients = coefficients;
            Constant = constant;
        }

        public IReadOnlyDictionary<string, BigInteger> Coefficients => _coefficients;
        public BigInteger Constant { get; }

        public static AffineTerm ConstantTerm(BigInteger value) => new(new Dictionary<string, BigInteger>(StringComparer.Ordinal), value);

        public static AffineTerm SymbolTerm(string symbol) => new(
            new Dictionary<string, BigInteger>(StringComparer.Ordinal) { [symbol] = BigInteger.One },
            BigInteger.Zero);

        public AffineTerm Negate() => Scale(-BigInteger.One);

        public AffineTerm Scale(BigInteger factor)
        {
            var coefficients = new Dictionary<string, BigInteger>(StringComparer.Ordinal);
            foreach (var (symbol, coefficient) in _coefficients)
            {
                var scaled = coefficient * factor;
                if (!scaled.IsZero)
                    coefficients[symbol] = scaled;
            }
            return new AffineTerm(coefficients, Constant * factor);
        }

        public bool TrySubtract(AffineTerm other, out AffineTerm result) =>
            TryAdd(other.Negate(), int.MaxValue, out result);

        public bool TryMultiply(AffineTerm other, int maxSymbols, out AffineTerm result)
        {
            if (_coefficients.Count == 0)
                return other.Scale(Constant).LimitSymbols(maxSymbols, out result);
            if (other._coefficients.Count == 0)
                return Scale(other.Constant).LimitSymbols(maxSymbols, out result);

            result = default!;
            return false;
        }

        public bool TryAdd(AffineTerm other, int maxSymbols, out AffineTerm result)
        {
            var coefficients = new Dictionary<string, BigInteger>(_coefficients, StringComparer.Ordinal);
            foreach (var (symbol, coefficient) in other._coefficients)
            {
                coefficients.TryGetValue(symbol, out var current);
                var next = current + coefficient;
                if (next.IsZero)
                    coefficients.Remove(symbol);
                else
                    coefficients[symbol] = next;
            }

            result = new AffineTerm(coefficients, Constant + other.Constant);
            return result.LimitSymbols(maxSymbols, out result);
        }

        public bool TryAsLinearTerm(out LinearTerm term)
        {
            if (_coefficients.Count == 0)
            {
                term = LinearTerm.ConstantTerm(Constant);
                return true;
            }

            if (_coefficients.Count == 1)
            {
                foreach (var (symbol, coefficient) in _coefficients)
                {
                    term = new LinearTerm(symbol, coefficient, Constant);
                    return true;
                }
            }

            term = default;
            return false;
        }

        private bool LimitSymbols(int maxSymbols, out AffineTerm result)
        {
            result = this;
            return _coefficients.Count <= maxSymbols;
        }
    }

    private enum ConstraintStatus
    {
        Supported,
        Unsupported,
        Contradiction,
    }

    private enum RelationOp
    {
        Equal,
        NotEqual,
        Less,
        LessOrEqual,
        Greater,
        GreaterOrEqual,
    }
}

internal static class BigIntegerExtensions
{
    public static bool TryInvertSign(this BigInteger value, out int sign)
    {
        if (value == BigInteger.One)
        {
            sign = 1;
            return true;
        }
        if (value == -BigInteger.One)
        {
            sign = -1;
            return true;
        }
        sign = 0;
        return false;
    }
}

internal readonly record struct PortableSmtResult(
    SmtOutcome Outcome,
    BigInteger? Value,
    IReadOnlyDictionary<string, object>? Witness);
