using System.Collections.Generic;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    /// <summary>
    /// StackItemType byte codes (mirrors Neo.VM.Types.StackItemType).
    /// </summary>
    public static class StackItemTypeCodes
    {
        public const byte Any = 0x00;
        public const byte Pointer = 0x10;
        public const byte Boolean = 0x20;
        public const byte Integer = 0x21;
        public const byte ByteString = 0x28;
        public const byte Buffer = 0x30;
        public const byte Array = 0x40;
        public const byte Struct = 0x41;
        public const byte Map = 0x48;
        public const byte InteropInterface = 0x60;
    }

    private IEnumerable<ExecutionState> HandleIsType(ExecutionState state, Instruction inst)
    {
        var v = state.Pop();
        byte typeByte = inst.Operand.Span[0];
        // Audit fix: per NeoVM JumpTable.Types, ISTYPE on `Any` (0x00) or any undefined StackItemType
        // byte throws InvalidOperationException — a non-catchable fault. We previously returned false,
        // which silently hid malformed bytecode the VM would reject. Fault to match.
        if (!IsDefinedStackItemType(typeByte) || typeByte == StackItemTypeCodes.Any)
            throw new VmFaultException($"ISTYPE with invalid type byte 0x{typeByte:X2}");
        var result = v.Sort == Sort.Unknown
            ? SymbolicValue.Of(new UnaryExpr(Sort.Bool, $"istype:{typeByte:X2}", v.Expression), v.Taints)
            : SymbolicValue.Bool(TypeMatches(v, typeByte));
        state.Push(result);
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static bool IsDefinedStackItemType(byte b) => b is
        StackItemTypeCodes.Any or
        StackItemTypeCodes.Pointer or
        StackItemTypeCodes.Boolean or
        StackItemTypeCodes.Integer or
        StackItemTypeCodes.ByteString or
        StackItemTypeCodes.Buffer or
        StackItemTypeCodes.Array or
        StackItemTypeCodes.Struct or
        StackItemTypeCodes.Map or
        StackItemTypeCodes.InteropInterface;

    private static bool TypeMatches(SymbolicValue v, byte typeByte) => (typeByte, v.Sort) switch
    {
        (StackItemTypeCodes.Boolean, Sort.Bool) => true,
        (StackItemTypeCodes.Integer, Sort.Int) => true,
        (StackItemTypeCodes.ByteString, Sort.Bytes) => true,
        (StackItemTypeCodes.Buffer, Sort.Buffer) => true,
        (StackItemTypeCodes.Array, Sort.Array) => true,
        (StackItemTypeCodes.Struct, Sort.Struct) => true,
        (StackItemTypeCodes.Map, Sort.Map) => true,
        (StackItemTypeCodes.Pointer, Sort.Pointer) => true,
        (StackItemTypeCodes.InteropInterface, Sort.InteropInterface) => true,
        _ => false,
    };

    private IEnumerable<ExecutionState> HandleConvert(ExecutionState state, Instruction inst)
    {
        var v = state.Pop();
        byte typeByte = inst.Operand.Span[0];
        // Audit fix: validate the operand byte. NeoVM JumpTable.Types.Convert throws on undefined.
        if (!IsDefinedStackItemType(typeByte) || typeByte == StackItemTypeCodes.Any)
            throw new VmFaultException($"CONVERT to invalid type byte 0x{typeByte:X2}");

        // Audit fix (iter-2 wakeup-4 differential): NeoVM's Null.ConvertTo returns the Null
        // itself regardless of target type (it's effectively a no-op for any defined target).
        // Our prior implementation faulted on (Null, ByteString) etc. — the differential
        // target found this immediately on the trivial PUSHNULL CONVERT 0x28 RET.
        if (v.IsConcreteNull)
        {
            state.Push(v);
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        if (v.Sort == Sort.Unknown && PathConditionsProveIsType(state, v.Expression, typeByte))
        {
            state.Push(RefineUnknownValueForType(state, v, typeByte, inst.Offset));
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        // Same-sort convert is identity (other than wrapping). NeoVM allows this.
        if (TypeMatches(v, typeByte))
        {
            state.Push(v);
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        if (typeByte == StackItemTypeCodes.Buffer
            && v.Sort == Sort.Bool
            && v.AsConcreteBool() is null)
        {
            var condition = Expr.ToBool(v.Expression);
            var trueState = state.Clone();
            trueState.PathConditions = trueState.PathConditions.Add(condition);
            trueState.Push(SymbolicValue
                .HeapRef(Sort.Buffer, trueState.Heap.NewBuffer(new byte[] { 1 }).Id)
                .WithTaints(v.Taints));
            trueState.Pc = inst.EndOffset;

            state.PathConditions = state.PathConditions.Add(Expr.Not(condition));
            state.Push(SymbolicValue
                .HeapRef(Sort.Buffer, state.Heap.NewBuffer(System.Array.Empty<byte>()).Id)
                .WithTaints(v.Taints));
            state.Pc = inst.EndOffset;
            return new[] { trueState, state };
        }

        SymbolicValue converted = (typeByte, v.Sort) switch
        {
            // Boolean target: any value can be converted via NeoVM truthiness.
            (StackItemTypeCodes.Boolean, _) => SymbolicValue.Of(Expr.ToBool(v.Expression), v.Taints),

            // Integer target.
            (StackItemTypeCodes.Integer, Sort.Bool) =>
                SymbolicValue.Of(
                    v.AsConcreteBool() is { } boolValue
                        ? Expr.Int(boolValue ? 1 : 0)
                        : Expr.Ite(v.Expression, Expr.Int(1), Expr.Int(0)),
                    v.Taints),
            (StackItemTypeCodes.Integer, Sort.Bytes) =>
                v.AsConcreteBytes() is byte[] bs
                    ? (bs.Length > 32
                        ? throw new VmFaultException($"CONVERT Integer: source bytes {bs.Length} > 32")
                        : SymbolicValue.Int(Expr.BytesToInteger(bs)))
                    : SymbolicValue.Of(new UnaryExpr(Sort.Int, "b2i", v.Expression), v.Taints),
            (StackItemTypeCodes.Integer, Sort.Buffer) =>
                v.Expression is HeapRef hbi && state.Heap.Objects.TryGetValue(hbi.ObjectId, out var bobj1) && bobj1 is BufferObject buf1
                    ? ConvertBufferToInt(state, inst, buf1, v.Expression, v.Taints)
                    : SymbolicValue.Of(new UnaryExpr(Sort.Int, "buf2i", v.Expression), v.Taints),

            // ByteString target.
            (StackItemTypeCodes.ByteString, Sort.Int) =>
                v.AsConcreteInt() is { } bi
                    ? SymbolicValue.Bytes(Expr.IntegerToBytes(bi))
                    // Audit C# #4 fix: for symbolic ints we previously returned the Int unchanged,
                    // which broke downstream ISTYPE Bytes checks. Wrap so the sort propagates.
                    : SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "i2b", v.Expression), v.Taints),
            (StackItemTypeCodes.ByteString, Sort.Bool) =>
                v.AsConcreteBool() is { } boolValue
                    ? (boolValue ? SymbolicValue.Bytes(new byte[] { 1 }) : SymbolicValue.Bytes(System.Array.Empty<byte>()))
                    : SymbolicValue.Of(
                        Expr.Ite(v.Expression, Expr.Bytes(new byte[] { 1 }), Expr.Bytes(System.Array.Empty<byte>())),
                        v.Taints),
            (StackItemTypeCodes.ByteString, Sort.Buffer) =>
                v.Expression is HeapRef hbs && state.Heap.Objects.TryGetValue(hbs.ObjectId, out var bobj2) && bobj2 is BufferObject buf2
                    ? ConvertBufferToBytes(buf2, v.Expression, v.Taints)
                    : SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "buf2bytes", v.Expression), v.Taints),

            // Buffer target — always allocate a fresh buffer.
            (StackItemTypeCodes.Buffer, Sort.Bytes) =>
                ConvertBytesToBuffer(state, v),
            (StackItemTypeCodes.Buffer, Sort.Int) =>
                v.AsConcreteInt() is { } bi2
                    ? SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(Expr.IntegerToBytes(bi2)).Id)
                        .WithTaints(v.Taints)
                    : ConvertSymbolicIntegerToBuffer(state, v),
            // Audit fix (iter-2 wakeup-5 differential): NeoVM's PrimitiveType.ConvertTo(Buffer)
            // is `new Buffer(GetSpan())` — works for ANY primitive (Boolean, Integer, ByteString).
            // Boolean's GetSpan returns [] for false and [1] for true.
            (StackItemTypeCodes.Buffer, Sort.Bool) =>
                v.AsConcreteBool() == true
                    ? SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(new byte[] { 1 }).Id)
                        .WithTaints(v.Taints)
                    : SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(System.Array.Empty<byte>()).Id)
                        .WithTaints(v.Taints),

            // Struct ↔ Array — sort change with content preserved per NeoVM rules. We allocate
            // a fresh heap object of the target sort containing the same items list.
            (StackItemTypeCodes.Array, Sort.Struct) =>
                v.Expression is HeapRef hsa && state.Heap.Objects.TryGetValue(hsa.ObjectId, out var sa) && sa is StructObject so1
                    ? SymbolicValue.HeapRef(Sort.Array, state.Heap.NewArray(so1.Fields).Id)
                    : v,
            (StackItemTypeCodes.Struct, Sort.Array) =>
                v.Expression is HeapRef has && state.Heap.Objects.TryGetValue(has.ObjectId, out var aa) && aa is ArrayObject ao1
                    ? SymbolicValue.HeapRef(Sort.Struct, state.Heap.NewStruct(ao1.Items).Id)
                    : v,

            // Audit fix: every other pair is invalid per NeoVM. Fault rather than silently
            // forwarding the input — the prior `_ => v` fallthrough hid type-system bugs from
            // every detector and oracle downstream.
            _ => throw new VmFaultException(
                $"CONVERT from {v.Sort} to type 0x{typeByte:X2} not supported"),
        };
        EnforceConvertIntegerSourceLength(state, inst, typeByte, v);
        state.Push(converted);
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static bool PathConditionsProveIsType(ExecutionState state, Expression value, byte typeByte)
    {
        var predicate = new UnaryExpr(Sort.Bool, $"istype:{typeByte:X2}", value);
        return state.PathConditions.Contains(predicate);
    }

    private static SymbolicValue RefineUnknownValueForType(
        ExecutionState state,
        SymbolicValue value,
        byte typeByte,
        int offset)
    {
        string name = value.Expression is Symbol symbol
            ? $"{symbol.Name}_as_{StackItemTypeName(typeByte)}"
            : $"convert_{StackItemTypeName(typeByte)}_{offset}";

        return typeByte switch
        {
            StackItemTypeCodes.Boolean =>
                SymbolicValue.Symbol(Sort.Bool, name).WithTaints(value.Taints),
            StackItemTypeCodes.Integer =>
                RefinedInteger(state, name, value),
            StackItemTypeCodes.ByteString =>
                RefinedByteString(state, name, value),
            StackItemTypeCodes.Buffer =>
                CreateBufferMethodEntrySymbol(state, name, name).WithTaints(value.Taints),
            StackItemTypeCodes.Array =>
                CreateArrayMethodEntrySymbol(state, name, name).WithTaints(value.Taints),
            StackItemTypeCodes.Struct =>
                CreateStructMethodEntrySymbol(state, name, name).WithTaints(value.Taints),
            StackItemTypeCodes.Map =>
                CreateMapMethodEntrySymbol(state, name, name).WithTaints(value.Taints),
            StackItemTypeCodes.Pointer =>
                SymbolicValue.Symbol(Sort.Pointer, name).WithTaints(value.Taints),
            StackItemTypeCodes.InteropInterface =>
                SymbolicValue.Symbol(Sort.InteropInterface, name).WithTaints(value.Taints),
            _ => value,
        };
    }

    private static SymbolicValue RefinedInteger(ExecutionState state, string name, SymbolicValue value)
    {
        var refined = SymbolicValue.Symbol(Sort.Int, name).WithTaints(value.Taints);
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(refined.Expression, Expr.Int(Expr.NeoVmIntegerMin)))
            .Add(Expr.Le(refined.Expression, Expr.Int(Expr.NeoVmIntegerMax)));
        return refined;
    }

    private static SymbolicValue RefinedByteString(ExecutionState state, string name, SymbolicValue value)
    {
        var refined = SymbolicValue.Symbol(Sort.Bytes, name).WithTaints(value.Taints);
        var size = new UnaryExpr(Sort.Int, "size", refined.Expression);
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(size, Expr.Int(0)))
            .Add(Expr.Le(size, Expr.Int(state.Heap.MaxItemSize)));
        return refined;
    }

    private static string StackItemTypeName(byte typeByte) => typeByte switch
    {
        StackItemTypeCodes.Boolean => "bool",
        StackItemTypeCodes.Integer => "int",
        StackItemTypeCodes.ByteString => "bytes",
        StackItemTypeCodes.Buffer => "buffer",
        StackItemTypeCodes.Array => "array",
        StackItemTypeCodes.Struct => "struct",
        StackItemTypeCodes.Map => "map",
        StackItemTypeCodes.Pointer => "pointer",
        StackItemTypeCodes.InteropInterface => "interop",
        _ => $"type_{typeByte:X2}",
    };

    private static void EnforceConvertIntegerSourceLength(
        ExecutionState state,
        Instruction inst,
        byte targetType,
        SymbolicValue source)
    {
        if (targetType != StackItemTypeCodes.Integer)
            return;
        if (source.Sort != Sort.Bytes)
            return;
        if (source.AsConcreteBytes() is not null)
            return;

        state.Telemetry.FaultConditions.Add(new FaultConditionOp(
            inst.Offset,
            "CONVERT Integer",
            Expr.Gt(new UnaryExpr(Sort.Int, "size", source.Expression), Expr.Int(MaxNeoVmIntegerBytes)),
            $"source bytes may exceed {MaxNeoVmIntegerBytes} bytes",
            "VM opcode precondition holds under requires"));
    }

    private static SymbolicValue ConvertBytesToBuffer(ExecutionState state, SymbolicValue value)
    {
        if (value.AsConcreteBytes() is byte[] concrete)
            return SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(concrete).Id)
                .WithTaints(value.Taints);

        if (!TryKnownByteLength(state, value.Expression, out int length))
            return ConvertOpenBytesToBuffer(state, value);

        var cells = new List<Expression>(length);
        for (int i = 0; i < length; i++)
        {
            var cell = new BinaryExpr(Sort.Int, "pick", value.Expression, Expr.Int(i));
            cells.Add(cell);
            state.PathConditions = state.PathConditions
                .Add(Expr.Ge(cell, Expr.Int(byte.MinValue)))
                .Add(Expr.Le(cell, Expr.Int(byte.MaxValue)));
        }

        var buffer = state.Heap.Allocate(id => new BufferObject(id, cells));
        return SymbolicValue.HeapRef(Sort.Buffer, buffer.Id).WithTaints(value.Taints);
    }

    private static SymbolicValue ConvertOpenBytesToBuffer(ExecutionState state, SymbolicValue value)
    {
        var symbolicLength = new UnaryExpr(Sort.Int, "size", value.Expression);
        int minLength = ProvenByteLengthLowerBound(state, value.Expression);
        int prefixLength = System.Math.Min(minLength, MethodEntryCollectionSeedSize);
        var cells = new List<Expression>(prefixLength);
        for (int i = 0; i < prefixLength; i++)
        {
            var cell = new BinaryExpr(Sort.Int, "pick", value.Expression, Expr.Int(i));
            cells.Add(cell);
            state.PathConditions = state.PathConditions
                .Add(Expr.Ge(cell, Expr.Int(byte.MinValue)))
                .Add(Expr.Le(cell, Expr.Int(byte.MaxValue)));
        }

        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(symbolicLength, Expr.Int(minLength)))
            .Add(Expr.Le(symbolicLength, Expr.Int(state.Heap.MaxItemSize)));

        var buffer = state.Heap.Allocate(id => new BufferObject(
            id,
            cells,
            isSymbolicOpen: true,
            minLength: minLength,
            symbolicLength: symbolicLength,
            sourceBytes: value.Expression));
        return SymbolicValue.HeapRef(Sort.Buffer, buffer.Id).WithTaints(value.Taints);
    }

    private static SymbolicValue ConvertSymbolicIntegerToBuffer(ExecutionState state, SymbolicValue value)
    {
        var sourceBytes = new UnaryExpr(Sort.Bytes, "i2b", value.Expression);
        var symbolicLength = new UnaryExpr(Sort.Int, "size", sourceBytes);
        state.PathConditions = state.PathConditions
            .Add(Expr.Ge(symbolicLength, Expr.Int(0)))
            .Add(Expr.Le(symbolicLength, Expr.Int(MaxNeoVmIntegerBytes)));

        var buffer = state.Heap.Allocate(id => new BufferObject(
            id,
            System.Array.Empty<Expression>(),
            isSymbolicOpen: true,
            minLength: 0,
            symbolicLength: symbolicLength,
            sourceBytes: sourceBytes));
        return SymbolicValue.HeapRef(Sort.Buffer, buffer.Id).WithTaints(value.Taints);
    }

    private static bool TryKnownByteLength(ExecutionState state, Expression bytes, out int length)
    {
        if (bytes is BytesConst concrete)
        {
            length = concrete.Value.Length;
            return true;
        }

        foreach (var condition in state.PathConditions)
        {
            if (TryByteLengthEquality(condition, bytes, out length)
                && length >= 0
                && length <= state.Heap.MaxItemSize)
            {
                return true;
            }
        }

        length = 0;
        return false;
    }

    private static int ProvenByteLengthLowerBound(ExecutionState state, Expression bytes)
    {
        int lowerBound = 0;
        foreach (var condition in state.PathConditions)
        {
            if (TryByteLengthLowerBound(condition, bytes, out int candidate))
                lowerBound = System.Math.Max(lowerBound, candidate);
        }

        return System.Math.Min(lowerBound, state.Heap.MaxItemSize);
    }

    private static bool TryByteLengthEquality(Expression condition, Expression bytes, out int length)
    {
        if (condition is BinaryExpr { Op: "==", Left: var left, Right: var right })
        {
            if (TrySizeOperand(left, bytes) && TryNonNegativeInt(right, out length))
                return true;
            if (TrySizeOperand(right, bytes) && TryNonNegativeInt(left, out length))
                return true;
        }

        length = 0;
        return false;
    }

    private static bool TryByteLengthLowerBound(Expression condition, Expression bytes, out int lowerBound)
    {
        if (condition is BinaryExpr { Op: "and", Left: var left, Right: var right })
        {
            bool leftFound = TryByteLengthLowerBound(left, bytes, out int leftBound);
            bool rightFound = TryByteLengthLowerBound(right, bytes, out int rightBound);
            lowerBound = System.Math.Max(leftBound, rightBound);
            return leftFound || rightFound;
        }

        if (TryByteLengthEquality(condition, bytes, out lowerBound))
            return true;

        if (condition is BinaryExpr { Left: var comparisonLeft, Right: var comparisonRight, Op: var op })
        {
            if (TrySizeOperand(comparisonLeft, bytes) && TryNonNegativeInt(comparisonRight, out int value))
            {
                lowerBound = op switch
                {
                    ">=" => value,
                    ">" when value < int.MaxValue => value + 1,
                    _ => 0,
                };
                return lowerBound > 0 || op == ">=" && value == 0;
            }

            if (TrySizeOperand(comparisonRight, bytes) && TryNonNegativeInt(comparisonLeft, out value))
            {
                lowerBound = op switch
                {
                    "<=" => value,
                    "<" when value < int.MaxValue => value + 1,
                    _ => 0,
                };
                return lowerBound > 0 || op == "<=" && value == 0;
            }
        }

        lowerBound = 0;
        return false;
    }

    private static bool TrySizeOperand(Expression expression, Expression bytes) =>
        expression is UnaryExpr { Sort: Sort.Int, Op: "size", Operand: var operand }
        && operand.Equals(bytes);

    private static bool TryNonNegativeInt(Expression expression, out int value)
    {
        if (expression is IntConst { Value: var integer }
            && integer >= 0
            && integer <= int.MaxValue)
        {
            value = (int)integer;
            return true;
        }

        value = 0;
        return false;
    }

    private static SymbolicValue ConvertBufferToInt(
        ExecutionState state,
        Instruction inst,
        BufferObject buf,
        Expression bufferExpression,
        System.Collections.Immutable.ImmutableHashSet<string> taints)
    {
        if (buf.IsSymbolicOpen)
        {
            var size = OpenBufferSize(state, buf);
            state.Telemetry.FaultConditions.Add(new FaultConditionOp(
                inst.Offset,
                "CONVERT Integer",
                Expr.Gt(size.Expression, Expr.Int(MaxNeoVmIntegerBytes)),
                $"source Buffer may exceed {MaxNeoVmIntegerBytes} bytes",
                "Buffer-to-Integer conversion source length is within NeoVM integer limit"));
            return SymbolicValue.Of(new UnaryExpr(Sort.Int, "buf2i", bufferExpression), taints);
        }

        if (buf.Length > 32) throw new VmFaultException($"CONVERT Buffer→Integer: length {buf.Length} > 32");
        // If all cells concrete, fold to IntConst; otherwise emit a symbolic conversion node.
        var bytes = new byte[buf.Length];
        for (int i = 0; i < buf.Length; i++)
        {
            if (buf.Cells[i] is not IntConst ic)
                return SymbolicValue.Of(new UnaryExpr(Sort.Int, "buf2i", bufferExpression), taints);
            int v = (int)ic.Value;
            if (v < 0 || v > 255) throw new VmFaultException($"buffer cell out of byte range: {v}");
            bytes[i] = (byte)v;
        }
        return SymbolicValue.Of(Expr.Int(Expr.BytesToInteger(bytes)), taints);
    }

    private static SymbolicValue ConvertBufferToBytes(
        BufferObject buf,
        Expression bufferExpression,
        System.Collections.Immutable.ImmutableHashSet<string> taints)
    {
        if (buf.IsSymbolicOpen)
            return SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "buf2bytes", bufferExpression), taints);

        var bytes = new byte[buf.Length];
        for (int i = 0; i < buf.Length; i++)
        {
            if (buf.Cells[i] is not IntConst ic)
                return SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "buf2bytes", bufferExpression), taints);
            int v = (int)ic.Value;
            if (v < 0 || v > 255) throw new VmFaultException($"buffer cell out of byte range: {v}");
            bytes[i] = (byte)v;
        }
        return SymbolicValue.Of(Expr.Bytes(bytes), taints);
    }
}
