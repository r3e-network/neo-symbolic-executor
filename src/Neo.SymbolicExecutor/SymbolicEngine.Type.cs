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
        var result = TypeMatches(v, typeByte);
        state.Push(SymbolicValue.Bool(result));
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

        // Same-sort convert is identity (other than wrapping). NeoVM allows this.
        if (TypeMatches(v, typeByte))
        {
            state.Push(v);
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        SymbolicValue converted = (typeByte, v.Sort) switch
        {
            // Boolean target: any value can be converted via NeoVM truthiness.
            (StackItemTypeCodes.Boolean, _) => SymbolicValue.Of(Expr.ToBool(v.Expression), v.Taints),

            // Integer target.
            (StackItemTypeCodes.Integer, Sort.Bool) =>
                SymbolicValue.Of(v.AsConcreteBool() == true ? Expr.Int(1) : Expr.Int(0), v.Taints),
            (StackItemTypeCodes.Integer, Sort.Bytes) =>
                v.AsConcreteBytes() is byte[] bs
                    ? (bs.Length > 32
                        ? throw new VmFaultException($"CONVERT Integer: source bytes {bs.Length} > 32")
                        : SymbolicValue.Int(Expr.BytesToInteger(bs)))
                    : SymbolicValue.Of(new UnaryExpr(Sort.Int, "b2i", v.Expression), v.Taints),
            (StackItemTypeCodes.Integer, Sort.Buffer) =>
                v.Expression is HeapRef hbi && state.Heap.Objects.TryGetValue(hbi.ObjectId, out var bobj1) && bobj1 is BufferObject buf1
                    ? ConvertBufferToInt(buf1, v.Taints)
                    : SymbolicValue.Of(new UnaryExpr(Sort.Int, "buf2i", v.Expression), v.Taints),

            // ByteString target.
            (StackItemTypeCodes.ByteString, Sort.Int) =>
                v.AsConcreteInt() is { } bi
                    ? SymbolicValue.Bytes(Expr.IntegerToBytes(bi))
                    // Audit C# #4 fix: for symbolic ints we previously returned the Int unchanged,
                    // which broke downstream ISTYPE Bytes checks. Wrap so the sort propagates.
                    : SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "i2b", v.Expression), v.Taints),
            (StackItemTypeCodes.ByteString, Sort.Bool) =>
                v.AsConcreteBool() == true ? SymbolicValue.Bytes(new byte[] { 1 }) : SymbolicValue.Bytes(System.Array.Empty<byte>()),
            (StackItemTypeCodes.ByteString, Sort.Buffer) =>
                v.Expression is HeapRef hbs && state.Heap.Objects.TryGetValue(hbs.ObjectId, out var bobj2) && bobj2 is BufferObject buf2
                    ? ConvertBufferToBytes(buf2, v.Taints)
                    : SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "buf2bytes", v.Expression), v.Taints),

            // Buffer target — always allocate a fresh buffer.
            (StackItemTypeCodes.Buffer, Sort.Bytes) =>
                v.AsConcreteBytes() is byte[] bb
                    ? SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(bb).Id)
                    : SymbolicValue.Of(new UnaryExpr(Sort.Buffer, "bytes2buf", v.Expression), v.Taints),
            (StackItemTypeCodes.Buffer, Sort.Int) =>
                v.AsConcreteInt() is { } bi2
                    ? SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(Expr.IntegerToBytes(bi2)).Id)
                    : SymbolicValue.Of(new UnaryExpr(Sort.Buffer, "i2buf", v.Expression), v.Taints),

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
        state.Push(converted);
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static SymbolicValue ConvertBufferToInt(BufferObject buf, System.Collections.Immutable.ImmutableHashSet<string> taints)
    {
        if (buf.Length > 32) throw new VmFaultException($"CONVERT Buffer→Integer: length {buf.Length} > 32");
        // If all cells concrete, fold to IntConst; otherwise emit a symbolic conversion node.
        var bytes = new byte[buf.Length];
        for (int i = 0; i < buf.Length; i++)
        {
            if (buf.Cells[i] is not IntConst ic)
                return SymbolicValue.Of(new UnaryExpr(Sort.Int, "buf2i", Expr.Bytes(bytes)), taints);
            int v = (int)ic.Value;
            if (v < 0 || v > 255) throw new VmFaultException($"buffer cell out of byte range: {v}");
            bytes[i] = (byte)v;
        }
        return SymbolicValue.Of(Expr.Int(Expr.BytesToInteger(bytes)), taints);
    }

    private static SymbolicValue ConvertBufferToBytes(BufferObject buf, System.Collections.Immutable.ImmutableHashSet<string> taints)
    {
        var bytes = new byte[buf.Length];
        for (int i = 0; i < buf.Length; i++)
        {
            if (buf.Cells[i] is not IntConst ic)
                return SymbolicValue.Of(new UnaryExpr(Sort.Bytes, "buf2bytes", Expr.Bytes(System.Array.Empty<byte>())), taints);
            int v = (int)ic.Value;
            if (v < 0 || v > 255) throw new VmFaultException($"buffer cell out of byte range: {v}");
            bytes[i] = (byte)v;
        }
        return SymbolicValue.Bytes(bytes);
    }
}
