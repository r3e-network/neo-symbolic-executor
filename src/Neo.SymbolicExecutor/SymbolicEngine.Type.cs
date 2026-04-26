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
        // Audit: ANY (0x00) is "no specific type" — always false per NeoVM (no item is the special ANY).
        if (typeByte == StackItemTypeCodes.Any)
        {
            state.Push(SymbolicValue.Bool(false));
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        var result = TypeMatches(v, typeByte);
        state.Push(SymbolicValue.Bool(result));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

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
        SymbolicValue converted = (typeByte, v.Sort) switch
        {
            (StackItemTypeCodes.Boolean, _) => SymbolicValue.Of(Expr.ToBool(v.Expression), v.Taints),
            (StackItemTypeCodes.Integer, Sort.Bool) =>
                SymbolicValue.Of(v.AsConcreteBool() == true ? Expr.Int(1) : Expr.Int(0), v.Taints),
            (StackItemTypeCodes.Integer, Sort.Bytes) =>
                v.AsConcreteBytes() is byte[] bs ? SymbolicValue.Int(Expr.BytesToInteger(bs)) : v,
            (StackItemTypeCodes.Integer, Sort.Int) => v,
            (StackItemTypeCodes.ByteString, Sort.Int) =>
                v.AsConcreteInt() is { } bi ? SymbolicValue.Bytes(Expr.IntegerToBytes(bi)) : v,
            (StackItemTypeCodes.ByteString, Sort.Bytes) => v,
            (StackItemTypeCodes.ByteString, Sort.Bool) =>
                v.AsConcreteBool() == true ? SymbolicValue.Bytes(new byte[] { 1 }) : SymbolicValue.Bytes(System.Array.Empty<byte>()),
            (StackItemTypeCodes.Buffer, Sort.Bytes) =>
                v.AsConcreteBytes() is byte[] bb
                    ? SymbolicValue.HeapRef(Sort.Buffer, state.Heap.NewBuffer(bb).Id)
                    : v,
            _ => v,  // permissive fallthrough; refined as type lattice fills in
        };
        state.Push(converted);
        state.Pc = inst.EndOffset;
        return Single(state);
    }
}
