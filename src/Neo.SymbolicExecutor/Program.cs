using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

/// <summary>
/// A decoded NeoVM script: original bytes, indexed instructions, resolved jump targets,
/// and (when loaded from a NEF) the contract's CALLT method tokens.
/// </summary>
public sealed class NeoProgram
{
    public ReadOnlyMemory<byte> Bytes { get; }
    public ImmutableArray<Instruction> Instructions { get; }
    public ImmutableDictionary<int, int> OffsetToIndex { get; }

    /// <summary>
    /// Method tokens declared in the source NEF for CALLT dispatch. May be null when the
    /// program was decoded from raw bytes only — in that case the engine treats CALLT
    /// metadata as fully dynamic (audit M1).
    /// </summary>
    public ImmutableArray<Nef.MethodToken> Tokens { get; }

    public NeoProgram(
        ReadOnlyMemory<byte> bytes,
        ImmutableArray<Instruction> instructions,
        ImmutableDictionary<int, int> offsetToIndex,
        ImmutableArray<Nef.MethodToken> tokens = default)
    {
        Bytes = bytes;
        Instructions = instructions;
        OffsetToIndex = offsetToIndex;
        Tokens = tokens.IsDefault ? ImmutableArray<Nef.MethodToken>.Empty : tokens;
    }

    public NeoProgram WithTokens(ImmutableArray<Nef.MethodToken> tokens) =>
        new(Bytes, Instructions, OffsetToIndex, tokens);

    public Instruction? AtOffset(int offset) =>
        OffsetToIndex.TryGetValue(offset, out int idx) ? Instructions[idx] : null;

    /// <summary>
    /// Look up an instruction at <paramref name="offset"/>; if the linear-scan index has no
    /// entry there (i.e., the offset lands inside the operand of a previously-decoded
    /// instruction), JIT-decode at that offset. This matches Neo.VM semantics: the runtime
    /// VM decodes each instruction at the program counter on-demand and accepts jump targets
    /// pointing into operand bytes of earlier instructions. Fuzzer differential testing
    /// (target `differential-neovm`) found this divergence in 10 seconds: a JMP +14 that
    /// landed inside an ISTYPE operand caused our engine to fault on "unaligned offset"
    /// while Neo.VM HALTed cleanly.
    /// </summary>
    public Instruction? AtOffsetOrDecode(int offset) =>
        OffsetToIndex.TryGetValue(offset, out int idx)
            ? Instructions[idx]
            : ScriptDecoder.DecodeOne(Bytes, offset);

    public Instruction RequireAt(int offset) =>
        AtOffset(offset) ?? throw new VmFaultException($"No instruction at offset {offset}");
}

public static class ScriptDecoder
{
    /// <summary>
    /// Decode a raw NeoVM script into instructions. Resolves branch targets from signed offsets
    /// per the canonical operand-size table. Variable-length operands (PUSHDATA*) read their
    /// size prefix first, then consume that many additional bytes.
    /// </summary>
    public static NeoProgram Decode(byte[] script)
    {
        var instructions = ImmutableArray.CreateBuilder<Instruction>();
        var offsetIndex = ImmutableDictionary.CreateBuilder<int, int>();

        int pos = 0;
        while (pos < script.Length)
        {
            int offset = pos;
            byte b = script[pos++];
            if (!OpCodeInfo.IsDefined(b))
                throw new VmFaultException($"Unknown opcode 0x{b:X2} at offset {offset}");
            var op = (NeoVm.OpCode)b;

            int operandSize;
            int prefixSize = OpCodeInfo.OperandPrefixSize(op);
            if (prefixSize > 0)
            {
                if (pos + prefixSize > script.Length)
                    throw new VmFaultException($"Truncated size prefix for {op} at offset {offset}");
                long size = ReadUnsigned(script.AsSpan(pos, prefixSize));
                pos += prefixSize;
                if (size < 0 || size > int.MaxValue)
                    throw new VmFaultException($"Operand size {size} for {op} out of range");
                operandSize = (int)size;
            }
            else
            {
                operandSize = OpCodeInfo.FixedOperandSize(op);
            }

            if (operandSize < 0 || pos + operandSize > script.Length)
                throw new VmFaultException($"Truncated operand for {op} at offset {offset}");

            var operandBytes = new ReadOnlyMemory<byte>(script, pos, operandSize);
            pos += operandSize;

            int totalSize = pos - offset;
            int target = -1;
            if (OpCodeInfo.IsBranch(op))
            {
                target = ResolveBranchTarget(op, offset, operandBytes.Span);
            }

            offsetIndex[offset] = instructions.Count;
            instructions.Add(new Instruction(offset, op, operandBytes, totalSize, target));
        }

        return new NeoProgram(script, instructions.ToImmutable(), offsetIndex.ToImmutable());
    }

    private static long ReadUnsigned(ReadOnlySpan<byte> bytes) => bytes.Length switch
    {
        1 => bytes[0],
        2 => System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(bytes),
        4 => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes),
        _ => throw new VmFaultException($"Bad prefix size {bytes.Length}"),
    };

    private static int ResolveBranchTarget(NeoVm.OpCode op, int offset, ReadOnlySpan<byte> operand)
    {
        // PUSHA pushes a 4-byte signed offset (target absolute address = offset + delta).
        // Same for short and long jump variants.
        if (operand.Length == 1) return offset + (sbyte)operand[0];
        if (operand.Length == 4) return offset + System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(operand);
        if (operand.Length == 8)
        {
            // TRY_L: catch + finally (each int32). Branch resolution surfaces the catch only here;
            // finally is handled separately in the engine.
            return offset + System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(operand[..4]);
        }
        return -1;
    }

    /// <summary>
    /// Decode a single instruction at <paramref name="offset"/> from the raw script bytes.
    /// Returns null when the offset is out of range, when the byte is not a defined opcode,
    /// or when the operand is truncated. Used by <see cref="NeoProgram.AtOffsetOrDecode"/>
    /// to support jumps that land inside operand bytes (Neo.VM-compatible behavior).
    /// </summary>
    public static Instruction? DecodeOne(ReadOnlyMemory<byte> script, int offset)
    {
        var span = script.Span;
        if (offset < 0 || offset >= span.Length) return null;
        int pos = offset;
        byte b = span[pos++];
        if (!OpCodeInfo.IsDefined(b)) return null;
        var op = (NeoVm.OpCode)b;

        int operandSize;
        int prefixSize = OpCodeInfo.OperandPrefixSize(op);
        if (prefixSize > 0)
        {
            if (pos + prefixSize > span.Length) return null;
            long size = ReadUnsigned(span.Slice(pos, prefixSize));
            pos += prefixSize;
            if (size < 0 || size > int.MaxValue) return null;
            operandSize = (int)size;
        }
        else
        {
            operandSize = OpCodeInfo.FixedOperandSize(op);
        }
        if (operandSize < 0 || pos + operandSize > span.Length) return null;

        var operandMem = script.Slice(pos, operandSize);
        pos += operandSize;

        int totalSize = pos - offset;
        int target = -1;
        if (OpCodeInfo.IsBranch(op))
            target = ResolveBranchTarget(op, offset, operandMem.Span);

        return new Instruction(offset, op, operandMem, totalSize, target);
    }

    public static (int CatchOffset, int FinallyOffset) ResolveTryTargets(Instruction inst)
    {
        var op = inst.Operand.Span;
        if (op.Length == 2)
        {
            int c = (sbyte)op[0];
            int f = (sbyte)op[1];
            return (c == 0 ? -1 : inst.Offset + c, f == 0 ? -1 : inst.Offset + f);
        }
        if (op.Length == 8)
        {
            int c = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(op[..4]);
            int f = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(op[4..]);
            return (c == 0 ? -1 : inst.Offset + c, f == 0 ? -1 : inst.Offset + f);
        }
        throw new VmFaultException("Bad TRY operand length");
    }
}
