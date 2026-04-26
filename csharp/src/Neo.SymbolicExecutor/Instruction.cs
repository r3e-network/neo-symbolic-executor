using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using System.Numerics;
using System.Reflection;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

/// <summary>
/// A single decoded NeoVM instruction at a real byte offset. Operand bytes are sliced from the
/// originating script. <see cref="Target"/> is the resolved absolute jump target for branch /
/// CALL_L / PUSHA opcodes; -1 for non-branch opcodes.
/// </summary>
public sealed record Instruction(
    int Offset,
    NeoVm.OpCode OpCode,
    ReadOnlyMemory<byte> Operand,
    int Size,
    int Target = -1)
{
    public int EndOffset => Offset + Size;

    public BigInteger ImmediateInt()
    {
        if (Operand.IsEmpty) return BigInteger.Zero;
        return new BigInteger(Operand.Span, isUnsigned: false, isBigEndian: false);
    }

    public byte[] OperandToArray() => Operand.ToArray();
}

/// <summary>
/// Operand-size table built from <see cref="NeoVm.OpCode"/> attributes. Mirrors the
/// canonical Neo.VM metadata so we do not redefine it.
/// </summary>
public static class OpCodeInfo
{
    private static readonly int[] _operandSizes;
    private static readonly int[] _operandPrefixSizes;
    private static readonly bool[] _defined;

    static OpCodeInfo()
    {
        _operandSizes = new int[256];
        _operandPrefixSizes = new int[256];
        _defined = new bool[256];

        var type = typeof(NeoVm.OpCode);
        foreach (var name in Enum.GetNames(type))
        {
            var field = type.GetField(name)!;
            byte value = (byte)(NeoVm.OpCode)field.GetValue(null)!;
            _defined[value] = true;
            var attr = field.GetCustomAttribute<NeoVm.OperandSizeAttribute>();
            if (attr is not null)
            {
                _operandSizes[value] = attr.Size;
                _operandPrefixSizes[value] = attr.SizePrefix;
            }
        }
    }

    public static bool IsDefined(byte b) => _defined[b];
    public static int FixedOperandSize(NeoVm.OpCode op) => _operandSizes[(byte)op];
    public static int OperandPrefixSize(NeoVm.OpCode op) => _operandPrefixSizes[(byte)op];

    public static bool IsBranch(NeoVm.OpCode op) => op switch
    {
        NeoVm.OpCode.JMP or NeoVm.OpCode.JMP_L
            or NeoVm.OpCode.JMPIF or NeoVm.OpCode.JMPIF_L
            or NeoVm.OpCode.JMPIFNOT or NeoVm.OpCode.JMPIFNOT_L
            or NeoVm.OpCode.JMPEQ or NeoVm.OpCode.JMPEQ_L
            or NeoVm.OpCode.JMPNE or NeoVm.OpCode.JMPNE_L
            or NeoVm.OpCode.JMPGT or NeoVm.OpCode.JMPGT_L
            or NeoVm.OpCode.JMPGE or NeoVm.OpCode.JMPGE_L
            or NeoVm.OpCode.JMPLT or NeoVm.OpCode.JMPLT_L
            or NeoVm.OpCode.JMPLE or NeoVm.OpCode.JMPLE_L
            or NeoVm.OpCode.CALL or NeoVm.OpCode.CALL_L
            or NeoVm.OpCode.ENDTRY or NeoVm.OpCode.ENDTRY_L
            or NeoVm.OpCode.PUSHA => true,
        _ => false,
    };

    public static bool IsTry(NeoVm.OpCode op) =>
        op == NeoVm.OpCode.TRY || op == NeoVm.OpCode.TRY_L;

    public static bool IsCondJump(NeoVm.OpCode op) => op switch
    {
        NeoVm.OpCode.JMPIF or NeoVm.OpCode.JMPIF_L
            or NeoVm.OpCode.JMPIFNOT or NeoVm.OpCode.JMPIFNOT_L
            or NeoVm.OpCode.JMPEQ or NeoVm.OpCode.JMPEQ_L
            or NeoVm.OpCode.JMPNE or NeoVm.OpCode.JMPNE_L
            or NeoVm.OpCode.JMPGT or NeoVm.OpCode.JMPGT_L
            or NeoVm.OpCode.JMPGE or NeoVm.OpCode.JMPGE_L
            or NeoVm.OpCode.JMPLT or NeoVm.OpCode.JMPLT_L
            or NeoVm.OpCode.JMPLE or NeoVm.OpCode.JMPLE_L => true,
        _ => false,
    };
}
