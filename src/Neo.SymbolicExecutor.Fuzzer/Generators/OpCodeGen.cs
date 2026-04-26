using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor.Fuzzer.Generators;

/// <summary>
/// Generator for structurally-valid NeoVM scripts. Emits opcodes drawn from a curated set
/// (so we exercise the engine's interesting paths instead of producing decode failures every
/// time), with correctly-sized operands. Always terminates the script with RET.
/// </summary>
public static class OpCodeGen
{
    /// <summary>Curated mix biased toward stack ops, arithmetic, control flow, and the dispatch
    /// paths the engine fixes from iter-2 audit touched (CONVERT, ISTYPE, NEWARRAY_T, INITSLOT).</summary>
    public static readonly NeoVm.OpCode[] DefaultMix = new[]
    {
        // Push immediates
        NeoVm.OpCode.PUSH0, NeoVm.OpCode.PUSH1, NeoVm.OpCode.PUSH2, NeoVm.OpCode.PUSH3,
        NeoVm.OpCode.PUSH4, NeoVm.OpCode.PUSH5, NeoVm.OpCode.PUSH6, NeoVm.OpCode.PUSH7,
        NeoVm.OpCode.PUSH8, NeoVm.OpCode.PUSH9, NeoVm.OpCode.PUSH10, NeoVm.OpCode.PUSH11,
        NeoVm.OpCode.PUSH12, NeoVm.OpCode.PUSH13, NeoVm.OpCode.PUSH14, NeoVm.OpCode.PUSH15,
        NeoVm.OpCode.PUSH16, NeoVm.OpCode.PUSHM1, NeoVm.OpCode.PUSHT, NeoVm.OpCode.PUSHF,
        NeoVm.OpCode.PUSHNULL, NeoVm.OpCode.PUSHA,
        NeoVm.OpCode.PUSHINT8, NeoVm.OpCode.PUSHINT16, NeoVm.OpCode.PUSHINT32,
        // Stack
        NeoVm.OpCode.NOP, NeoVm.OpCode.DUP, NeoVm.OpCode.DROP, NeoVm.OpCode.SWAP,
        NeoVm.OpCode.OVER, NeoVm.OpCode.NIP, NeoVm.OpCode.ROT, NeoVm.OpCode.TUCK,
        NeoVm.OpCode.DEPTH, NeoVm.OpCode.CLEAR, NeoVm.OpCode.PICK, NeoVm.OpCode.ROLL,
        NeoVm.OpCode.REVERSE3, NeoVm.OpCode.REVERSE4, NeoVm.OpCode.REVERSEN,
        NeoVm.OpCode.XDROP,
        // Slots
        NeoVm.OpCode.INITSLOT, NeoVm.OpCode.INITSSLOT,
        NeoVm.OpCode.LDLOC0, NeoVm.OpCode.LDLOC1, NeoVm.OpCode.STLOC0, NeoVm.OpCode.STLOC1,
        NeoVm.OpCode.LDARG0, NeoVm.OpCode.LDARG1, NeoVm.OpCode.STARG0, NeoVm.OpCode.STARG1,
        NeoVm.OpCode.LDSFLD0, NeoVm.OpCode.LDSFLD1, NeoVm.OpCode.STSFLD0, NeoVm.OpCode.STSFLD1,
        // Arithmetic / bitwise
        NeoVm.OpCode.ADD, NeoVm.OpCode.SUB, NeoVm.OpCode.MUL, NeoVm.OpCode.DIV, NeoVm.OpCode.MOD,
        NeoVm.OpCode.NEGATE, NeoVm.OpCode.ABS, NeoVm.OpCode.SIGN,
        NeoVm.OpCode.INC, NeoVm.OpCode.DEC, NeoVm.OpCode.POW, NeoVm.OpCode.SQRT,
        NeoVm.OpCode.SHL, NeoVm.OpCode.SHR, NeoVm.OpCode.MODMUL, NeoVm.OpCode.MODPOW,
        NeoVm.OpCode.AND, NeoVm.OpCode.OR, NeoVm.OpCode.XOR, NeoVm.OpCode.INVERT,
        NeoVm.OpCode.NOT, NeoVm.OpCode.BOOLAND, NeoVm.OpCode.BOOLOR, NeoVm.OpCode.NZ,
        NeoVm.OpCode.NUMEQUAL, NeoVm.OpCode.NUMNOTEQUAL,
        NeoVm.OpCode.LT, NeoVm.OpCode.LE, NeoVm.OpCode.GT, NeoVm.OpCode.GE,
        NeoVm.OpCode.MIN, NeoVm.OpCode.MAX, NeoVm.OpCode.WITHIN,
        NeoVm.OpCode.EQUAL, NeoVm.OpCode.NOTEQUAL,
        // Compound
        NeoVm.OpCode.NEWARRAY0, NeoVm.OpCode.NEWMAP, NeoVm.OpCode.NEWSTRUCT0,
        NeoVm.OpCode.NEWARRAY, NeoVm.OpCode.NEWSTRUCT, NeoVm.OpCode.NEWARRAY_T,
        NeoVm.OpCode.NEWBUFFER,
        NeoVm.OpCode.SIZE, NeoVm.OpCode.ISNULL, NeoVm.OpCode.PACK, NeoVm.OpCode.UNPACK,
        NeoVm.OpCode.PACKSTRUCT, NeoVm.OpCode.PACKMAP,
        NeoVm.OpCode.PICKITEM, NeoVm.OpCode.HASKEY, NeoVm.OpCode.SETITEM, NeoVm.OpCode.APPEND,
        NeoVm.OpCode.REMOVE, NeoVm.OpCode.REVERSEITEMS, NeoVm.OpCode.CLEARITEMS,
        NeoVm.OpCode.KEYS, NeoVm.OpCode.VALUES, NeoVm.OpCode.POPITEM,
        // Splice
        NeoVm.OpCode.CAT, NeoVm.OpCode.SUBSTR, NeoVm.OpCode.LEFT, NeoVm.OpCode.RIGHT,
        NeoVm.OpCode.MEMCPY,
        // Type
        NeoVm.OpCode.ISTYPE, NeoVm.OpCode.CONVERT,
        // Control flow
        NeoVm.OpCode.JMP, NeoVm.OpCode.JMPIF, NeoVm.OpCode.JMPIFNOT,
        NeoVm.OpCode.JMPEQ, NeoVm.OpCode.JMPNE,
        NeoVm.OpCode.JMPGT, NeoVm.OpCode.JMPGE, NeoVm.OpCode.JMPLT, NeoVm.OpCode.JMPLE,
        NeoVm.OpCode.CALL, NeoVm.OpCode.CALLA,
        NeoVm.OpCode.ABORT, NeoVm.OpCode.ASSERT, NeoVm.OpCode.ASSERTMSG, NeoVm.OpCode.ABORTMSG,
        NeoVm.OpCode.THROW, NeoVm.OpCode.TRY, NeoVm.OpCode.ENDTRY, NeoVm.OpCode.ENDFINALLY,
    };

    public static byte[] RandomScript(Random rng, int minOps = 2, int maxOps = 64)
    {
        int n = rng.Next(minOps, maxOps + 1);
        var bytes = new List<byte>();
        for (int i = 0; i < n; i++)
        {
            var op = DefaultMix[rng.Next(DefaultMix.Length)];
            bytes.Add((byte)op);
            int operandSize = OpCodeInfo.FixedOperandSize(op);
            if (operandSize == 1 && IsRelativeJump(op))
            {
                // Generate small forward/backward offsets relative to current instruction byte.
                sbyte delta = (sbyte)rng.Next(-8, 16);
                bytes.Add((byte)delta);
            }
            else if (operandSize > 0)
            {
                for (int k = 0; k < operandSize; k++) bytes.Add((byte)rng.Next(0, 256));
            }
        }
        bytes.Add((byte)NeoVm.OpCode.RET);
        return bytes.ToArray();
    }

    private static bool IsRelativeJump(NeoVm.OpCode op) =>
        op is NeoVm.OpCode.JMP or NeoVm.OpCode.JMPIF or NeoVm.OpCode.JMPIFNOT
            or NeoVm.OpCode.JMPEQ or NeoVm.OpCode.JMPNE
            or NeoVm.OpCode.JMPGT or NeoVm.OpCode.JMPGE
            or NeoVm.OpCode.JMPLT or NeoVm.OpCode.JMPLE;
}
