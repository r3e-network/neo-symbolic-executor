using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using NeoVm = Neo.VM;

namespace Neo.SymbolicExecutor;

public sealed partial class SymbolicEngine
{
    private IEnumerable<ExecutionState> Dispatch(ExecutionState state, Instruction inst)
    {
        var op = inst.OpCode;

        // Push-immediate constants (cheap, common, no fork).
        if (TryPushConstant(state, inst, out var pushed))
        {
            state.Pc = inst.EndOffset;
            return Single(state);
        }

        switch (op)
        {
            // ---- Control flow
            case NeoVm.OpCode.NOP:
                state.Pc = inst.EndOffset;
                return Single(state);

            case NeoVm.OpCode.JMP:
            case NeoVm.OpCode.JMP_L:
                // Audit fix (iter-2 wakeup-17 pipeline-consistency): only record valid back-edges
                // in LoopsDetected. Negative jump targets fault on the next step, but the Add()
                // before that point lets detectors emit Findings with negative offsets.
                if (inst.Target >= 0 && inst.Target < state.Pc) state.Telemetry.LoopsDetected.Add(inst.Target);
                state.Pc = inst.Target;
                return Single(state);

            case NeoVm.OpCode.JMPIF:
            case NeoVm.OpCode.JMPIF_L:
                return ConditionalBranch(state, inst, jumpOnTrue: true);
            case NeoVm.OpCode.JMPIFNOT:
            case NeoVm.OpCode.JMPIFNOT_L:
                return ConditionalBranch(state, inst, jumpOnTrue: false);

            case NeoVm.OpCode.JMPEQ:
            case NeoVm.OpCode.JMPEQ_L:
            case NeoVm.OpCode.JMPNE:
            case NeoVm.OpCode.JMPNE_L:
            case NeoVm.OpCode.JMPGT:
            case NeoVm.OpCode.JMPGT_L:
            case NeoVm.OpCode.JMPGE:
            case NeoVm.OpCode.JMPGE_L:
            case NeoVm.OpCode.JMPLT:
            case NeoVm.OpCode.JMPLT_L:
            case NeoVm.OpCode.JMPLE:
            case NeoVm.OpCode.JMPLE_L:
                return ComparisonBranch(state, inst);

            case NeoVm.OpCode.CALL:
            case NeoVm.OpCode.CALL_L:
                return HandleCall(state, inst, target: inst.Target);
            case NeoVm.OpCode.CALLA:
                return HandleCallA(state, inst);

            case NeoVm.OpCode.RET:
                return HandleReturn(state, inst);

            case NeoVm.OpCode.ABORT:
                state.Terminate(TerminalStatus.Faulted, "ABORT");
                return Single(state);
            case NeoVm.OpCode.ABORTMSG:
                {
                    var msg = state.Pop();
                    state.Terminate(TerminalStatus.Faulted, "ABORTMSG: " + DescribeMessage(msg));
                    return Single(state);
                }
            case NeoVm.OpCode.ASSERT:
                return HandleAssert(state, inst, withMessage: false);
            case NeoVm.OpCode.ASSERTMSG:
                return HandleAssert(state, inst, withMessage: true);

            case NeoVm.OpCode.THROW:
                return HandleThrow(state, inst);

            case NeoVm.OpCode.TRY:
            case NeoVm.OpCode.TRY_L:
                return HandleTry(state, inst);
            case NeoVm.OpCode.ENDTRY:
            case NeoVm.OpCode.ENDTRY_L:
                return HandleEndTry(state, inst);
            case NeoVm.OpCode.ENDFINALLY:
                return HandleEndFinally(state, inst);

            case NeoVm.OpCode.SYSCALL:
                return HandleSyscall(state, inst);

            // ---- Stack
            case NeoVm.OpCode.DEPTH:
                state.Push(SymbolicValue.Int(state.EvaluationStack.Count));
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.DROP:
                state.Pop(); state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.NIP:
                {
                    var top = state.Pop(); state.Pop(); state.Push(top);
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.XDROP:
                return HandleXDrop(state, inst);
            case NeoVm.OpCode.CLEAR:
                state.EvaluationStack.Clear(); state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.DUP:
                state.Push(state.Peek()); state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.OVER:
                state.Push(state.Peek(1)); state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.PICK:
                return HandlePick(state, inst);
            case NeoVm.OpCode.TUCK:
                {
                    var a = state.Pop();
                    var b = state.Pop();
                    state.Push(a); state.Push(b); state.Push(a);
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.SWAP:
                {
                    var a = state.Pop(); var b = state.Pop();
                    state.Push(a); state.Push(b);
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.ROT:
                {
                    var c = state.Pop(); var b = state.Pop(); var a = state.Pop();
                    state.Push(b); state.Push(c); state.Push(a);
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.ROLL:
                return HandleRoll(state, inst);
            case NeoVm.OpCode.REVERSE3:
                ReverseTopN(state, 3); state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.REVERSE4:
                ReverseTopN(state, 4); state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.REVERSEN:
                return HandleReverseN(state, inst);

            // ---- Slots
            case NeoVm.OpCode.INITSSLOT:
                {
                    int n = inst.Operand.Span[0];
                    // Audit fix (engine L3): per NeoVM JumpTable.Slot, INITSSLOT throws if statics
                    // are already initialized OR if n == 0. The prior implementation cleared and
                    // refilled, masking double-init bugs.
                    if (n == 0)
                        throw new VmFaultException("INITSSLOT requires non-zero static slot count");
                    if (state.StaticFields.Count > 0)
                        throw new VmFaultException("INITSSLOT called twice — statics already initialized");
                    for (int i = 0; i < n; i++) state.StaticFields.Add(SymbolicValue.Null());
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.INITSLOT:
                {
                    int locals = inst.Operand.Span[0];
                    int args = inst.Operand.Span[1];
                    var frame = state.CurrentFrame;
                    // Audit fix (engine M1): NeoVM rejects INITSLOT when slots already exist on the
                    // frame, and rejects (locals==0 && args==0). We previously appended silently,
                    // letting bytecode produce arbitrarily-large slot tables.
                    if (locals == 0 && args == 0)
                        throw new VmFaultException("INITSLOT with zero locals AND zero args");
                    if (frame.Locals.Count > 0 || frame.Args.Count > 0)
                        throw new VmFaultException("INITSLOT called twice — slots already initialized on this frame");
                    var popped = new SymbolicValue[args];
                    for (int i = 0; i < args; i++) popped[i] = state.Pop();
                    // NeoVM pops args in order so arg[0] was last pushed; restore positional order.
                    for (int i = 0; i < args; i++) frame.Args.Add(popped[i]);
                    for (int i = 0; i < locals; i++) frame.Locals.Add(SymbolicValue.Null());
                    state.Pc = inst.EndOffset; return Single(state);
                }

            case NeoVm.OpCode.LDSFLD0:
            case NeoVm.OpCode.LDSFLD1:
            case NeoVm.OpCode.LDSFLD2:
            case NeoVm.OpCode.LDSFLD3:
            case NeoVm.OpCode.LDSFLD4:
            case NeoVm.OpCode.LDSFLD5:
            case NeoVm.OpCode.LDSFLD6:
                state.Push(LoadSlot(state.StaticFields, op - NeoVm.OpCode.LDSFLD0));
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.LDSFLD:
                state.Push(LoadSlot(state.StaticFields, inst.Operand.Span[0]));
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.STSFLD0:
            case NeoVm.OpCode.STSFLD1:
            case NeoVm.OpCode.STSFLD2:
            case NeoVm.OpCode.STSFLD3:
            case NeoVm.OpCode.STSFLD4:
            case NeoVm.OpCode.STSFLD5:
            case NeoVm.OpCode.STSFLD6:
                StoreSlot(state.StaticFields, op - NeoVm.OpCode.STSFLD0, state.Pop());
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.STSFLD:
                StoreSlot(state.StaticFields, inst.Operand.Span[0], state.Pop());
                state.Pc = inst.EndOffset; return Single(state);

            case NeoVm.OpCode.LDLOC0:
            case NeoVm.OpCode.LDLOC1:
            case NeoVm.OpCode.LDLOC2:
            case NeoVm.OpCode.LDLOC3:
            case NeoVm.OpCode.LDLOC4:
            case NeoVm.OpCode.LDLOC5:
            case NeoVm.OpCode.LDLOC6:
                state.Push(LoadSlot(state.CurrentFrame.Locals, op - NeoVm.OpCode.LDLOC0));
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.LDLOC:
                state.Push(LoadSlot(state.CurrentFrame.Locals, inst.Operand.Span[0]));
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.STLOC0:
            case NeoVm.OpCode.STLOC1:
            case NeoVm.OpCode.STLOC2:
            case NeoVm.OpCode.STLOC3:
            case NeoVm.OpCode.STLOC4:
            case NeoVm.OpCode.STLOC5:
            case NeoVm.OpCode.STLOC6:
                StoreSlot(state.CurrentFrame.Locals, op - NeoVm.OpCode.STLOC0, state.Pop());
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.STLOC:
                StoreSlot(state.CurrentFrame.Locals, inst.Operand.Span[0], state.Pop());
                state.Pc = inst.EndOffset; return Single(state);

            case NeoVm.OpCode.LDARG0:
            case NeoVm.OpCode.LDARG1:
            case NeoVm.OpCode.LDARG2:
            case NeoVm.OpCode.LDARG3:
            case NeoVm.OpCode.LDARG4:
            case NeoVm.OpCode.LDARG5:
            case NeoVm.OpCode.LDARG6:
                state.Push(LoadSlot(state.CurrentFrame.Args, op - NeoVm.OpCode.LDARG0));
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.LDARG:
                state.Push(LoadSlot(state.CurrentFrame.Args, inst.Operand.Span[0]));
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.STARG0:
            case NeoVm.OpCode.STARG1:
            case NeoVm.OpCode.STARG2:
            case NeoVm.OpCode.STARG3:
            case NeoVm.OpCode.STARG4:
            case NeoVm.OpCode.STARG5:
            case NeoVm.OpCode.STARG6:
                StoreSlot(state.CurrentFrame.Args, op - NeoVm.OpCode.STARG0, state.Pop());
                state.Pc = inst.EndOffset; return Single(state);
            case NeoVm.OpCode.STARG:
                StoreSlot(state.CurrentFrame.Args, inst.Operand.Span[0], state.Pop());
                state.Pc = inst.EndOffset; return Single(state);

            // ---- Bitwise / Arithmetic / Compare
            case NeoVm.OpCode.INVERT: return Unary(state, inst, Expr.Invert);
            case NeoVm.OpCode.AND: return Binary(state, inst, Expr.And);
            case NeoVm.OpCode.OR: return Binary(state, inst, Expr.Or);
            case NeoVm.OpCode.XOR: return Binary(state, inst, Expr.Xor);
            // Audit fix (iter-2 wakeup-12): EQUAL/NOTEQUAL use NeoVM's `x1.Equals(x2, limits)`
            // which does DEEP structural comparison for Structs (recursively walking fields).
            // The plain Expr.Eq fast-path treats HeapRef==HeapRef as ID equality, which is
            // wrong for two NEWSTRUCT0 (they have different IDs but identical empty contents).
            // Caught by differential: NEWSTRUCT0 NEWSTRUCT0 EQUAL DIV → NeoVM halts (true→1,
            // 10/1=10), our engine pushed false then DIV by zero faulted.
            case NeoVm.OpCode.EQUAL: return HandleEquality(state, inst, negate: false);
            case NeoVm.OpCode.NOTEQUAL: return HandleEquality(state, inst, negate: true);

            case NeoVm.OpCode.SIGN: return Unary(state, inst, Expr.Sign);
            case NeoVm.OpCode.ABS: return Unary(state, inst, Expr.Abs);
            case NeoVm.OpCode.NEGATE: return Unary(state, inst, Expr.Neg);
            case NeoVm.OpCode.INC: return UnaryArith(state, inst, "INC", Expr.Inc, overflow: true);
            case NeoVm.OpCode.DEC: return UnaryArith(state, inst, "DEC", Expr.Dec, overflow: true);
            case NeoVm.OpCode.ADD: return BinaryArith(state, inst, "ADD", Expr.Add, overflow: true);
            case NeoVm.OpCode.SUB: return BinaryArith(state, inst, "SUB", Expr.Sub, overflow: true);
            case NeoVm.OpCode.MUL: return BinaryArith(state, inst, "MUL", Expr.Mul, overflow: true);
            case NeoVm.OpCode.DIV: return BinaryArith(state, inst, "DIV", Expr.Div, overflow: false, divisorMatters: true);
            case NeoVm.OpCode.MOD: return BinaryArith(state, inst, "MOD", Expr.Mod, overflow: false, divisorMatters: true);
            case NeoVm.OpCode.POW: return BinaryArith(state, inst, "POW", (a, b) => Expr.Pow(a, b, _options.MaxPowExponent), overflow: true);
            case NeoVm.OpCode.SQRT: return UnaryArith(state, inst, "SQRT", Expr.Sqrt, overflow: false);
            case NeoVm.OpCode.MODMUL: return TernaryArith(state, inst, "MODMUL", Expr.ModMul);
            case NeoVm.OpCode.MODPOW: return TernaryArith(state, inst, "MODPOW", Expr.ModPow);
            // Audit fix (iter-2 wakeup-4 differential): NeoVM's SHL/SHR pop the SHIFT first,
            // then check `if (shift == 0) return;` BEFORE popping x. So a script with stack=[x]
            // and SHL/SHR consuming a 0 shift leaves x on the stack — Neo.VM HALTs cleanly.
            // Our prior `BinaryArith` always popped both unconditionally, producing a spurious
            // Stack-underflow fault. Keep BinaryArith for symbolic shifts (the divergence is
            // unobservable when shift is non-zero or symbolic); special-case concrete shift==0.
            case NeoVm.OpCode.SHL: return HandleShift(state, inst, "SHL", isLeft: true);
            case NeoVm.OpCode.SHR: return HandleShift(state, inst, "SHR", isLeft: false);

            case NeoVm.OpCode.NOT: return Unary(state, inst, Expr.Not);
            case NeoVm.OpCode.BOOLAND: return Binary(state, inst, Expr.BoolAnd);
            case NeoVm.OpCode.BOOLOR: return Binary(state, inst, Expr.BoolOr);
            case NeoVm.OpCode.NZ: return Unary(state, inst, Expr.Nz);
            // Audit fix (iter-2 wakeup-10): NUMEQUAL / NUMNOTEQUAL pop both operands as
            // GetInteger and compare numerically — this is DIFFERENT from EQUAL/NOTEQUAL which
            // use type-aware StackItem.Equals (Bool != Int regardless of value). Use NumEq.
            case NeoVm.OpCode.NUMEQUAL: return Binary(state, inst, Expr.NumEq);
            case NeoVm.OpCode.NUMNOTEQUAL: return Binary(state, inst, Expr.NumNe);
            case NeoVm.OpCode.LT: return Binary(state, inst, Expr.Lt);
            case NeoVm.OpCode.LE: return Binary(state, inst, Expr.Le);
            case NeoVm.OpCode.GT: return Binary(state, inst, Expr.Gt);
            case NeoVm.OpCode.GE: return Binary(state, inst, Expr.Ge);
            case NeoVm.OpCode.MIN: return Binary(state, inst, Expr.Min);
            case NeoVm.OpCode.MAX: return Binary(state, inst, Expr.Max);
            case NeoVm.OpCode.WITHIN:
                {
                    var hi = state.Pop().Expression;
                    var lo = state.Pop().Expression;
                    var x = state.Pop().Expression;
                    state.Push(SymbolicValue.Of(Expr.Within(x, lo, hi)));
                    state.Pc = inst.EndOffset; return Single(state);
                }

            // ---- Type
            case NeoVm.OpCode.ISNULL:
                {
                    var v = state.Pop();
                    state.Push(SymbolicValue.Bool(v.IsConcreteNull));
                    state.Pc = inst.EndOffset; return Single(state);
                }
            case NeoVm.OpCode.ISTYPE:
                return HandleIsType(state, inst);
            case NeoVm.OpCode.CONVERT:
                return HandleConvert(state, inst);

            // ---- Compound + Splice + others (covered in partial files)
            default:
                return DispatchExtended(state, inst);
        }
    }

    private static IEnumerable<ExecutionState> Single(ExecutionState s) => new[] { s };

    /// <summary>Push-immediate constants. Returns true if handled.</summary>
    private bool TryPushConstant(ExecutionState state, Instruction inst, out SymbolicValue? value)
    {
        value = null;
        var op = inst.OpCode;

        // Numeric range PUSH0..PUSH16, PUSHM1
        if (op == NeoVm.OpCode.PUSHM1) { state.Push(SymbolicValue.Int(-1)); return true; }
        if ((byte)op >= (byte)NeoVm.OpCode.PUSH0 && (byte)op <= (byte)NeoVm.OpCode.PUSH16)
        {
            int n = (byte)op - (byte)NeoVm.OpCode.PUSH0;
            state.Push(SymbolicValue.Int(n));
            return true;
        }
        if (op == NeoVm.OpCode.PUSHT) { state.Push(SymbolicValue.Bool(true)); return true; }
        if (op == NeoVm.OpCode.PUSHF) { state.Push(SymbolicValue.Bool(false)); return true; }
        if (op == NeoVm.OpCode.PUSHNULL) { state.Push(SymbolicValue.Null()); return true; }
        if (op == NeoVm.OpCode.PUSHA)
        {
            // Audit CRIT-1 fix: never read the raw operand delta as the value; always push the
            // resolved absolute target (which is 0 when the target is offset 0).
            state.Push(SymbolicValue.Int(inst.Target));
            return true;
        }
        if (op is NeoVm.OpCode.PUSHINT8 or NeoVm.OpCode.PUSHINT16 or NeoVm.OpCode.PUSHINT32
                or NeoVm.OpCode.PUSHINT64 or NeoVm.OpCode.PUSHINT128 or NeoVm.OpCode.PUSHINT256)
        {
            state.Push(SymbolicValue.Of(Expr.Int(new BigInteger(inst.Operand.Span, isUnsigned: false, isBigEndian: false))));
            return true;
        }
        if (op is NeoVm.OpCode.PUSHDATA1 or NeoVm.OpCode.PUSHDATA2 or NeoVm.OpCode.PUSHDATA4)
        {
            state.Push(SymbolicValue.Bytes(inst.Operand.ToArray()));
            return true;
        }
        return false;
    }

    private static SymbolicValue LoadSlot(IList<SymbolicValue?> slot, int index)
    {
        if (index < 0 || index >= slot.Count)
            throw new VmFaultException($"slot index {index} out of range (size {slot.Count})");
        return slot[index] ?? SymbolicValue.Null();
    }

    private static void StoreSlot(IList<SymbolicValue?> slot, int index, SymbolicValue value)
    {
        if (index < 0 || index >= slot.Count)
            throw new VmFaultException($"slot index {index} out of range (size {slot.Count})");
        slot[index] = value;
    }

    private static void ReverseTopN(ExecutionState state, int n)
    {
        if (state.EvaluationStack.Count < n)
            throw new VmFaultException($"REVERSE requires {n} stack items");
        int hi = state.EvaluationStack.Count - 1;
        int lo = state.EvaluationStack.Count - n;
        while (lo < hi)
        {
            (state.EvaluationStack[lo], state.EvaluationStack[hi]) =
                (state.EvaluationStack[hi], state.EvaluationStack[lo]);
            lo++; hi--;
        }
    }

    private IEnumerable<ExecutionState> Unary(ExecutionState state, Instruction inst, Func<Expression, Expression> f)
    {
        var v = state.Pop();
        state.Push(SymbolicValue.Of(f(v.Expression), v.Taints));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> Binary(ExecutionState state, Instruction inst, Func<Expression, Expression, Expression> f)
    {
        var b = state.Pop();
        var a = state.Pop();
        state.Push(SymbolicValue.Of(f(a.Expression, b.Expression), a.Taints.Union(b.Taints)));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> UnaryArith(ExecutionState state, Instruction inst, string opName,
                                                   Func<Expression, Expression> f, bool overflow)
    {
        var v = state.Pop();
        var result = f(v.Expression);
        state.Push(SymbolicValue.Of(result, v.Taints));
        state.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
            inst.Offset, opName, v, null,
            OverflowPossible: overflow && !v.IsConcrete,
            DivisorMaybeZero: false,
            Checked: false));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> BinaryArith(ExecutionState state, Instruction inst, string opName,
                                                    Func<Expression, Expression, Expression> f,
                                                    bool overflow, bool divisorMatters = false)
    {
        var b = state.Pop();
        var a = state.Pop();
        var result = f(a.Expression, b.Expression);
        bool divisorMaybeZero = divisorMatters && !b.IsConcrete;
        state.Push(SymbolicValue.Of(result, a.Taints.Union(b.Taints)));
        // Audit overflow.py finding: only flag overflow when neither operand is bounded.
        // For now, mark when either is symbolic; the SMT layer will tighten this later.
        bool overflowPossible = overflow && (!a.IsConcrete || !b.IsConcrete);
        state.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
            inst.Offset, opName, a, b,
            OverflowPossible: overflowPossible,
            DivisorMaybeZero: divisorMaybeZero,
            Checked: false));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private IEnumerable<ExecutionState> TernaryArith(ExecutionState state, Instruction inst, string opName,
                                                     Func<Expression, Expression, Expression, Expression> f)
    {
        var c = state.Pop();
        var b = state.Pop();
        var a = state.Pop();
        var result = f(a.Expression, b.Expression, c.Expression);
        state.Push(SymbolicValue.Of(result, a.Taints.Union(b.Taints).Union(c.Taints)));
        state.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
            inst.Offset, opName, a, b,
            OverflowPossible: !a.IsConcrete || !b.IsConcrete || !c.IsConcrete,
            DivisorMaybeZero: false,
            Checked: false));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    private static string DescribeMessage(SymbolicValue v) =>
        v.AsConcreteBytes() is byte[] bytes
            ? System.Text.Encoding.UTF8.GetString(bytes)
            : "<symbolic message>";

    private IEnumerable<ExecutionState> HandleEquality(ExecutionState state, Instruction inst, bool negate)
    {
        var b = state.Pop();
        var a = state.Pop();
        Expression eq = StackItemEquals(state, a.Expression, b.Expression, depth: 0);
        var result = negate ? Expr.Not(eq) : eq;
        state.Push(SymbolicValue.Of(result, a.Taints.Union(b.Taints)));
        state.Pc = inst.EndOffset;
        return Single(state);
    }

    /// <summary>
    /// Mirrors NeoVM's StackItem.Equals(other, limits) for the EQUAL/NOTEQUAL opcodes.
    /// Primitives use Expr.Eq's type-aware byte-canonical semantics. HeapRefs:
    ///  - Same id  → true
    ///  - Different sort → false
    ///  - Both Struct → deep recursive equality (walk fields, max-depth-bounded)
    ///  - Map / Array / Buffer → reference identity (different ids ⇒ false)
    /// Anything symbolic returns a BinaryExpr that downstream branching can resolve.
    /// </summary>
    private Expression StackItemEquals(ExecutionState state, Expression a, Expression b, int depth)
    {
        const int MaxDepth = 64;
        if (a is HeapRef ah && b is HeapRef bh)
        {
            if (ah.ObjectId == bh.ObjectId) return BoolConst.True;
            if (ah.RefSort != bh.RefSort) return BoolConst.False;
            if (ah.RefSort == Sort.Struct && depth < MaxDepth)
            {
                var s1 = state.Heap.Objects.TryGetValue(ah.ObjectId, out var o1) ? o1 as StructObject : null;
                var s2 = state.Heap.Objects.TryGetValue(bh.ObjectId, out var o2) ? o2 as StructObject : null;
                if (s1 is null || s2 is null) return BoolConst.False;
                if (s1.Fields.Count != s2.Fields.Count) return BoolConst.False;
                Expression acc = BoolConst.True;
                for (int i = 0; i < s1.Fields.Count; i++)
                {
                    var fEq = StackItemEquals(state, s1.Fields[i].Expression, s2.Fields[i].Expression, depth + 1);
                    if (fEq is BoolConst bc && !bc.Value) return BoolConst.False;
                    acc = Expr.BoolAnd(acc, fEq);
                }
                return acc;
            }
            // Array / Map / Buffer: NeoVM uses reference identity; different ids ⇒ false.
            return BoolConst.False;
        }
        return Expr.Eq(a, b);
    }

    private IEnumerable<ExecutionState> HandleShift(ExecutionState state, Instruction inst, string opName, bool isLeft)
    {
        var b = state.Pop();
        // Audit fix (iter-2 wakeup-5): NeoVM's GetInteger converts Bool/ByteString to BigInteger
        // before checking shift==0. Use Expr.ConcreteInt for the same cross-type semantics —
        // a PUSH5 NOT SHR (where NOT produces BoolConst.False = shift 0) used to underflow on
        // the second pop because b.AsConcreteInt() returned null on a BoolConst.
        if (Expr.ConcreteInt(b.Expression) is { } shift && shift == 0)
        {
            state.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
                inst.Offset, opName, b, null,
                OverflowPossible: false, DivisorMaybeZero: false, Checked: false));
            state.Pc = inst.EndOffset;
            return Single(state);
        }
        var a = state.Pop();
        Expression result = isLeft
            ? Expr.Shl(a.Expression, b.Expression, _options.MaxShiftCount)
            : Expr.Shr(a.Expression, b.Expression, _options.MaxShiftCount);
        state.Push(SymbolicValue.Of(result, a.Taints.Union(b.Taints)));
        state.Telemetry.ArithmeticOps.Add(new ArithmeticOp(
            inst.Offset, opName, a, b,
            OverflowPossible: isLeft && (!a.IsConcrete || !b.IsConcrete),
            DivisorMaybeZero: false, Checked: false));
        state.Pc = inst.EndOffset;
        return Single(state);
    }
}
