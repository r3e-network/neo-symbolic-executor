"""Symbolic execution engine for NeoVM bytecode."""
from __future__ import annotations

from typing import Any

from ..nef.manifest import Manifest
from ..nef.opcodes import OpCode
from ..nef.parser import Instruction, NefFile
from ..nef.syscalls import SYSCALLS_BY_ID, SyscallInfo
from .state import (
    ArithmeticOp,
    ExecutionState,
    ExternalCall,
    StorageOp,
    SymbolicValue,
    TryFrame,
)


def _to_signed_i8(value: int) -> int:
    return value - 256 if value >= 128 else value


_BASE_GAS: dict[OpCode, int] = {
    OpCode.SYSCALL: 0,
    OpCode.CALL: 2,
    OpCode.CALL_L: 2,
    OpCode.MUL: 8,
    OpCode.ADD: 2,
    OpCode.SUB: 2,
}


class SymbolicEngine:
    """Path-exploring symbolic executor for a subset of NeoVM opcodes."""

    MAX_PATHS = 256
    MAX_DEPTH = 128
    MAX_STACK = 2048
    WORD_BITS = 256

    def __init__(self, nef: NefFile, manifest: Manifest | None = None) -> None:
        self.nef = nef
        self.manifest = manifest
        self._instructions = {ins.offset: ins for ins in nef.instructions}

    def run(self, entry_offset: int = 0) -> list[ExecutionState]:
        if entry_offset not in self._instructions:
            entry_offset = min(self._instructions) if self._instructions else 0

        initial = ExecutionState(pc=entry_offset, entry_offset=entry_offset)
        queue: list[ExecutionState] = [initial]
        final_states: list[ExecutionState] = []

        while queue and len(final_states) < self.MAX_PATHS:
            state = queue.pop()
            if state.halted:
                final_states.append(state)
                continue

            if state.depth >= self.MAX_DEPTH:
                state.halted = True
                state.error = "maximum depth reached"
                final_states.append(state)
                continue

            instruction = self._instructions.get(state.pc)
            if instruction is None:
                state.halted = True
                state.error = f"invalid pc {state.pc}"
                final_states.append(state)
                continue

            state.path.append(state.pc)
            state.visited_offsets.add(state.pc)
            state.depth += 1
            state.gas_cost += _BASE_GAS.get(instruction.opcode, 1)

            try:
                next_states = self._execute_instruction(state, instruction)
            except IndexError as exc:
                state.halted = True
                state.error = str(exc)
                final_states.append(state)
                continue

            if not next_states:
                final_states.append(state)
                continue

            for next_state in next_states:
                if len(next_state.stack) > self.MAX_STACK:
                    next_state.halted = True
                    next_state.error = f"stack overflow ({len(next_state.stack)} > {self.MAX_STACK})"
                if next_state.halted:
                    final_states.append(next_state)
                elif len(queue) + len(final_states) >= self.MAX_PATHS:
                    next_state.halted = True
                    next_state.error = "maximum paths reached"
                    final_states.append(next_state)
                else:
                    queue.append(next_state)

        if not final_states:
            final_states.append(initial)
        return final_states

    def _execute_instruction(self, state: ExecutionState, instruction: Instruction) -> list[ExecutionState]:
        opcode = instruction.opcode

        if opcode == OpCode.PUSHM1:
            state.push(SymbolicValue(concrete=-1))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.PUSHT:
            state.push(SymbolicValue(concrete=True))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.PUSHF:
            state.push(SymbolicValue(concrete=False))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in {
            OpCode.PUSHINT8,
            OpCode.PUSHINT16,
            OpCode.PUSHINT32,
            OpCode.PUSHINT64,
            OpCode.PUSHINT128,
            OpCode.PUSHINT256,
        }:
            value = int.from_bytes(instruction.operand, "little", signed=True)
            state.push(SymbolicValue(concrete=value))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in {
            OpCode.PUSH0,
            OpCode.PUSH1,
            OpCode.PUSH2,
            OpCode.PUSH3,
            OpCode.PUSH4,
            OpCode.PUSH5,
            OpCode.PUSH6,
            OpCode.PUSH7,
            OpCode.PUSH8,
            OpCode.PUSH9,
            OpCode.PUSH10,
            OpCode.PUSH11,
            OpCode.PUSH12,
            OpCode.PUSH13,
            OpCode.PUSH14,
            OpCode.PUSH15,
            OpCode.PUSH16,
        }:
            pushed = int(opcode) - int(OpCode.PUSH0)
            state.push(SymbolicValue(concrete=pushed))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.PUSHDATA1, OpCode.PUSHDATA2, OpCode.PUSHDATA4):
            length_size = {
                OpCode.PUSHDATA1: 1,
                OpCode.PUSHDATA2: 2,
                OpCode.PUSHDATA4: 4,
            }[opcode]
            payload = instruction.operand[length_size:] if instruction.operand else b""
            state.push(SymbolicValue(concrete=payload))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.NOP:
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.DUP:
            state.push(state.top().clone())
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.DROP:
            state.pop()
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.INITSLOT:
            local_count = instruction.operand[0] if len(instruction.operand) >= 1 else 0
            arg_count = instruction.operand[1] if len(instruction.operand) >= 2 else 0
            for i in range(local_count):
                state.locals[i] = SymbolicValue(name=f"loc{i}")
            for i in range(arg_count):
                state.args[i] = SymbolicValue(name=f"arg{i}")
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in {
            OpCode.LDARG0,
            OpCode.LDARG1,
            OpCode.LDARG2,
            OpCode.LDARG3,
            OpCode.LDARG4,
            OpCode.LDARG5,
            OpCode.LDARG6,
        }:
            arg_index = int(opcode) - int(OpCode.LDARG0)
            state.push(state.args.get(arg_index, SymbolicValue(name=f"arg{arg_index}")).clone())
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.LDARG:
            arg_index = instruction.operand[0] if instruction.operand else 0
            state.push(state.args.get(arg_index, SymbolicValue(name=f"arg{arg_index}")).clone())
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in {
            OpCode.STLOC0,
            OpCode.STLOC1,
            OpCode.STLOC2,
            OpCode.STLOC3,
            OpCode.STLOC4,
            OpCode.STLOC5,
            OpCode.STLOC6,
        }:
            local_index = int(opcode) - int(OpCode.STLOC0)
            state.locals[local_index] = state.pop()
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.STLOC:
            local_index = instruction.operand[0] if instruction.operand else 0
            state.locals[local_index] = state.pop()
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in {
            OpCode.LDLOC0,
            OpCode.LDLOC1,
            OpCode.LDLOC2,
            OpCode.LDLOC3,
            OpCode.LDLOC4,
            OpCode.LDLOC5,
            OpCode.LDLOC6,
        }:
            local_index = int(opcode) - int(OpCode.LDLOC0)
            state.push(state.locals.get(local_index, SymbolicValue(name=f"loc{local_index}")).clone())
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.LDLOC:
            local_index = instruction.operand[0] if instruction.operand else 0
            state.push(state.locals.get(local_index, SymbolicValue(name=f"loc{local_index}")).clone())
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in {
            OpCode.STARG0,
            OpCode.STARG1,
            OpCode.STARG2,
            OpCode.STARG3,
            OpCode.STARG4,
            OpCode.STARG5,
            OpCode.STARG6,
        }:
            arg_index = int(opcode) - int(OpCode.STARG0)
            state.args[arg_index] = state.pop()
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.STARG:
            arg_index = instruction.operand[0] if instruction.operand else 0
            state.args[arg_index] = state.pop()
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.ADD, OpCode.SUB, OpCode.MUL, OpCode.DIV, OpCode.MOD):
            right = state.pop()
            left = state.pop()
            result = self._compute_arithmetic(opcode, left, right)
            if result.get("halt"):
                state.halted = True
                state.error = f"{result['halt']} at 0x{instruction.offset:04X}"
                return [state]
            state.arithmetic_ops.append(
                ArithmeticOp(
                    opcode=opcode.name,
                    offset=instruction.offset,
                    left=left,
                    right=right,
                    overflow_possible=result["overflow"],
                    checked=False,
                )
            )
            state.push(result["value"])
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.JMP, OpCode.JMP_L):
            state.pc = self._jump_target(instruction)
            if state.pc <= instruction.offset:
                state.loops_detected.append(instruction.offset)
            return [state]

        if opcode in (OpCode.JMPIF, OpCode.JMPIF_L, OpCode.JMPIFNOT, OpCode.JMPIFNOT_L):
            cond = state.pop()
            target = self._jump_target(instruction)
            fallthrough = instruction.offset + instruction.size
            jump_if_not = opcode in (OpCode.JMPIFNOT, OpCode.JMPIFNOT_L)
            self._mark_checked_external_call(state, cond)

            is_null = cond.name == "null" and cond.concrete is None
            if cond.concrete is not None or is_null:
                self._mark_enforced_witness(state, cond)
                truthy = False if is_null else bool(cond.concrete)
                if jump_if_not:
                    truthy = not truthy
                state.pc = target if truthy else fallthrough
                if state.pc <= instruction.offset:
                    state.loops_detected.append(instruction.offset)
                return [state]

            self._mark_enforced_witness(state, cond)
            taken = state.clone()
            not_taken = state.clone()
            taken.constraints.append(("branch", instruction.offset, True))
            not_taken.constraints.append(("branch", instruction.offset, False))
            if not jump_if_not:
                taken.pc = target
                not_taken.pc = fallthrough
            else:
                taken.pc = fallthrough
                not_taken.pc = target
            if taken.pc <= instruction.offset:
                taken.loops_detected.append(instruction.offset)
            if not_taken.pc <= instruction.offset:
                not_taken.loops_detected.append(instruction.offset)
            return [taken, not_taken]

        if opcode in {
            OpCode.JMPEQ,
            OpCode.JMPEQ_L,
            OpCode.JMPNE,
            OpCode.JMPNE_L,
            OpCode.JMPGT,
            OpCode.JMPGT_L,
            OpCode.JMPGE,
            OpCode.JMPGE_L,
            OpCode.JMPLT,
            OpCode.JMPLT_L,
            OpCode.JMPLE,
            OpCode.JMPLE_L,
        }:
            right = state.pop()
            left = state.pop()
            self._mark_checked_external_call(state, left)
            self._mark_checked_external_call(state, right)
            self._mark_enforced_witness(state, left)
            self._mark_enforced_witness(state, right)
            target = self._jump_target(instruction)
            fallthrough = instruction.offset + instruction.size
            l_null = left.name == "null" and left.concrete is None
            r_null = right.name == "null" and right.concrete is None
            if (l_null or r_null) and opcode in (
                OpCode.JMPEQ, OpCode.JMPEQ_L, OpCode.JMPNE, OpCode.JMPNE_L,
            ):
                is_eq = opcode in (OpCode.JMPEQ, OpCode.JMPEQ_L)
                if l_null and r_null:
                    comparison = is_eq
                elif (l_null and right.is_concrete()) or (r_null and left.is_concrete()):
                    comparison = not is_eq
                else:
                    comparison = None
            else:
                comparison = self._evaluate_comparison(opcode, left.concrete, right.concrete)

            if comparison is not None:
                state.pc = target if comparison else fallthrough
                if state.pc <= instruction.offset:
                    state.loops_detected.append(instruction.offset)
                return [state]

            taken = state.clone()
            not_taken = state.clone()
            taken.constraints.append(("cmp_branch", opcode.name, instruction.offset, True))
            not_taken.constraints.append(("cmp_branch", opcode.name, instruction.offset, False))
            taken.pc = target
            not_taken.pc = fallthrough
            if taken.pc <= instruction.offset:
                taken.loops_detected.append(instruction.offset)
            if not_taken.pc <= instruction.offset:
                not_taken.loops_detected.append(instruction.offset)
            return [taken, not_taken]

        if opcode in (OpCode.TRY, OpCode.TRY_L):
            return self._handle_try(state, instruction)

        if opcode in (OpCode.ENDTRY, OpCode.ENDTRY_L):
            return self._handle_endtry(state, instruction)

        if opcode == OpCode.ENDFINALLY:
            return self._handle_endfinally(state, instruction)

        if opcode == OpCode.ASSERT:
            cond = state.pop()
            self._mark_checked_external_call(state, cond)
            self._mark_enforced_witness(state, cond)
            is_null = cond.name == "null" and cond.concrete is None
            if is_null or (cond.concrete is not None and not cond.concrete):
                state.halted = True
                state.error = f"assert failed at 0x{instruction.offset:04X}"
                return [state]
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.ABORT:
            state.halted = True
            state.error = f"ABORT at 0x{instruction.offset:04X}"
            state.exception_offsets.append(instruction.offset)
            state.try_stack.clear()
            return [state]

        if opcode == OpCode.ABORTMSG:
            message = state.pop()
            rendered_message = self._coerce_string(message) or "<dynamic-message>"
            state.halted = True
            state.error = f"ABORTMSG at 0x{instruction.offset:04X}: {rendered_message}"
            state.exception_offsets.append(instruction.offset)
            state.try_stack.clear()
            return [state]

        if opcode == OpCode.ASSERTMSG:
            message = state.pop()
            cond = state.pop()
            self._mark_checked_external_call(state, cond)
            self._mark_enforced_witness(state, cond)
            is_null = cond.name == "null" and cond.concrete is None
            if is_null or (cond.concrete is not None and not cond.concrete):
                rendered_message = self._coerce_string(message) or "<dynamic-message>"
                state.halted = True
                state.error = f"ASSERTMSG failed at 0x{instruction.offset:04X}: {rendered_message}"
                return [state]
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.THROW:
            state.exception_offsets.append(instruction.offset)
            return self._raise_exception(state, throw_offset=instruction.offset)

        if opcode == OpCode.SYSCALL:
            return self._handle_syscall(state, instruction)

        if opcode in (OpCode.CALL, OpCode.CALL_L):
            state.call_stack.append(instruction.offset + instruction.size)
            state.max_call_stack_depth = max(state.max_call_stack_depth, len(state.call_stack))
            state.pc = self._jump_target(instruction)
            if state.pc <= instruction.offset:
                state.loops_detected.append(instruction.offset)
            return [state]

        if opcode == OpCode.CALLT:
            return self._handle_call_token(state, instruction)

        if opcode == OpCode.CALLA:
            target = state.pop()
            if isinstance(target.concrete, int):
                state.call_stack.append(instruction.offset + instruction.size)
                state.max_call_stack_depth = max(state.max_call_stack_depth, len(state.call_stack))
                state.pc = target.concrete
                if state.pc <= instruction.offset:
                    state.loops_detected.append(instruction.offset)
                return [state]
            state.halted = True
            state.error = f"CALLA requires concrete target at 0x{instruction.offset:04X}"
            return [state]

        if opcode == OpCode.RET:
            if state.call_stack:
                state.pc = state.call_stack.pop()
            else:
                state.halted = True
            return [state]

        if opcode == OpCode.PUSHNULL:
            state.push(SymbolicValue(concrete=None, name="null"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.PUSHA:
            rel = int.from_bytes(instruction.operand, "little", signed=True) if instruction.operand else 0
            state.push(SymbolicValue(concrete=instruction.offset + rel))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.SWAP:
            b = state.pop()
            a = state.pop()
            state.push(b)
            state.push(a)
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.OVER:
            b = state.pop()
            a = state.pop()
            state.push(a)
            state.push(b)
            state.push(a.clone())
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.NIP:
            top = state.pop()
            state.pop()  # discard second
            state.push(top)
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.CLEAR:
            state.stack.clear()
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.EQUAL, OpCode.NUMEQUAL):
            b = state.pop()
            a = state.pop()
            a_null = a.name == "null" and a.concrete is None
            b_null = b.name == "null" and b.concrete is None
            if a_null and b_null:
                state.push(SymbolicValue(concrete=True))
            elif a_null and b.is_concrete():
                state.push(SymbolicValue(concrete=False))
            elif b_null and a.is_concrete():
                state.push(SymbolicValue(concrete=False))
            elif a.is_concrete() and b.is_concrete():
                state.push(SymbolicValue(concrete=a.concrete == b.concrete))
            else:
                state.push(SymbolicValue(name=f"eq_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.NOTEQUAL, OpCode.NUMNOTEQUAL):
            b = state.pop()
            a = state.pop()
            a_null = a.name == "null" and a.concrete is None
            b_null = b.name == "null" and b.concrete is None
            if a_null and b_null:
                state.push(SymbolicValue(concrete=False))
            elif a_null and b.is_concrete():
                state.push(SymbolicValue(concrete=True))
            elif b_null and a.is_concrete():
                state.push(SymbolicValue(concrete=True))
            elif a.is_concrete() and b.is_concrete():
                state.push(SymbolicValue(concrete=a.concrete != b.concrete))
            else:
                state.push(SymbolicValue(name=f"neq_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.NOT:
            val = state.pop()
            is_null = val.name == "null" and val.concrete is None
            if is_null:
                state.push(SymbolicValue(concrete=True))
            elif val.is_concrete():
                state.push(SymbolicValue(concrete=not val.concrete))
            else:
                state.push(SymbolicValue(name=f"not_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.NZ:
            val = state.pop()
            is_null = val.name == "null" and val.concrete is None
            if is_null:
                state.push(SymbolicValue(concrete=False))
            elif val.is_concrete():
                state.push(SymbolicValue(concrete=bool(val.concrete)))
            else:
                state.push(SymbolicValue(name=f"nz_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.LT, OpCode.GT, OpCode.LE, OpCode.GE):
            b = state.pop()
            a = state.pop()
            if isinstance(a.concrete, int) and isinstance(b.concrete, int):
                result = {OpCode.LT: a.concrete < b.concrete, OpCode.GT: a.concrete > b.concrete,
                          OpCode.LE: a.concrete <= b.concrete, OpCode.GE: a.concrete >= b.concrete}[opcode]
                state.push(SymbolicValue(concrete=result))
            else:
                state.push(SymbolicValue(name=f"cmp_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.SIGN:
            val = state.pop()
            if isinstance(val.concrete, int):
                state.push(SymbolicValue(concrete=(1 if val.concrete > 0 else (-1 if val.concrete < 0 else 0))))
            else:
                state.push(SymbolicValue(name=f"sign_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.NEGATE:
            val = state.pop()
            if isinstance(val.concrete, int):
                state.push(SymbolicValue(concrete=-val.concrete))
            else:
                state.push(SymbolicValue(name=f"neg_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.ABS:
            val = state.pop()
            if isinstance(val.concrete, int):
                state.push(SymbolicValue(concrete=abs(val.concrete)))
            else:
                state.push(SymbolicValue(name=f"abs_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.INC:
            val = state.pop()
            if isinstance(val.concrete, int):
                state.push(SymbolicValue(concrete=val.concrete + 1))
            else:
                state.push(SymbolicValue(name=f"inc_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.DEC:
            val = state.pop()
            if isinstance(val.concrete, int):
                state.push(SymbolicValue(concrete=val.concrete - 1))
            else:
                state.push(SymbolicValue(name=f"dec_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.BOOLAND:
            b = state.pop()
            a = state.pop()
            a_null = a.name == "null" and a.concrete is None
            b_null = b.name == "null" and b.concrete is None
            if a_null or b_null:
                state.push(SymbolicValue(concrete=False))
            elif a.is_concrete() and b.is_concrete():
                state.push(SymbolicValue(concrete=bool(a.concrete) and bool(b.concrete)))
            else:
                state.push(SymbolicValue(name=f"booland_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.BOOLOR:
            b = state.pop()
            a = state.pop()
            a_null = a.name == "null" and a.concrete is None
            b_null = b.name == "null" and b.concrete is None
            if a_null and b_null:
                state.push(SymbolicValue(concrete=False))
            elif a_null:
                if b.is_concrete():
                    state.push(SymbolicValue(concrete=bool(b.concrete)))
                else:
                    state.push(SymbolicValue(name=f"boolor_{instruction.offset}"))
            elif b_null:
                if a.is_concrete():
                    state.push(SymbolicValue(concrete=bool(a.concrete)))
                else:
                    state.push(SymbolicValue(name=f"boolor_{instruction.offset}"))
            elif a.is_concrete() and b.is_concrete():
                state.push(SymbolicValue(concrete=bool(a.concrete) or bool(b.concrete)))
            else:
                state.push(SymbolicValue(name=f"boolor_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.DEPTH:
            state.push(SymbolicValue(concrete=len(state.stack)))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.ISNULL:
            val = state.pop()
            if val.name == "null" and val.concrete is None:
                state.push(SymbolicValue(concrete=True))
            elif val.concrete is not None:
                state.push(SymbolicValue(concrete=False))
            else:
                state.push(SymbolicValue(name=f"isnull_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.SIZE:
            val = state.pop()
            if isinstance(val.concrete, (bytes, str)):
                state.push(SymbolicValue(concrete=len(val.concrete)))
            else:
                state.push(SymbolicValue(name=f"size_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.SHL, OpCode.SHR):
            shift = state.pop()
            val = state.pop()
            if isinstance(val.concrete, int) and isinstance(shift.concrete, int):
                if shift.concrete < 0 or shift.concrete > 256:
                    state.halted = True
                    state.error = f"invalid shift {shift.concrete} at 0x{instruction.offset:04X}"
                    return [state]
                result = val.concrete << shift.concrete if opcode == OpCode.SHL else val.concrete >> shift.concrete
                state.push(SymbolicValue(concrete=result))
            else:
                state.push(SymbolicValue(name=f"{opcode.name.lower()}_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.AND, OpCode.OR, OpCode.XOR):
            b = state.pop()
            a = state.pop()
            if isinstance(a.concrete, int) and isinstance(b.concrete, int):
                result = {OpCode.AND: a.concrete & b.concrete, OpCode.OR: a.concrete | b.concrete,
                          OpCode.XOR: a.concrete ^ b.concrete}[opcode]
                state.push(SymbolicValue(concrete=result))
            else:
                state.push(SymbolicValue(name=f"{opcode.name.lower()}_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.INVERT:
            val = state.pop()
            if isinstance(val.concrete, int):
                state.push(SymbolicValue(concrete=~val.concrete))
            else:
                state.push(SymbolicValue(name=f"invert_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode in (OpCode.MIN, OpCode.MAX):
            b = state.pop()
            a = state.pop()
            if isinstance(a.concrete, int) and isinstance(b.concrete, int):
                state.push(SymbolicValue(concrete=min(a.concrete, b.concrete) if opcode == OpCode.MIN else max(a.concrete, b.concrete)))
            else:
                state.push(SymbolicValue(name=f"{opcode.name.lower()}_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.WITHIN:
            b = state.pop()
            a = state.pop()
            x = state.pop()
            if isinstance(x.concrete, int) and isinstance(a.concrete, int) and isinstance(b.concrete, int):
                state.push(SymbolicValue(concrete=a.concrete <= x.concrete < b.concrete))
            else:
                state.push(SymbolicValue(name=f"within_{instruction.offset}"))
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.ROT:
            c = state.pop()
            b = state.pop()
            a = state.pop()
            state.push(b)
            state.push(c)
            state.push(a)
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.TUCK:
            b = state.pop()
            a = state.pop()
            state.push(b.clone())
            state.push(a)
            state.push(b)
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.REVERSE3:
            c = state.pop()
            b = state.pop()
            a = state.pop()
            state.push(c)
            state.push(b)
            state.push(a)
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.REVERSE4:
            d = state.pop()
            c = state.pop()
            b = state.pop()
            a = state.pop()
            state.push(d)
            state.push(c)
            state.push(b)
            state.push(a)
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.REVERSEN:
            n_val = state.pop()
            n = n_val.concrete if isinstance(n_val.concrete, int) else 0
            if n < 0 or n > len(state.stack):
                state.halted = True
                state.error = f"REVERSEN count {n} invalid at 0x{instruction.offset:04X}"
                return [state]
            items = [state.pop() for _ in range(n)]
            for item in items:
                state.push(item)
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.PICK:
            n_val = state.pop()
            n = n_val.concrete if isinstance(n_val.concrete, int) else 0
            if 0 <= n < len(state.stack):
                state.push(state.stack[-(n + 1)].clone())
            else:
                state.halted = True
                state.error = f"PICK index {n} out of range at 0x{instruction.offset:04X}"
                return [state]
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.ROLL:
            n_val = state.pop()
            n = n_val.concrete if isinstance(n_val.concrete, int) else 0
            if 0 <= n < len(state.stack):
                item = state.stack.pop(-(n + 1))
                state.push(item)
            else:
                state.halted = True
                state.error = f"ROLL index {n} out of range at 0x{instruction.offset:04X}"
                return [state]
            state.pc = instruction.offset + instruction.size
            return [state]

        if opcode == OpCode.XDROP:
            n_val = state.pop()
            n = n_val.concrete if isinstance(n_val.concrete, int) else 0
            if 0 <= n < len(state.stack):
                del state.stack[-(n + 1)]
            else:
                state.halted = True
                state.error = f"XDROP index {n} out of range at 0x{instruction.offset:04X}"
                return [state]
            state.pc = instruction.offset + instruction.size
            return [state]

        # Unknown opcode: track and advance.
        state.unknown_opcodes.append(instruction.offset)
        state.pc = instruction.offset + instruction.size
        return [state]

    def _handle_call_token(self, state: ExecutionState, instruction: Instruction) -> list[ExecutionState]:
        if len(instruction.operand) != 2:
            state.halted = True
            state.error = f"Malformed CALLT operand at 0x{instruction.offset:04X}"
            return [state]

        token_index = int.from_bytes(instruction.operand, "little", signed=False)
        if token_index >= len(self.nef.tokens):
            state.halted = True
            state.error = f"CALLT token index out of range: {token_index}"
            return [state]

        token = self.nef.tokens[token_index]
        state.external_calls.append(
            ExternalCall(
                contract_hash=token.hash,
                method=f"CALLT:{token.method}",
                offset=instruction.offset,
                call_flags=token.call_flags,
                call_flags_dynamic=False,
                has_return_value=token.has_return_value,
            )
        )
        if token.has_return_value:
            state.push(SymbolicValue(name=f"ext_ret_{instruction.offset}", concrete=True))
        state.pc = instruction.offset + instruction.size
        return [state]

    def _handle_syscall(self, state: ExecutionState, instruction: Instruction) -> list[ExecutionState]:
        syscall_id = int.from_bytes(instruction.operand, "little", signed=False) if instruction.operand else 0
        info = SYSCALLS_BY_ID.get(
            syscall_id,
            SyscallInfo(name=f"syscall_0x{syscall_id:08X}", syscall_id=syscall_id, fixed_price=0),
        )
        state.gas_cost += info.fixed_price
        name = info.name

        if name == "System.Runtime.CheckWitness":
            if state.stack:
                _ = state.pop()
            state.witness_checks.append(instruction.offset)
            state.push(SymbolicValue(name=f"witness_ok_{instruction.offset}"))
        elif name == "System.Runtime.GetTime":
            state.time_accesses.append(instruction.offset)
            state.push(SymbolicValue(name="timestamp"))
        elif name == "System.Runtime.GetRandom":
            state.randomness_accesses.append(instruction.offset)
            state.push(SymbolicValue(name="randomness"))
        elif name in {"System.Storage.Put", "System.Storage.Local.Put"}:
            context = state.pop()
            key = state.pop()
            value = state.pop()
            state.storage_ops.append(StorageOp(op_type="put", key=key, value=value, offset=instruction.offset))
            state.locals[0xFFFF] = context
        elif name in {"System.Storage.Get", "System.Storage.Local.Get"}:
            context = state.pop()
            key = state.pop()
            state.storage_ops.append(StorageOp(op_type="get", key=key, offset=instruction.offset))
            state.locals[0xFFFF] = context
            state.push(SymbolicValue(name=f"storage_read_{instruction.offset}"))
        elif name in {"System.Storage.Delete", "System.Storage.Local.Delete"}:
            context = state.pop()
            key = state.pop()
            state.storage_ops.append(StorageOp(op_type="delete", key=key, offset=instruction.offset))
            state.locals[0xFFFF] = context
        elif name == "System.Contract.Call":
            contract_hash = state.pop()
            method_name = state.pop()
            call_flags = state.pop()
            args = state.pop()
            resolved_hash = self._coerce_hash160(contract_hash)
            resolved_method = self._coerce_string(method_name) or "Contract.Call"
            resolved_call_flags = call_flags.concrete if isinstance(call_flags.concrete, int) else None
            state.external_calls.append(
                ExternalCall(
                    contract_hash=resolved_hash,
                    method=f"Contract.Call:{resolved_method}",
                    offset=instruction.offset,
                    target_hash_dynamic=resolved_hash is None,
                    method_dynamic=method_name.concrete is None,
                    call_flags=resolved_call_flags,
                    call_flags_dynamic=not isinstance(call_flags.concrete, int),
                )
            )
            state.locals[0xFFFE] = call_flags
            state.locals[0xFFFD] = args
            state.push(SymbolicValue(name=f"ext_ret_{instruction.offset}", concrete=True))
        elif name.endswith(".Notify"):
            event_name = state.pop() if state.stack else SymbolicValue()
            _ = state.pop() if state.stack else None
            resolved_event = self._coerce_string(event_name) or f"notify@{instruction.offset}"
            state.events_emitted.append(resolved_event)
        elif name.endswith(".Log"):
            if state.stack:
                _ = state.pop()
        else:
            # Unknown or unmodelled syscall: track and preserve stack shape with symbolic result.
            state.unknown_syscalls.append((instruction.offset, name))
            state.push(SymbolicValue(name=name))

        state.pc = instruction.offset + instruction.size
        return [state]

    def _jump_target(self, instruction: Instruction) -> int:
        if not instruction.operand:
            return instruction.offset + instruction.size
        if len(instruction.operand) == 1:
            rel = _to_signed_i8(instruction.operand[0])
        else:
            rel = int.from_bytes(instruction.operand, "little", signed=True)
        return instruction.offset + rel

    def _handle_try(self, state: ExecutionState, instruction: Instruction) -> list[ExecutionState]:
        if instruction.opcode == OpCode.TRY:
            if len(instruction.operand) != 2:
                state.halted = True
                state.error = f"Malformed TRY operand at 0x{instruction.offset:04X}"
                return [state]
            catch_rel = _to_signed_i8(instruction.operand[0])
            finally_rel = _to_signed_i8(instruction.operand[1])
        elif instruction.opcode == OpCode.TRY_L:
            if len(instruction.operand) != 8:
                state.halted = True
                state.error = f"Malformed TRY_L operand at 0x{instruction.offset:04X}"
                return [state]
            catch_rel = int.from_bytes(instruction.operand[:4], "little", signed=True)
            finally_rel = int.from_bytes(instruction.operand[4:], "little", signed=True)
        else:
            state.halted = True
            state.error = f"Invalid TRY opcode at 0x{instruction.offset:04X}"
            return [state]

        catch_offset = instruction.offset + catch_rel if catch_rel != 0 else None
        finally_offset = instruction.offset + finally_rel if finally_rel != 0 else None
        state.try_stack.append(TryFrame(catch_offset=catch_offset, finally_offset=finally_offset))
        state.pc = instruction.offset + instruction.size
        return [state]

    def _handle_endtry(self, state: ExecutionState, instruction: Instruction) -> list[ExecutionState]:
        if not state.try_stack:
            state.halted = True
            state.error = f"ENDTRY without active TRY at 0x{instruction.offset:04X}"
            return [state]

        frame = state.try_stack.pop()
        continuation = self._jump_target(instruction)
        if frame.finally_offset is None:
            state.pc = continuation
            return [state]

        frame.continuation_offset = continuation
        frame.pending_exception = None
        state.try_stack.append(frame)
        state.pc = frame.finally_offset
        return [state]

    def _handle_endfinally(self, state: ExecutionState, instruction: Instruction) -> list[ExecutionState]:
        if not state.try_stack:
            state.halted = True
            state.error = f"ENDFINALLY without active TRY at 0x{instruction.offset:04X}"
            return [state]

        frame = state.try_stack.pop()
        if frame.pending_exception is not None:
            return self._raise_exception(
                state,
                throw_offset=instruction.offset,
                message=frame.pending_exception,
            )

        if frame.continuation_offset is None:
            state.halted = True
            state.error = f"ENDFINALLY without continuation at 0x{instruction.offset:04X}"
            return [state]

        state.pc = frame.continuation_offset
        return [state]

    def _raise_exception(
        self,
        state: ExecutionState,
        throw_offset: int,
        message: str | None = None,
    ) -> list[ExecutionState]:
        exception_message = message or f"Unhandled throw at 0x{throw_offset:04X}"

        while state.try_stack:
            frame = state.try_stack.pop()
            if frame.catch_offset is not None:
                state.pc = frame.catch_offset
                state.error = None
                state.halted = False
                return [state]
            if frame.finally_offset is not None:
                frame.pending_exception = exception_message
                frame.continuation_offset = None
                state.try_stack.append(frame)
                state.pc = frame.finally_offset
                state.error = None
                state.halted = False
                return [state]

        state.halted = True
        state.error = exception_message
        return [state]

    @staticmethod
    def _evaluate_comparison(opcode: OpCode, left: Any, right: Any) -> bool | None:
        if left is None or right is None:
            return None
        try:
            if opcode in (OpCode.JMPEQ, OpCode.JMPEQ_L):
                return left == right
            if opcode in (OpCode.JMPNE, OpCode.JMPNE_L):
                return left != right
            if opcode in (OpCode.JMPGT, OpCode.JMPGT_L):
                return left > right
            if opcode in (OpCode.JMPGE, OpCode.JMPGE_L):
                return left >= right
            if opcode in (OpCode.JMPLT, OpCode.JMPLT_L):
                return left < right
            if opcode in (OpCode.JMPLE, OpCode.JMPLE_L):
                return left <= right
        except TypeError:
            return None
        return None

    @staticmethod
    def _coerce_string(value: SymbolicValue) -> str | None:
        if isinstance(value.concrete, str):
            return value.concrete
        if isinstance(value.concrete, bytes):
            try:
                return value.concrete.decode("utf-8")
            except UnicodeDecodeError:
                return value.concrete.hex()
        if isinstance(value.concrete, int):
            return str(value.concrete)
        return value.name

    @staticmethod
    def _coerce_hash160(value: SymbolicValue) -> bytes | None:
        if isinstance(value.concrete, bytes) and len(value.concrete) == 20:
            return value.concrete
        if isinstance(value.concrete, str):
            raw = value.concrete.lower().removeprefix("0x")
            if len(raw) == 40:
                try:
                    return bytes.fromhex(raw)
                except ValueError:
                    return None
        return None

    @staticmethod
    def _mark_checked_external_call(state: ExecutionState, condition: SymbolicValue) -> None:
        """Mark the specific external call referenced by an assertion condition."""
        if not condition.name:
            return
        if not condition.name.startswith("ext_ret_"):
            return
        try:
            expected_offset = int(condition.name[len("ext_ret_") :])
        except ValueError:
            return

        for call in state.external_calls:
            if call.offset == expected_offset:
                call.return_checked = True
                return

    @staticmethod
    def _mark_enforced_witness(state: ExecutionState, condition: SymbolicValue) -> None:
        """Track witness checks that are consumed by control-flow/assertion enforcement."""
        if not condition.name or not condition.name.startswith("witness_ok_"):
            return
        try:
            witness_offset = int(condition.name[len("witness_ok_") :])
        except ValueError:
            return
        if witness_offset not in state.witness_checks_enforced:
            state.witness_checks_enforced.append(witness_offset)

    def _compute_arithmetic(self, opcode: OpCode, left: SymbolicValue, right: SymbolicValue) -> dict[str, Any]:
        # NeoVM uses arbitrary-precision BigInteger; overflow is only possible
        # when the result exceeds the VM's 32-byte integer limit (±2^255).
        max_magnitude = 1 << (self.WORD_BITS - 1)
        overflow = False
        concrete: int | None = None

        if isinstance(left.concrete, int) and isinstance(right.concrete, int):
            if opcode == OpCode.ADD:
                concrete = left.concrete + right.concrete
            elif opcode == OpCode.SUB:
                concrete = left.concrete - right.concrete
            elif opcode == OpCode.MUL:
                concrete = left.concrete * right.concrete
            elif opcode == OpCode.DIV:
                if right.concrete == 0:
                    return {"value": SymbolicValue(name="div_by_zero"), "overflow": True, "halt": "division by zero"}
                # NeoVM truncates toward zero (Python's int division truncates toward -inf).
                q = int(left.concrete / right.concrete) if (left.concrete ^ right.concrete) < 0 and left.concrete % right.concrete != 0 else left.concrete // right.concrete
                concrete = q
            elif opcode == OpCode.MOD:
                if right.concrete == 0:
                    return {"value": SymbolicValue(name="mod_by_zero"), "overflow": True, "halt": "modulo by zero"}
                # NeoVM truncated modulo: result sign matches dividend (not Python's floored mod).
                q = int(left.concrete / right.concrete) if (left.concrete ^ right.concrete) < 0 and left.concrete % right.concrete != 0 else left.concrete // right.concrete
                concrete = left.concrete - q * right.concrete
            overflow = concrete >= max_magnitude or concrete < -max_magnitude

        return {
            "value": SymbolicValue(
                concrete=concrete,
                name=f"{opcode.name.lower()}_{left.name or 'lhs'}_{right.name or 'rhs'}",
                expr=(opcode.name, left.expr or left.concrete, right.expr or right.concrete),
                taints=set(left.taints | right.taints),
            ),
            "overflow": overflow or not (left.is_concrete() and right.is_concrete()),
        }
