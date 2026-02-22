"""Symbolic execution state models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class SymbolicValue:
    expr: Any | None = None
    concrete: int | bytes | str | bool | None = None
    name: str | None = None
    taints: set[str] = field(default_factory=set)

    def is_concrete(self) -> bool:
        return self.concrete is not None

    def clone(self) -> SymbolicValue:
        return SymbolicValue(expr=self.expr, concrete=self.concrete, name=self.name, taints=set(self.taints))


@dataclass(slots=True)
class StorageOp:
    op_type: str
    key: SymbolicValue
    value: SymbolicValue | None = None
    offset: int = -1


@dataclass(slots=True)
class ExternalCall:
    contract_hash: bytes | None
    method: str
    offset: int = -1
    return_checked: bool = False
    target_hash_dynamic: bool = False
    method_dynamic: bool = False
    call_flags: int | None = None
    call_flags_dynamic: bool = False
    has_return_value: bool = True


@dataclass(slots=True)
class ArithmeticOp:
    opcode: str
    offset: int
    left: SymbolicValue
    right: SymbolicValue
    overflow_possible: bool = False
    checked: bool = False


@dataclass(slots=True)
class TryFrame:
    catch_offset: int | None
    finally_offset: int | None
    continuation_offset: int | None = None
    pending_exception: str | None = None


@dataclass(slots=True)
class ExecutionState:
    pc: int = 0
    entry_offset: int = 0
    depth: int = 0
    gas_cost: int = 0
    halted: bool = False
    error: str | None = None

    stack: list[SymbolicValue] = field(default_factory=list)
    locals: dict[int, SymbolicValue] = field(default_factory=dict)
    args: dict[int, SymbolicValue] = field(default_factory=dict)
    constraints: list[Any] = field(default_factory=list)
    path: list[int] = field(default_factory=list)
    visited_offsets: set[int] = field(default_factory=set)
    call_stack: list[int] = field(default_factory=list)
    max_call_stack_depth: int = 0

    storage_ops: list[StorageOp] = field(default_factory=list)
    external_calls: list[ExternalCall] = field(default_factory=list)
    witness_checks: list[int] = field(default_factory=list)
    witness_checks_enforced: list[int] = field(default_factory=list)
    time_accesses: list[int] = field(default_factory=list)
    randomness_accesses: list[int] = field(default_factory=list)
    arithmetic_ops: list[ArithmeticOp] = field(default_factory=list)
    loops_detected: list[int] = field(default_factory=list)
    events_emitted: list[str] = field(default_factory=list)
    exception_offsets: list[int] = field(default_factory=list)
    try_stack: list[TryFrame] = field(default_factory=list)

    unknown_opcodes: list[int] = field(default_factory=list)
    unknown_syscalls: list[tuple[int, str]] = field(default_factory=list)
    reentrancy_guard: bool = False

    def clone(self) -> ExecutionState:
        cloned_storage_ops = [
            StorageOp(
                op_type=op.op_type,
                key=op.key.clone(),
                value=op.value.clone() if op.value is not None else None,
                offset=op.offset,
            )
            for op in self.storage_ops
        ]
        cloned_external_calls = [
            ExternalCall(
                contract_hash=bytes(call.contract_hash) if call.contract_hash is not None else None,
                method=call.method,
                offset=call.offset,
                return_checked=call.return_checked,
                target_hash_dynamic=call.target_hash_dynamic,
                method_dynamic=call.method_dynamic,
                call_flags=call.call_flags,
                call_flags_dynamic=call.call_flags_dynamic,
                has_return_value=call.has_return_value,
            )
            for call in self.external_calls
        ]
        cloned_arithmetic_ops = [
            ArithmeticOp(
                opcode=op.opcode,
                offset=op.offset,
                left=op.left.clone(),
                right=op.right.clone(),
                overflow_possible=op.overflow_possible,
                checked=op.checked,
            )
            for op in self.arithmetic_ops
        ]
        return ExecutionState(
            pc=self.pc,
            entry_offset=self.entry_offset,
            depth=self.depth,
            gas_cost=self.gas_cost,
            halted=self.halted,
            error=self.error,
            stack=[v.clone() for v in self.stack],
            locals={k: v.clone() for k, v in self.locals.items()},
            args={k: v.clone() for k, v in self.args.items()},
            constraints=list(self.constraints),
            path=list(self.path),
            visited_offsets=set(self.visited_offsets),
            call_stack=list(self.call_stack),
            max_call_stack_depth=self.max_call_stack_depth,
            storage_ops=cloned_storage_ops,
            external_calls=cloned_external_calls,
            witness_checks=list(self.witness_checks),
            witness_checks_enforced=list(self.witness_checks_enforced),
            time_accesses=list(self.time_accesses),
            randomness_accesses=list(self.randomness_accesses),
            arithmetic_ops=cloned_arithmetic_ops,
            loops_detected=list(self.loops_detected),
            events_emitted=list(self.events_emitted),
            exception_offsets=list(self.exception_offsets),
            try_stack=[
                TryFrame(
                    catch_offset=frame.catch_offset,
                    finally_offset=frame.finally_offset,
                    continuation_offset=frame.continuation_offset,
                    pending_exception=frame.pending_exception,
                )
                for frame in self.try_stack
            ],
            unknown_opcodes=list(self.unknown_opcodes),
            unknown_syscalls=list(self.unknown_syscalls),
            reentrancy_guard=self.reentrancy_guard,
        )

    def push(self, value: SymbolicValue) -> None:
        self.stack.append(value)

    def pop(self) -> SymbolicValue:
        if not self.stack:
            raise IndexError("stack underflow")
        return self.stack.pop()

    def top(self) -> SymbolicValue:
        if not self.stack:
            raise IndexError("stack is empty")
        return self.stack[-1]
