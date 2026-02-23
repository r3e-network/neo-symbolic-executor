"""Symbolic execution state models."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = ["ArithmeticOp", "ExecutionState", "ExternalCall", "StorageOp", "SymbolicValue", "TryFrame"]


@dataclass(slots=True)
class SymbolicValue:
    expr: Any | None = None
    concrete: int | bytes | str | bool | None = None
    name: str | None = None
    taints: set[str] = field(default_factory=set)

    def is_concrete(self) -> bool:
        return self.concrete is not None

    def clone(self) -> SymbolicValue:
        return SymbolicValue(
            expr=self.expr,
            concrete=self.concrete,
            name=self.name,
            taints=set(self.taints),
        )


@dataclass(slots=True)
class StorageOp:
    op_type: str
    key: SymbolicValue
    value: SymbolicValue | None = None
    offset: int = -1

    def clone(self) -> StorageOp:
        return StorageOp(
            op_type=self.op_type,
            key=self.key.clone(),
            value=self.value.clone() if self.value else None,
            offset=self.offset,
        )


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

    def clone(self) -> ExternalCall:
        return ExternalCall(
            contract_hash=self.contract_hash,
            method=self.method,
            offset=self.offset,
            return_checked=self.return_checked,
            target_hash_dynamic=self.target_hash_dynamic,
            method_dynamic=self.method_dynamic,
            call_flags=self.call_flags,
            call_flags_dynamic=self.call_flags_dynamic,
            has_return_value=self.has_return_value,
        )


@dataclass(slots=True)
class ArithmeticOp:
    opcode: str
    offset: int
    left: SymbolicValue
    right: SymbolicValue
    overflow_possible: bool = False
    checked: bool = False

    def clone(self) -> ArithmeticOp:
        return ArithmeticOp(
            opcode=self.opcode,
            offset=self.offset,
            left=self.left.clone(),
            right=self.right.clone(),
            overflow_possible=self.overflow_possible,
            checked=self.checked,
        )


@dataclass(slots=True)
class TryFrame:
    catch_offset: int | None
    finally_offset: int | None
    continuation_offset: int | None = None
    pending_exception: str | None = None

    def clone(self) -> TryFrame:
        return TryFrame(
            catch_offset=self.catch_offset,
            finally_offset=self.finally_offset,
            continuation_offset=self.continuation_offset,
            pending_exception=self.pending_exception,
        )


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
            storage_ops=[op.clone() for op in self.storage_ops],
            external_calls=[call.clone() for call in self.external_calls],
            witness_checks=list(self.witness_checks),
            witness_checks_enforced=list(self.witness_checks_enforced),
            time_accesses=list(self.time_accesses),
            randomness_accesses=list(self.randomness_accesses),
            arithmetic_ops=[op.clone() for op in self.arithmetic_ops],
            loops_detected=list(self.loops_detected),
            events_emitted=list(self.events_emitted),
            exception_offsets=list(self.exception_offsets),
            try_stack=[frame.clone() for frame in self.try_stack],
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
