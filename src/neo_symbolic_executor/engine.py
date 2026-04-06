from __future__ import annotations

from dataclasses import dataclass, field

from .expr import (
    BoolConst,
    BytesConst,
    Expression,
    HeapRef,
    IntConst,
    NullConst,
    Sort,
    _int_to_signed_bytes,
    _integer_byte_size,
    bool_const,
    bytes_const,
    bytes_symbol,
    int_const,
    int_symbol,
    is_array_like,
    is_bool,
    is_buffer,
    is_int,
    is_map,
    is_null,
    make_binary,
    make_unary,
    negate,
    null_const,
    render_expr,
    simplify,
    truthy,
)
from .heap import (
    ArrayObject,
    BufferObject,
    HeapObject,
    MapObject,
    StructObject,
    clone_heap_object,
    new_array_ref,
    new_buffer_ref,
    new_map_ref,
    new_struct_ref,
    render_heap_snapshot,
)
from .interop import (
    CALL_FLAGS_ALL,
    DEFAULT_ADDRESS_VERSION,
    DEFAULT_NETWORK_MAGIC,
    INTEROP_BY_ID,
    TRIGGER_APPLICATION,
)
from .model import Instruction, Program
from .opcodes import (
    INTEGER_MAX_SIZE,
    MAX_EVENT_NAME_LENGTH,
    STACK_ITEM_TYPE_ANY,
    STACK_ITEM_TYPE_ARRAY,
    STACK_ITEM_TYPE_BOOLEAN,
    STACK_ITEM_TYPE_BUFFER,
    STACK_ITEM_TYPE_BYTESTRING,
    STACK_ITEM_TYPE_CODE_TO_NAME,
    STACK_ITEM_TYPE_INTEGER,
    STACK_ITEM_TYPE_INTEROP,
    STACK_ITEM_TYPE_MAP,
    STACK_ITEM_TYPE_POINTER,
    STACK_ITEM_TYPE_STRUCT,
    VALID_STACK_ITEM_TYPES,
)


@dataclass(frozen=True)
class ExecutionOptions:
    max_steps: int = 256
    max_states: int = 512
    max_visits_per_instruction: int = 12
    initial_stack: tuple[Expression, ...] = ()
    max_item_size: int = 1_048_576
    max_collection_size: int = 16_384
    max_heap_objects: int = 4_096
    max_invocation_stack: int = 1_024
    max_try_nesting_depth: int = 16
    max_shift: int = 256
    max_stack_depth: int = 1024
    trigger: int = TRIGGER_APPLICATION
    network_magic: int = DEFAULT_NETWORK_MAGIC
    address_version: int = DEFAULT_ADDRESS_VERSION
    call_flags: int = CALL_FLAGS_ALL
    script_hash: bytes | None = None
    gas_left: int | None = None
    time: int | None = None

    def __post_init__(self) -> None:
        if self.max_steps <= 0:
            raise ValueError("max_steps must be positive")
        if self.max_states <= 0:
            raise ValueError("max_states must be positive")
        if self.max_visits_per_instruction <= 0:
            raise ValueError("max_visits_per_instruction must be positive")
        if self.max_item_size <= 0:
            raise ValueError("max_item_size must be positive")
        if self.max_collection_size <= 0:
            raise ValueError("max_collection_size must be positive")
        if self.max_heap_objects <= 0:
            raise ValueError("max_heap_objects must be positive")
        if self.max_invocation_stack <= 0:
            raise ValueError("max_invocation_stack must be positive")
        if self.max_try_nesting_depth <= 0:
            raise ValueError("max_try_nesting_depth must be positive")
        if self.max_shift <= 0:
            raise ValueError("max_shift must be positive")
        if self.max_stack_depth <= 0:
            raise ValueError("max_stack_depth must be positive")
        if not 0 <= self.trigger <= 0xFF:
            raise ValueError("trigger must fit in one byte")
        if not 0 <= self.network_magic <= 0xFFFFFFFF:
            raise ValueError("network_magic must fit in uint32")
        if not 0 <= self.address_version <= 0xFF:
            raise ValueError("address_version must fit in one byte")
        if not 0 <= self.call_flags <= 0x0F:
            raise ValueError("call_flags must fit in Neo CallFlags")
        if self.script_hash is not None and len(self.script_hash) != 20:
            raise ValueError("script_hash must be exactly 20 bytes")
        if self.gas_left is not None and self.gas_left < 0:
            raise ValueError("gas_left must be non-negative")
        if self.time is not None and self.time < 0:
            raise ValueError("time must be non-negative")
        if len(self.initial_stack) > self.max_stack_depth:
            raise ValueError("initial_stack length exceeds max_stack_depth")


@dataclass
class ExceptionHandler:
    catch_ip: int | None
    finally_ip: int | None
    end_ip: int | None = None
    state: str = "try"

    def clone(self) -> ExceptionHandler:
        return ExceptionHandler(
            catch_ip=self.catch_ip,
            finally_ip=self.finally_ip,
            end_ip=self.end_ip,
            state=self.state,
        )


@dataclass
class CallFrame:
    return_ip: int
    arguments: list[Expression] | None
    local_variables: list[Expression] | None
    try_stack: list[ExceptionHandler] = field(default_factory=list)

    def clone(self) -> CallFrame:
        return CallFrame(
            return_ip=self.return_ip,
            arguments=None if self.arguments is None else list(self.arguments),
            local_variables=None if self.local_variables is None else list(self.local_variables),
            try_stack=[handler.clone() for handler in self.try_stack],
        )


@dataclass(frozen=True)
class TerminalState:
    status: str
    reason: str | None
    ip: int
    call_depth: int
    steps: int
    stack: tuple[Expression, ...]
    arguments: tuple[Expression, ...] | None
    local_variables: tuple[Expression, ...] | None
    static_fields: tuple[Expression, ...] | None
    call_stack: tuple[tuple[int, tuple[Expression, ...] | None, tuple[Expression, ...] | None], ...]
    heap: dict[str, object]
    path_conditions: tuple[Expression, ...]
    trace: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "ip": self.ip,
            "call_depth": self.call_depth,
            "steps": self.steps,
            "stack": [render_expr(item) for item in self.stack],
            "arguments": [render_expr(item) for item in self.arguments] if self.arguments is not None else None,
            "local_variables": [render_expr(item) for item in self.local_variables]
            if self.local_variables is not None
            else None,
            "static_fields": [render_expr(item) for item in self.static_fields]
            if self.static_fields is not None
            else None,
            "call_stack": [
                {
                    "return_ip": return_ip,
                    "arguments": None if arguments is None else [render_expr(item) for item in arguments],
                    "local_variables": None
                    if local_variables is None
                    else [render_expr(item) for item in local_variables],
                }
                for return_ip, arguments, local_variables in self.call_stack
            ],
            "heap": self.heap,
            "path_conditions": [render_expr(cond) for cond in self.path_conditions],
            "trace": list(self.trace),
        }


@dataclass(frozen=True)
class ExecutionReport:
    returned: tuple[TerminalState, ...]
    faulted: tuple[TerminalState, ...]
    stopped: tuple[TerminalState, ...]
    explored_states: int

    def to_dict(self) -> dict[str, object]:
        return {
            "explored_states": self.explored_states,
            "returned": [state.to_dict() for state in self.returned],
            "faulted": [state.to_dict() for state in self.faulted],
            "stopped": [state.to_dict() for state in self.stopped],
        }


@dataclass
class State:
    ip: int = 0
    steps: int = 0
    stack: list[Expression] = field(default_factory=list)
    max_item_size: int = 1_048_576
    max_collection_size: int = 16_384
    max_heap_objects: int = 4_096
    max_invocation_stack: int = 1_024
    max_try_nesting_depth: int = 16
    max_shift: int = 256
    max_stack_depth: int = 1024
    trigger: int = TRIGGER_APPLICATION
    network_magic: int = DEFAULT_NETWORK_MAGIC
    address_version: int = DEFAULT_ADDRESS_VERSION
    call_flags: int = CALL_FLAGS_ALL
    script_hash: bytes | None = None
    gas_left: int | None = None
    time: int | None = None
    arguments: list[Expression] | None = None
    local_variables: list[Expression] | None = None
    static_fields: list[Expression] | None = None
    try_stack: list[ExceptionHandler] = field(default_factory=list)
    uncaught_exception: Expression | None = None
    call_stack: list[CallFrame] = field(default_factory=list)
    heap: dict[int, HeapObject] = field(default_factory=dict)
    next_heap_id: int = 1
    path_conditions: list[Expression] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    visit_counts: dict[int, int] = field(default_factory=dict)

    def clone(self) -> State:
        return State(
            ip=self.ip,
            steps=self.steps,
            stack=list(self.stack),
            max_item_size=self.max_item_size,
            max_collection_size=self.max_collection_size,
            max_heap_objects=self.max_heap_objects,
            max_invocation_stack=self.max_invocation_stack,
            max_try_nesting_depth=self.max_try_nesting_depth,
            max_shift=self.max_shift,
            max_stack_depth=self.max_stack_depth,
            trigger=self.trigger,
            network_magic=self.network_magic,
            address_version=self.address_version,
            call_flags=self.call_flags,
            script_hash=self.script_hash,
            gas_left=self.gas_left,
            time=self.time,
            arguments=None if self.arguments is None else list(self.arguments),
            local_variables=None if self.local_variables is None else list(self.local_variables),
            static_fields=None if self.static_fields is None else list(self.static_fields),
            try_stack=[handler.clone() for handler in self.try_stack],
            uncaught_exception=self.uncaught_exception,
            call_stack=[frame.clone() for frame in self.call_stack],
            heap={object_id: clone_heap_object(obj) for object_id, obj in self.heap.items()},
            next_heap_id=self.next_heap_id,
            path_conditions=list(self.path_conditions),
            trace=list(self.trace),
            visit_counts=dict(self.visit_counts),
        )


class ExecutionLimitExceeded(ValueError):
    pass


def explore_program(program: Program, options: ExecutionOptions | None = None) -> ExecutionReport:
    options = options or ExecutionOptions()
    initial_state = State(
        stack=list(options.initial_stack),
        max_item_size=options.max_item_size,
        max_collection_size=options.max_collection_size,
        max_heap_objects=options.max_heap_objects,
        max_invocation_stack=options.max_invocation_stack,
        max_try_nesting_depth=options.max_try_nesting_depth,
        max_shift=options.max_shift,
        max_stack_depth=options.max_stack_depth,
        trigger=options.trigger,
        network_magic=options.network_magic,
        address_version=options.address_version,
        call_flags=options.call_flags,
        script_hash=options.script_hash,
        gas_left=options.gas_left,
        time=options.time,
    )
    worklist: list[State] = [initial_state]
    returned: list[TerminalState] = []
    faulted: list[TerminalState] = []
    stopped: list[TerminalState] = []
    explored_states = 0
    seen_signatures: set[tuple[object, ...]] = set()

    while worklist:
        state = worklist.pop()
        if explored_states >= options.max_states:
            stopped.append(_terminal(state, "stopped", f"state budget {options.max_states} exhausted"))
            continue

        if state.steps >= options.max_steps:
            stopped.append(_terminal(state, "stopped", f"step budget {options.max_steps} exhausted"))
            continue

        if not program.has_offset(state.ip):
            faulted.append(
                _terminal(
                    state,
                    "faulted",
                    f"instruction pointer {state.ip} is not a valid instruction offset",
                )
            )
            continue

        visit_count = state.visit_counts.get(state.ip, 0) + 1
        if visit_count > options.max_visits_per_instruction:
            stopped.append(
                _terminal(
                    state,
                    "stopped",
                    f"visit budget {options.max_visits_per_instruction} exceeded at offset {state.ip}",
                )
            )
            continue

        state.visit_counts[state.ip] = visit_count
        signature = _signature(state)
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        explored_states += 1

        instruction = program.instruction_at_offset(state.ip)
        state.trace.append(_trace_entry(instruction))
        state.steps += 1

        try:
            next_states, terminal = _execute_instruction(state, instruction, program)
        except ExecutionLimitExceeded as exc:
            stopped.append(_terminal(state, "stopped", str(exc)))
            continue
        worklist.extend(next_states)
        if terminal is not None:
            if terminal.status == "returned":
                returned.append(terminal)
            elif terminal.status == "faulted":
                faulted.append(terminal)
            else:
                stopped.append(terminal)

    return ExecutionReport(
        returned=tuple(returned),
        faulted=tuple(faulted),
        stopped=tuple(stopped),
        explored_states=explored_states,
    )


def _execute_instruction(
    state: State,
    instruction: Instruction,
    program: Program,
) -> tuple[list[State], TerminalState | None]:
    opcode = instruction.opcode

    if opcode in {"NOP"}:
        state.ip = instruction.end_offset
        return [state], None

    if opcode in {
        "PUSHM1",
        "PUSH0",
        "PUSH1",
        "PUSH2",
        "PUSH3",
        "PUSH4",
        "PUSH5",
        "PUSH6",
        "PUSH7",
        "PUSH8",
        "PUSH9",
        "PUSH10",
        "PUSH11",
        "PUSH12",
        "PUSH13",
        "PUSH14",
        "PUSH15",
        "PUSH16",
        "PUSHINT8",
        "PUSHINT16",
        "PUSHINT32",
        "PUSHINT64",
        "PUSHINT128",
        "PUSHINT256",
    }:
        terminal = _push(state, int_const(int(instruction.argument)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "PUSHT":
        terminal = _push(state, bool_const(True), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "PUSHF":
        terminal = _push(state, bool_const(False), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "PUSHNULL":
        terminal = _push(state, null_const(), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode in {"PUSHDATA1", "PUSHDATA2", "PUSHDATA4"}:
        terminal = _push(state, bytes_const(bytes(instruction.argument)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "PUSHA":
        terminal = _push(state, int_const(int(instruction.target or instruction.argument)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "NEWARRAY0":
        terminal = _push(state, _alloc_array(state, []), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "NEWSTRUCT0":
        terminal = _push(state, _alloc_struct(state, []), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "NEWMAP":
        terminal = _push(state, _alloc_map(state, []), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "NEWBUFFER":
        return _execute_splice_op(state, opcode, instruction)

    if opcode in {"NEWARRAY", "NEWSTRUCT", "NEWARRAY_T"}:
        count_value = _pop(state)
        if isinstance(count_value, TerminalState):
            return [], count_value
        count = _require_concrete_index(count_value, state, opcode)
        if isinstance(count, TerminalState):
            return [], count
        if count < 0:
            return [], _terminal(state, "faulted", f"{opcode} size {count} is invalid")
        if opcode == "NEWARRAY_T":
            try:
                fill = _default_value_for_stack_item_type(int(instruction.argument))
            except ValueError as exc:
                return [], _terminal(state, "faulted", str(exc))
            terminal = _push(state, _alloc_array(state, [fill for _ in range(count)]), opcode)
            if isinstance(terminal, TerminalState):
                return [], terminal
        elif opcode == "NEWARRAY":
            terminal = _push(state, _alloc_array(state, [null_const() for _ in range(count)]), opcode)
            if isinstance(terminal, TerminalState):
                return [], terminal
        else:
            terminal = _push(state, _alloc_struct(state, [null_const() for _ in range(count)]), opcode)
            if isinstance(terminal, TerminalState):
                return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode in {"PACK", "PACKSTRUCT"}:
        count_value = _pop(state)
        if isinstance(count_value, TerminalState):
            return [], count_value
        count = _require_concrete_index(count_value, state, opcode)
        if isinstance(count, TerminalState):
            return [], count
        if count < 0 or count > len(state.stack):
            return [], _terminal(state, "faulted", f"{opcode} size {count} is out of range")
        elements: list[Expression] = []
        for _ in range(count):
            item = _pop(state)
            if isinstance(item, TerminalState):
                return [], item
            elements.append(item)
        collection = _alloc_struct(state, elements) if opcode == "PACKSTRUCT" else _alloc_array(state, elements)
        terminal = _push(state, collection, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "PACKMAP":
        count_value = _pop(state)
        if isinstance(count_value, TerminalState):
            return [], count_value
        count = _require_concrete_index(count_value, state, opcode)
        if isinstance(count, TerminalState):
            return [], count
        if count < 0 or count * 2 > len(state.stack):
            return [], _terminal(state, "faulted", f"{opcode} size {count} is out of range")
        pairs: list[tuple[Expression, Expression]] = []
        for _ in range(count):
            key = _pop(state)
            if isinstance(key, TerminalState):
                return [], key
            value = _pop(state)
            if isinstance(value, TerminalState):
                return [], value
            key = _require_map_key(key, state, opcode)
            if isinstance(key, TerminalState):
                return [], key
            pairs.append((key, value))
        map_ref = _alloc_map(state, [])
        states: list[State] = [state]
        for key, value in pairs:
            next_states: list[State] = []
            for branch_state in states:
                obj = _require_heap_object(branch_state, map_ref, opcode)
                if isinstance(obj, TerminalState):
                    return [], obj
                assert isinstance(obj, MapObject)
                matches, miss_state, terminal = _branch_map_matches(branch_state, obj, key, opcode)
                if terminal is not None:
                    return [], terminal
                for match_state, index in matches:
                    match_obj = _require_heap_object(match_state, map_ref, opcode)
                    if isinstance(match_obj, TerminalState):
                        return [], match_obj
                    assert isinstance(match_obj, MapObject)
                    existing_key, _existing_value = match_obj.entries[index]
                    match_obj.entries[index] = (existing_key, value)
                    next_states.append(match_state)
                if miss_state is not None:
                    miss_obj = _require_heap_object(miss_state, map_ref, opcode)
                    if isinstance(miss_obj, TerminalState):
                        return [], miss_obj
                    assert isinstance(miss_obj, MapObject)
                    _assert_collection_growth(miss_state, len(miss_obj.entries), "map")
                    miss_obj.entries.append((key, value))
                    next_states.append(miss_state)
            if not next_states:
                return [], _terminal(state, "stopped", f"{opcode} branches were unsatisfiable")
            states = next_states
        for branch_state in states:
            terminal = _push(branch_state, map_ref, opcode)
            if isinstance(terminal, TerminalState):
                return [], terminal
            branch_state.ip = instruction.end_offset
        return states, None

    if opcode == "UNPACK":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        obj = _require_heap_object(state, value, opcode)
        if isinstance(obj, TerminalState):
            return [], obj
        if isinstance(obj, MapObject):
            for key, item in reversed(obj.entries):
                terminal = _push(state, item, opcode)
                if isinstance(terminal, TerminalState):
                    return [], terminal
                terminal = _push(state, key, opcode)
                if isinstance(terminal, TerminalState):
                    return [], terminal
            terminal = _push(state, int_const(len(obj.entries)), opcode)
            if isinstance(terminal, TerminalState):
                return [], terminal
        elif isinstance(obj, (ArrayObject, StructObject)):
            for item in reversed(obj.elements):
                terminal = _push(state, item, opcode)
                if isinstance(terminal, TerminalState):
                    return [], terminal
            terminal = _push(state, int_const(len(obj.elements)), opcode)
            if isinstance(terminal, TerminalState):
                return [], terminal
        else:
            return [], _terminal(state, "faulted", f"{opcode} expects a compound type")
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "DEPTH":
        terminal = _push(state, int_const(len(state.stack)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "DROP":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "NIP":
        if len(state.stack) < 2:
            return [], _terminal(state, "faulted", "stack underflow")
        top = state.stack.pop()
        state.stack.pop()
        terminal = _push(state, top, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "XDROP":
        index_value = _pop(state)
        if isinstance(index_value, TerminalState):
            return [], index_value
        index = _require_concrete_index(index_value, state, opcode)
        if isinstance(index, TerminalState):
            return [], index
        depth_index = len(state.stack) - 1 - index
        if depth_index < 0 or depth_index >= len(state.stack):
            return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
        del state.stack[depth_index]
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "CLEAR":
        state.stack.clear()
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "DUP":
        value = _peek(state)
        if isinstance(value, TerminalState):
            return [], value
        terminal = _push(state, value, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "OVER":
        if len(state.stack) < 2:
            return [], _terminal(state, "faulted", "stack underflow")
        terminal = _push(state, state.stack[-2], opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "PICK":
        index_value = _pop(state)
        if isinstance(index_value, TerminalState):
            return [], index_value
        index = _require_concrete_index(index_value, state, opcode)
        if isinstance(index, TerminalState):
            return [], index
        depth_index = len(state.stack) - 1 - index
        if depth_index < 0 or depth_index >= len(state.stack):
            return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
        terminal = _push(state, state.stack[depth_index], opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "TUCK":
        if len(state.stack) < 2:
            return [], _terminal(state, "faulted", "stack underflow")
        state.stack.insert(len(state.stack) - 2, state.stack[-1])
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "SWAP":
        if len(state.stack) < 2:
            return [], _terminal(state, "faulted", "stack underflow")
        state.stack[-1], state.stack[-2] = state.stack[-2], state.stack[-1]
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "ROT":
        if len(state.stack) < 3:
            return [], _terminal(state, "faulted", "stack underflow")
        state.stack[-3], state.stack[-2], state.stack[-1] = state.stack[-2], state.stack[-1], state.stack[-3]
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "ROLL":
        index_value = _pop(state)
        if isinstance(index_value, TerminalState):
            return [], index_value
        index = _require_concrete_index(index_value, state, opcode)
        if isinstance(index, TerminalState):
            return [], index
        depth_index = len(state.stack) - 1 - index
        if depth_index < 0 or depth_index >= len(state.stack):
            return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
        terminal = _push(state, state.stack.pop(depth_index), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "REVERSE3":
        if len(state.stack) < 3:
            return [], _terminal(state, "faulted", "stack underflow")
        state.stack[-3:] = reversed(state.stack[-3:])
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "REVERSE4":
        if len(state.stack) < 4:
            return [], _terminal(state, "faulted", "stack underflow")
        state.stack[-4:] = reversed(state.stack[-4:])
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "REVERSEN":
        count_value = _pop(state)
        if isinstance(count_value, TerminalState):
            return [], count_value
        count = _require_concrete_index(count_value, state, opcode)
        if isinstance(count, TerminalState):
            return [], count
        if count < 0 or count > len(state.stack):
            return [], _terminal(state, "faulted", f"{opcode} count {count} is out of range")
        if count == 0:
            state.ip = instruction.end_offset
            return [state], None
        state.stack[-count:] = reversed(state.stack[-count:])
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "INITSSLOT":
        count = int(instruction.argument)
        if state.static_fields is not None:
            return [], _terminal(state, "faulted", f"{opcode} cannot be executed twice")
        if count <= 0:
            return [], _terminal(state, "faulted", f"{opcode} requires a positive slot count")
        state.static_fields = [null_const() for _ in range(count)]
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "INITSLOT":
        local_count, argument_count = instruction.argument
        if state.local_variables is not None or state.arguments is not None:
            return [], _terminal(state, "faulted", f"{opcode} cannot be executed twice")
        if local_count == 0 and argument_count == 0:
            return [], _terminal(state, "faulted", f"{opcode} requires locals or arguments")
        if local_count > 0:
            state.local_variables = [null_const() for _ in range(local_count)]
        if argument_count > 0:
            arguments: list[Expression] = []
            for _ in range(argument_count):
                item = _pop(state)
                if isinstance(item, TerminalState):
                    return [], item
                arguments.append(item)
            state.arguments = arguments
        state.ip = instruction.end_offset
        return [state], None

    if opcode.startswith("LD") and opcode.startswith(("LDARG", "LDLOC", "LDSFLD")):
        slots = _slot_list(state, opcode)
        if isinstance(slots, TerminalState):
            return [], slots
        index = int(instruction.argument)
        if index < 0 or index >= len(slots):
            return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
        terminal = _push(state, slots[index], opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode.startswith("ST") and opcode.startswith(("STARG", "STLOC", "STSFLD")):
        slots = _slot_list(state, opcode)
        if isinstance(slots, TerminalState):
            return [], slots
        index = int(instruction.argument)
        if index < 0 or index >= len(slots):
            return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        slots[index] = value
        state.ip = instruction.end_offset
        return [state], None

    if opcode in {"JMP", "JMP_L"}:
        state.ip = _require_target(instruction)
        return [state], None

    if opcode in {"JMPIF", "JMPIF_L", "JMPIFNOT", "JMPIFNOT_L"}:
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        condition = truthy(value)
        if opcode in {"JMPIFNOT", "JMPIFNOT_L"}:
            condition = negate(condition)
        return _branch_on_condition(state, condition, _require_target(instruction), instruction.end_offset)

    if opcode in {
        "JMPEQ",
        "JMPEQ_L",
        "JMPNE",
        "JMPNE_L",
        "JMPGT",
        "JMPGT_L",
        "JMPGE",
        "JMPGE_L",
        "JMPLT",
        "JMPLT_L",
        "JMPLE",
        "JMPLE_L",
    }:
        values = _pop2(state)
        if isinstance(values, TerminalState):
            return [], values
        left, right = values
        operation = {
            "JMPEQ": "==",
            "JMPEQ_L": "==",
            "JMPNE": "!=",
            "JMPNE_L": "!=",
            "JMPGT": ">",
            "JMPGT_L": ">",
            "JMPGE": ">=",
            "JMPGE_L": ">=",
            "JMPLT": "<",
            "JMPLT_L": "<",
            "JMPLE": "<=",
            "JMPLE_L": "<=",
        }[opcode]
        try:
            condition = make_binary(operation, left, right)
        except TypeError as exc:
            return [], _terminal(state, "faulted", str(exc))
        return _branch_on_condition(state, condition, _require_target(instruction), instruction.end_offset)

    if opcode == "ASSERT":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        return _assert_condition(state, truthy(value), instruction.end_offset)

    if opcode == "ABORT":
        return [], _terminal(state, "faulted", "ABORT executed")

    if opcode == "ABORTMSG":
        message = _pop(state)
        if isinstance(message, TerminalState):
            return [], message
        return [], _terminal(state, "faulted", f"ABORTMSG executed: {_render_message(message)}")

    if opcode in {"CALL", "CALL_L"}:
        frame_error = _push_call_frame(state, instruction.end_offset)
        if frame_error is not None:
            return [], frame_error
        state.ip = _require_target(instruction)
        return [state], None

    if opcode == "CALLA":
        pointer = _pop(state)
        if isinstance(pointer, TerminalState):
            return [], pointer
        if not isinstance(pointer, IntConst):
            return _execute_symbolic_calla(state, instruction, program, pointer)
        if not program.has_offset(pointer.value):
            return [], _terminal(state, "faulted", f"CALLA target {pointer.value} is not a valid instruction offset")
        frame_error = _push_call_frame(state, instruction.end_offset)
        if frame_error is not None:
            return [], frame_error
        state.ip = pointer.value
        return [state], None

    if opcode == "RET":
        if not state.call_stack:
            return [], _terminal(state, "returned", None)
        _restore_call_frame(state, state.call_stack.pop())
        return [state], None

    if opcode == "THROW":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        return _execute_throw(state, value)

    if opcode in {"TRY", "TRY_L"}:
        catch_offset, finally_offset = instruction.argument
        if catch_offset == 0 and finally_offset == 0:
            return [], _terminal(state, "faulted", "TRY requires a catch or finally target")
        if len(state.try_stack) >= state.max_try_nesting_depth:
            return [], _terminal(state, "faulted", f"try nesting depth exceeds limit {state.max_try_nesting_depth}")
        catch_ip = _resolve_exception_target(state, program, instruction, catch_offset, opcode, "catch")
        if isinstance(catch_ip, TerminalState):
            return [], catch_ip
        finally_ip = _resolve_exception_target(state, program, instruction, finally_offset, opcode, "finally")
        if isinstance(finally_ip, TerminalState):
            return [], finally_ip
        state.try_stack.append(ExceptionHandler(catch_ip=catch_ip, finally_ip=finally_ip))
        state.ip = instruction.end_offset
        return [state], None

    if opcode in {"ENDTRY", "ENDTRY_L"}:
        if not state.try_stack:
            return [], _terminal(state, "faulted", "ENDTRY requires an active TRY block")
        current_try = state.try_stack[-1]
        if current_try.state == "finally":
            return [], _terminal(state, "faulted", "ENDTRY cannot execute inside a FINALLY block")
        end_ip = _require_target(instruction)
        if current_try.finally_ip is not None:
            current_try.state = "finally"
            current_try.end_ip = end_ip
            state.ip = current_try.finally_ip
        else:
            state.try_stack.pop()
            state.ip = end_ip
        return [state], None

    if opcode == "ENDFINALLY":
        if not state.try_stack:
            return [], _terminal(state, "faulted", "ENDFINALLY requires an active FINALLY block")
        current_try = state.try_stack.pop()
        if state.uncaught_exception is None:
            if current_try.end_ip is None or not program.has_offset(current_try.end_ip):
                return [], _terminal(state, "faulted", "ENDFINALLY is missing an ENDTRY target")
            state.ip = current_try.end_ip
            return [state], None
        return _execute_throw(state, state.uncaught_exception)

    if opcode == "CALLT":
        token_id = int(instruction.argument)
        method_tokens = program.metadata.get("method_tokens")
        if not isinstance(method_tokens, list):
            return [], _terminal(
                state,
                "stopped",
                f"CALLT token {token_id} requires NEF method-token metadata and external contract context",
            )
        if token_id >= len(method_tokens):
            return [], _terminal(state, "faulted", f"CALLT token {token_id} is not defined in NEF metadata")
        token = method_tokens[token_id]
        return [], _terminal(
            state,
            "stopped",
            "CALLT token "
            f"{token_id} targets {token['hash']}::{token['method']} "
            f"({token['parameters_count']} params, return={token['has_return_value']}, flags={token['call_flags']}) "
            "and requires contract-dispatch context",
        )

    if opcode == "SYSCALL":
        return _execute_syscall(state, instruction)

    if opcode in {"MEMCPY", "CAT", "SUBSTR", "LEFT", "RIGHT"}:
        return _execute_splice_op(state, opcode, instruction)

    if opcode in {
        "SIZE",
        "HASKEY",
        "KEYS",
        "VALUES",
        "PICKITEM",
        "APPEND",
        "SETITEM",
        "REVERSEITEMS",
        "REMOVE",
        "CLEARITEMS",
        "POPITEM",
        "ISNULL",
        "ISTYPE",
        "CONVERT",
    }:
        return _execute_compound_or_type_op(state, opcode, instruction)

    if opcode == "ASSERTMSG":
        message = _pop(state)
        if isinstance(message, TerminalState):
            return [], message
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        return _assert_condition(
            state,
            truthy(value),
            instruction.end_offset,
            f"ASSERTMSG failed: {_render_message(message)}",
        )

    if opcode in {"INVERT", "SIGN", "ABS", "NEGATE", "INC", "DEC", "NOT", "NZ", "SQRT"}:
        return _execute_unary_op(state, opcode, instruction)

    if opcode in {
        "AND",
        "OR",
        "XOR",
        "EQUAL",
        "NOTEQUAL",
        "ADD",
        "SUB",
        "MUL",
        "DIV",
        "MOD",
        "POW",
        "SHL",
        "SHR",
        "BOOLAND",
        "BOOLOR",
        "NUMEQUAL",
        "NUMNOTEQUAL",
        "LT",
        "LE",
        "GT",
        "GE",
        "MIN",
        "MAX",
    }:
        return _execute_binary_op(state, opcode, instruction)

    if opcode in {"MODMUL", "MODPOW"}:
        return _execute_ternary_numeric_op(state, opcode, instruction)

    if opcode == "WITHIN":
        return _execute_within(state, instruction)

    return [], _terminal(state, "faulted", f"unsupported opcode {opcode}")


def _execute_unary_op(state: State, opcode: str, instruction: Instruction) -> tuple[list[State], TerminalState | None]:
    value = _pop(state)
    if isinstance(value, TerminalState):
        return [], value
    if opcode == "SQRT":
        return _execute_sqrt_op(state, instruction, value)

    try:
        if opcode == "INVERT":
            result = make_unary("invert", value)
        elif opcode == "SIGN":
            result = make_unary("sign", value)
        elif opcode == "ABS":
            result = make_unary("abs", value)
        elif opcode == "NEGATE":
            result = make_unary("neg", value)
        elif opcode == "INC":
            if not is_int(value):
                raise TypeError("INC expects an integer operand")
            result = make_binary("+", value, int_const(1))
        elif opcode == "DEC":
            if not is_int(value):
                raise TypeError("DEC expects an integer operand")
            result = make_binary("-", value, int_const(1))
        elif opcode == "NOT":
            result = negate(truthy(value))
        else:
            result = truthy(value)
    except TypeError as exc:
        return [], _terminal(state, "faulted", str(exc))

    integer_limit = _ensure_vm_integer_limit(state, result, opcode)
    if integer_limit is not None:
        return [], integer_limit
    terminal = _push(state, result, opcode)
    if isinstance(terminal, TerminalState):
        return [], terminal
    state.ip = instruction.end_offset
    return [state], None


def _execute_sqrt_op(
    state: State,
    instruction: Instruction,
    value: Expression,
) -> tuple[list[State], TerminalState | None]:
    if not is_int(value):
        return [], _terminal(state, "faulted", "SQRT expects an integer operand")
    if isinstance(value, IntConst):
        if value.value < 0:
            return [], _terminal(state, "faulted", "value can not be negative")
        result = int_const(_integer_sqrt(value.value))
        integer_limit = _ensure_vm_integer_limit(state, result, "SQRT")
        if integer_limit is not None:
            return [], integer_limit
        terminal = _push(state, result, "SQRT")
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    non_negative = make_binary(">=", value, int_const(0))
    negative = make_binary("<", value, int_const(0))
    valid_state = state.clone()
    invalid_state = state.clone()
    next_states: list[State] = []
    if _append_condition(valid_state, non_negative):
        result = make_unary("sqrt", value)
        integer_limit = _ensure_vm_integer_limit(valid_state, result, "SQRT")
        if integer_limit is not None:
            return [], integer_limit
        terminal = _push(valid_state, result, "SQRT")
        if isinstance(terminal, TerminalState):
            return [], terminal
        valid_state.ip = instruction.end_offset
        next_states.append(valid_state)
    fault = None
    if _append_condition(invalid_state, negative):
        fault = _terminal(invalid_state, "faulted", "value can not be negative")
    if next_states:
        return next_states, fault
    if fault is not None:
        return [], fault
    return [], _terminal(state, "stopped", "SQRT branches were unsatisfiable")


def _execute_binary_op(state: State, opcode: str, instruction: Instruction) -> tuple[list[State], TerminalState | None]:
    values = _pop2(state)
    if isinstance(values, TerminalState):
        return [], values
    left, right = values

    if opcode in {
        "AND",
        "OR",
        "XOR",
        "ADD",
        "SUB",
        "MUL",
        "DIV",
        "MOD",
        "POW",
        "SHL",
        "SHR",
        "LT",
        "LE",
        "GT",
        "GE",
        "NUMEQUAL",
        "NUMNOTEQUAL",
        "MIN",
        "MAX",
    } and (not is_int(left) or not is_int(right)):
        return [], _terminal(state, "faulted", f"{opcode} expects integer operands")

    if opcode in {"SHL", "SHR"}:
        return _execute_shift_op(state, opcode, instruction, left, right)

    if opcode == "POW":
        return _execute_pow_op(state, instruction, left, right)

    if opcode in {"DIV", "MOD"}:
        zero_condition = make_binary("==", right, IntConst(0))
        non_zero_condition = make_binary("!=", right, IntConst(0))
        if isinstance(zero_condition, BoolConst) and zero_condition.value:
            return [], _terminal(state, "faulted", f"{opcode} by zero")
        if not isinstance(zero_condition, BoolConst):
            fault_state = state.clone()
            if _append_condition(fault_state, zero_condition):
                return_state = state.clone()
                if _append_condition(return_state, non_zero_condition):
                    result_expr = make_binary("/" if opcode == "DIV" else "%", left, right)
                    integer_limit = _ensure_vm_integer_limit(return_state, result_expr, opcode)
                    if integer_limit is not None:
                        return [], integer_limit
                    terminal = _push(return_state, result_expr, opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    return_state.ip = instruction.end_offset
                    return [return_state], _terminal(fault_state, "faulted", f"{opcode} by zero")
                return [], _terminal(fault_state, "faulted", f"{opcode} by zero")

    if opcode == "MIN":
        if isinstance(left, IntConst) and isinstance(right, IntConst):
            result = int_const(min(left.value, right.value))
        else:
            condition = simplify(make_binary("<=", left, right))
            if isinstance(condition, BoolConst):
                result = left if condition.value else right
            else:
                lesser_state = state.clone()
                greater_state = state.clone()
                next_states: list[State] = []
                if _append_condition(lesser_state, condition):
                    terminal = _push(lesser_state, left, opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    lesser_state.ip = instruction.end_offset
                    next_states.append(lesser_state)
                if _append_condition(greater_state, negate(condition)):
                    terminal = _push(greater_state, right, opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    greater_state.ip = instruction.end_offset
                    next_states.append(greater_state)
                if next_states:
                    return next_states, None
                return [], _terminal(state, "stopped", "MIN branches were unsatisfiable")
    elif opcode == "MAX":
        if isinstance(left, IntConst) and isinstance(right, IntConst):
            result = int_const(max(left.value, right.value))
        else:
            condition = simplify(make_binary(">=", left, right))
            if isinstance(condition, BoolConst):
                result = left if condition.value else right
            else:
                greater_state = state.clone()
                lesser_state = state.clone()
                next_states: list[State] = []
                if _append_condition(greater_state, condition):
                    terminal = _push(greater_state, left, opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    greater_state.ip = instruction.end_offset
                    next_states.append(greater_state)
                if _append_condition(lesser_state, negate(condition)):
                    terminal = _push(lesser_state, right, opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    lesser_state.ip = instruction.end_offset
                    next_states.append(lesser_state)
                if next_states:
                    return next_states, None
                return [], _terminal(state, "stopped", "MAX branches were unsatisfiable")
    else:
        operation = {
            "AND": "&",
            "OR": "|",
            "XOR": "^",
            "EQUAL": "==",
            "NOTEQUAL": "!=",
            "ADD": "+",
            "SUB": "-",
            "MUL": "*",
            "DIV": "/",
            "MOD": "%",
            "SHL": "<<",
            "SHR": ">>",
            "BOOLAND": "and",
            "BOOLOR": "or",
            "NUMEQUAL": "==",
            "NUMNOTEQUAL": "!=",
            "LT": "<",
            "LE": "<=",
            "GT": ">",
            "GE": ">=",
        }.get(opcode)
        try:
            if opcode in {"BOOLAND", "BOOLOR"}:
                result = make_binary(operation, truthy(left), truthy(right))
            else:
                result = make_binary(operation, left, right)
        except TypeError as exc:
            return [], _terminal(state, "faulted", str(exc))

    integer_limit = _ensure_vm_integer_limit(state, result, opcode)
    if integer_limit is not None:
        return [], integer_limit
    terminal = _push(state, result, opcode)
    if isinstance(terminal, TerminalState):
        return [], terminal
    state.ip = instruction.end_offset
    return [state], None


def _execute_shift_op(
    state: State,
    opcode: str,
    instruction: Instruction,
    left: Expression,
    right: Expression,
) -> tuple[list[State], TerminalState | None]:
    operation = "<<" if opcode == "SHL" else ">>"

    if isinstance(right, IntConst):
        if right.value < 0 or right.value > state.max_shift:
            return [], _terminal(state, "faulted", _concrete_shift_failure_reason(right.value, state.max_shift))
        result = make_binary(operation, left, right)
        integer_limit = _ensure_vm_integer_limit(state, result, opcode)
        if integer_limit is not None:
            return [], integer_limit
        terminal = _push(state, result, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    try:
        valid_condition = simplify(
            make_binary(
                "and",
                make_binary(">=", right, int_const(0)),
                make_binary("<=", right, int_const(state.max_shift)),
            )
        )
    except TypeError as exc:
        return [], _terminal(state, "faulted", str(exc))

    valid_state = state.clone()
    invalid_state = state.clone()
    next_states: list[State] = []
    if _append_condition(valid_state, valid_condition):
        result = make_binary(operation, left, right)
        integer_limit = _ensure_vm_integer_limit(valid_state, result, opcode)
        if integer_limit is not None:
            return [], integer_limit
        terminal = _push(valid_state, result, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        valid_state.ip = instruction.end_offset
        next_states.append(valid_state)
    fault = None
    if _append_condition(invalid_state, negate(valid_condition)):
        fault = _terminal(invalid_state, "faulted", _symbolic_shift_failure_reason(state.max_shift))
    if next_states:
        return next_states, fault
    if fault is not None:
        return [], fault
    return [], _terminal(state, "stopped", f"{opcode} branches were unsatisfiable")


def _execute_pow_op(
    state: State,
    instruction: Instruction,
    left: Expression,
    right: Expression,
) -> tuple[list[State], TerminalState | None]:
    if isinstance(right, IntConst):
        if right.value < 0 or right.value > state.max_shift:
            return [], _terminal(state, "faulted", _concrete_shift_failure_reason(right.value, state.max_shift))
        if isinstance(left, IntConst):
            result = int_const(pow(left.value, right.value))
        else:
            result = _power_expression(left, right.value)
        integer_limit = _ensure_vm_integer_limit(state, result, "POW")
        if integer_limit is not None:
            return [], integer_limit
        terminal = _push(state, result, "POW")
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    valid_condition = make_binary(
        "and",
        make_binary(">=", right, int_const(0)),
        make_binary("<=", right, int_const(state.max_shift)),
    )
    invalid_condition = make_binary(
        "or",
        make_binary("<", right, int_const(0)),
        make_binary(">", right, int_const(state.max_shift)),
    )
    valid_state = state.clone()
    invalid_state = state.clone()
    next_states: list[State] = []
    if _append_condition(valid_state, valid_condition):
        result = make_binary("pow", left, right)
        integer_limit = _ensure_vm_integer_limit(valid_state, result, "POW")
        if integer_limit is not None:
            return [], integer_limit
        terminal = _push(valid_state, result, "POW")
        if isinstance(terminal, TerminalState):
            return [], terminal
        valid_state.ip = instruction.end_offset
        next_states.append(valid_state)
    fault = None
    if _append_condition(invalid_state, invalid_condition):
        fault = _terminal(invalid_state, "faulted", _symbolic_shift_failure_reason(state.max_shift))
    if next_states:
        return next_states, fault
    if fault is not None:
        return [], fault
    return [], _terminal(state, "stopped", "POW branches were unsatisfiable")


def _execute_ternary_numeric_op(
    state: State,
    opcode: str,
    instruction: Instruction,
) -> tuple[list[State], TerminalState | None]:
    if len(state.stack) < 3:
        return [], _terminal(state, "faulted", "stack underflow")
    third = state.stack.pop()
    second = state.stack.pop()
    first = state.stack.pop()

    if not is_int(first) or not is_int(second) or not is_int(third):
        return [], _terminal(state, "faulted", f"{opcode} expects integer operands")

    if opcode == "MODMUL":
        if isinstance(third, IntConst):
            if third.value == 0:
                return [], _terminal(state, "faulted", "MODMUL by zero")
            if isinstance(first, IntConst) and isinstance(second, IntConst):
                result = int_const((first.value * second.value) % third.value)
            else:
                result = make_binary("%", make_binary("*", first, second), third)
        else:
            product = make_binary("*", first, second)
            valid_state = state.clone()
            invalid_state = state.clone()
            next_states: list[State] = []
            if _append_condition(valid_state, make_binary("!=", third, int_const(0))):
                result = make_binary("%", product, third)
                integer_limit = _ensure_vm_integer_limit(valid_state, result, opcode)
                if integer_limit is not None:
                    return [], integer_limit
                terminal = _push(valid_state, result, opcode)
                if isinstance(terminal, TerminalState):
                    return [], terminal
                valid_state.ip = instruction.end_offset
                next_states.append(valid_state)
            fault = None
            if _append_condition(invalid_state, make_binary("==", third, int_const(0))):
                fault = _terminal(invalid_state, "faulted", "MODMUL by zero")
            if next_states:
                return next_states, fault
            if fault is not None:
                return [], fault
            return [], _terminal(state, "stopped", "MODMUL branches were unsatisfiable")
    else:
        assert opcode == "MODPOW"
        if not isinstance(second, IntConst):
            return [], _terminal(state, "stopped", "MODPOW requires a concrete exponent")
        exponent = second.value
        if exponent == -1:
            if not isinstance(third, IntConst):
                return [], _terminal(state, "stopped", "MODPOW requires a concrete modulus")
            modulus = third.value
            if not isinstance(first, IntConst):
                return [], _terminal(
                    state,
                    "stopped",
                    "MODPOW modular inverse on symbolic bases is not implemented yet",
                )
            if first.value <= 0:
                return [], _terminal(state, "faulted", "MODPOW modular inverse requires a positive value")
            if modulus < 2:
                return [], _terminal(state, "faulted", "MODPOW modular inverse requires modulus >= 2")
            try:
                result = int_const(_mod_inverse(first.value, modulus))
            except ValueError as exc:
                return [], _terminal(state, "faulted", str(exc))
        else:
            if exponent < 0:
                return [], _terminal(state, "faulted", "MODPOW exponent must be >= -1")
            if isinstance(third, IntConst):
                modulus = third.value
                if modulus <= 0:
                    return [], _terminal(state, "faulted", "MODPOW modulus must be positive")
                if isinstance(first, IntConst):
                    result = int_const(pow(first.value, exponent, modulus))
                else:
                    powered = _power_expression(first, exponent)
                    result = make_binary("%", powered, third)
            else:
                powered = (
                    int_const(pow(first.value, exponent))
                    if isinstance(first, IntConst)
                    else _power_expression(first, exponent)
                )
                valid_state = state.clone()
                invalid_state = state.clone()
                next_states = []
                if _append_condition(valid_state, make_binary(">", third, int_const(0))):
                    result = make_binary("%", powered, third)
                    integer_limit = _ensure_vm_integer_limit(valid_state, result, opcode)
                    if integer_limit is not None:
                        return [], integer_limit
                    terminal = _push(valid_state, result, opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    valid_state.ip = instruction.end_offset
                    next_states.append(valid_state)
                fault = None
                if _append_condition(invalid_state, make_binary("<=", third, int_const(0))):
                    fault = _terminal(invalid_state, "faulted", "MODPOW modulus must be positive")
                if next_states:
                    return next_states, fault
                if fault is not None:
                    return [], fault
                return [], _terminal(state, "stopped", "MODPOW branches were unsatisfiable")

    integer_limit = _ensure_vm_integer_limit(state, result, opcode)
    if integer_limit is not None:
        return [], integer_limit
    terminal = _push(state, result, opcode)
    if isinstance(terminal, TerminalState):
        return [], terminal
    state.ip = instruction.end_offset
    return [state], None


def _execute_within(state: State, instruction: Instruction) -> tuple[list[State], TerminalState | None]:
    if len(state.stack) < 3:
        return [], _terminal(state, "faulted", "stack underflow")
    upper = state.stack.pop()
    lower = state.stack.pop()
    value = state.stack.pop()
    if not is_int(value) or not is_int(lower) or not is_int(upper):
        return [], _terminal(state, "faulted", "WITHIN expects integer operands")
    if isinstance(value, IntConst) and isinstance(lower, IntConst) and isinstance(upper, IntConst):
        result = bool_const(lower.value <= value.value < upper.value)
    else:
        lower_check = make_binary("<=", lower, value)
        upper_check = make_binary("<", value, upper)
        result = make_binary("and", lower_check, upper_check)
    terminal = _push(state, result, "WITHIN")
    if isinstance(terminal, TerminalState):
        return [], terminal
    state.ip = instruction.end_offset
    return [state], None


def _execute_syscall(state: State, instruction: Instruction) -> tuple[list[State], TerminalState | None]:
    token = int(instruction.argument)
    descriptor = INTEROP_BY_ID.get(token)
    if descriptor is None:
        return [], _terminal(state, "faulted", f"Syscall not found: {token}")
    if state.call_flags & descriptor.required_call_flags != descriptor.required_call_flags:
        return [], _terminal(
            state,
            "faulted",
            f"Cannot call SYSCALL {descriptor.name} with call flags 0x{state.call_flags:02x}",
        )

    if descriptor.name == "System.Runtime.Platform":
        terminal = _push(state, bytes_const(b"NEO"), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GetTrigger":
        terminal = _push(state, int_const(state.trigger), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GetNetwork":
        terminal = _push(state, int_const(state.network_magic), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GetAddressVersion":
        terminal = _push(state, int_const(state.address_version), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name in {
        "System.Runtime.GetExecutingScriptHash",
        "System.Runtime.GetEntryScriptHash",
    }:
        terminal = _push(state, _current_script_hash_expr(state), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GetCallingScriptHash":
        if state.call_stack:
            terminal = _push(state, _current_script_hash_expr(state), "SYSCALL")
        else:
            terminal = _push(state, null_const(), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GetInvocationCounter":
        terminal = _push(state, int_const(len(state.call_stack) + 1), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GasLeft":
        terminal = _push(state, _gas_left_expr(state, instruction), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GetTime":
        terminal = _push(state, _time_expr(state), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.GetRandom":
        terminal = _push(state, int_symbol(f"sys_random_{instruction.offset}_{state.steps}"), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Contract.GetCallFlags":
        terminal = _push(state, int_const(state.call_flags), "SYSCALL")
        if isinstance(terminal, TerminalState):
            return [], terminal
    elif descriptor.name == "System.Runtime.Log":
        terminal = _execute_runtime_log(state, descriptor.name)
        if terminal is not None:
            return [], terminal
    elif descriptor.name == "System.Runtime.Notify":
        terminal = _execute_runtime_notify(state, descriptor.name)
        if terminal is not None:
            return [], terminal
    else:
        return [], _terminal(
            state,
            "stopped",
            f"SYSCALL 0x{token:08x} ({descriptor.name}) requires interop context",
        )

    state.ip = instruction.end_offset
    return [state], None


def _current_script_hash_expr(state: State) -> Expression:
    if state.script_hash is not None:
        return bytes_const(state.script_hash)
    return bytes_symbol("current_script_hash")


def _gas_left_expr(state: State, instruction: Instruction) -> Expression:
    if state.gas_left is not None:
        return int_const(state.gas_left)
    return int_symbol(f"sys_gas_left_{instruction.offset}_{state.steps}")


def _time_expr(state: State) -> Expression:
    if state.time is not None:
        return int_const(state.time)
    return int_symbol("sys_time")


def _execute_runtime_log(state: State, opcode: str) -> TerminalState | None:
    message = _pop(state)
    if isinstance(message, TerminalState):
        return message
    payload = _primitive_bytes(state, message, opcode)
    if isinstance(payload, TerminalState):
        return payload
    if len(payload) > 1024:
        return _terminal(state, "faulted", "Message is too long.")
    try:
        rendered = payload.decode("utf-8")
    except UnicodeDecodeError:
        return _terminal(
            state,
            "faulted",
            "Failed to convert byte array to string: Invalid or non-printable UTF-8 sequence detected.",
        )
    state.trace.append(f"LOG {rendered}")
    return None


def _execute_runtime_notify(state: State, opcode: str) -> TerminalState | None:
    event_name = _pop(state)
    if isinstance(event_name, TerminalState):
        return event_name
    payload = _primitive_bytes(state, event_name, opcode)
    if isinstance(payload, TerminalState):
        return payload
    if len(payload) > MAX_EVENT_NAME_LENGTH:
        return _terminal(state, "faulted", "Event name is too long.")
    try:
        name = payload.decode("utf-8")
    except UnicodeDecodeError:
        return _terminal(
            state,
            "faulted",
            "Failed to convert byte array to string: Invalid or non-printable UTF-8 sequence detected.",
        )
    event_state = _pop(state)
    if isinstance(event_state, TerminalState):
        return event_state
    obj = _require_heap_object(state, event_state, opcode)
    if isinstance(obj, TerminalState):
        return obj
    if not isinstance(obj, (ArrayObject, StructObject)):
        return _terminal(state, "faulted", "System.Runtime.Notify expects an array state payload")
    state.trace.append(f"NOTIFY {name} {render_expr(event_state)}")
    return None


def _execute_splice_op(state: State, opcode: str, instruction: Instruction) -> tuple[list[State], TerminalState | None]:
    if opcode == "NEWBUFFER":
        length_value = _pop(state)
        if isinstance(length_value, TerminalState):
            return [], length_value
        length = _require_concrete_index(length_value, state, opcode)
        if isinstance(length, TerminalState):
            return [], length
        if length < 0:
            return [], _terminal(state, "faulted", f"{opcode} size {length} is invalid")
        if length > state.max_item_size:
            raise ExecutionLimitExceeded(f"buffer size {length} exceeds item size limit {state.max_item_size}")
        terminal = _push(state, _alloc_buffer(state, bytearray(length)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "MEMCPY":
        if len(state.stack) < 5:
            return [], _terminal(state, "faulted", "stack underflow")
        count_value = state.stack.pop()
        source_index_value = state.stack.pop()
        source_value = state.stack.pop()
        destination_index_value = state.stack.pop()
        destination_value = state.stack.pop()
        count = _require_concrete_index(count_value, state, opcode)
        if isinstance(count, TerminalState):
            return [], count
        source_index = _require_concrete_index(source_index_value, state, opcode)
        if isinstance(source_index, TerminalState):
            return [], source_index
        destination_index = _require_concrete_index(destination_index_value, state, opcode)
        if isinstance(destination_index, TerminalState):
            return [], destination_index
        if count < 0:
            return [], _terminal(state, "faulted", f"{opcode} count {count} is invalid")
        if source_index < 0:
            return [], _terminal(state, "faulted", f"{opcode} source index {source_index} is invalid")
        if destination_index < 0:
            return [], _terminal(state, "faulted", f"{opcode} destination index {destination_index} is invalid")
        source_bytes = _primitive_bytes(state, source_value, opcode)
        if isinstance(source_bytes, TerminalState):
            return [], source_bytes
        destination = _require_buffer_object(state, destination_value, opcode)
        if isinstance(destination, TerminalState):
            return [], destination
        if source_index + count > len(source_bytes):
            return [], _terminal(state, "faulted", f"{opcode} source range is out of bounds")
        if destination_index + count > len(destination.data):
            return [], _terminal(state, "faulted", f"{opcode} destination range is out of bounds")
        destination.data[destination_index : destination_index + count] = source_bytes[
            source_index : source_index + count
        ]
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "CAT":
        values = _pop2(state)
        if isinstance(values, TerminalState):
            return [], values
        left, right = values
        left_bytes = _primitive_bytes(state, left, opcode)
        if isinstance(left_bytes, TerminalState):
            return [], left_bytes
        right_bytes = _primitive_bytes(state, right, opcode)
        if isinstance(right_bytes, TerminalState):
            return [], right_bytes
        terminal = _push(state, _alloc_buffer(state, bytearray(left_bytes + right_bytes)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "SUBSTR":
        if len(state.stack) < 3:
            return [], _terminal(state, "faulted", "stack underflow")
        count_value = state.stack.pop()
        index_value = state.stack.pop()
        source_value = state.stack.pop()
        count = _require_concrete_index(count_value, state, opcode)
        if isinstance(count, TerminalState):
            return [], count
        index = _require_concrete_index(index_value, state, opcode)
        if isinstance(index, TerminalState):
            return [], index
        if count < 0:
            return [], _terminal(state, "faulted", f"{opcode} count {count} is invalid")
        if index < 0:
            return [], _terminal(state, "faulted", f"{opcode} index {index} is invalid")
        source_bytes = _primitive_bytes(state, source_value, opcode)
        if isinstance(source_bytes, TerminalState):
            return [], source_bytes
        if index + count > len(source_bytes):
            return [], _terminal(state, "faulted", f"{opcode} range is out of bounds")
        terminal = _push(state, _alloc_buffer(state, bytearray(source_bytes[index : index + count])), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode in {"LEFT", "RIGHT"}:
        values = _pop2(state)
        if isinstance(values, TerminalState):
            return [], values
        source_value, count_value = values
        count = _require_concrete_index(count_value, state, opcode)
        if isinstance(count, TerminalState):
            return [], count
        if count < 0:
            return [], _terminal(state, "faulted", f"{opcode} count {count} is invalid")
        source_bytes = _primitive_bytes(state, source_value, opcode)
        if isinstance(source_bytes, TerminalState):
            return [], source_bytes
        if count > len(source_bytes):
            return [], _terminal(state, "faulted", f"{opcode} range is out of bounds")
        if opcode == "LEFT":
            result = source_bytes[:count]
        else:
            result = source_bytes[len(source_bytes) - count :] if count else b""
        terminal = _push(state, _alloc_buffer(state, bytearray(result)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    raise ValueError(f"Unhandled splice opcode {opcode}")


def _assert_condition(
    state: State,
    condition: Expression,
    fallthrough_ip: int,
    failure_reason: str = "ASSERT failed",
) -> tuple[list[State], TerminalState | None]:
    condition = simplify(condition)
    if isinstance(condition, BoolConst):
        if condition.value:
            state.ip = fallthrough_ip
            return [state], None
        return [], _terminal(state, "faulted", failure_reason)

    success_state = state.clone()
    fault_state = state.clone()
    success_added = _append_condition(success_state, condition)
    fault_added = _append_condition(fault_state, negate(condition))

    terminal_fault = _terminal(fault_state, "faulted", failure_reason) if fault_added else None
    if success_added:
        success_state.ip = fallthrough_ip
        return [success_state], terminal_fault
    if terminal_fault is not None:
        return [], terminal_fault
    return [], _terminal(state, "stopped", "assert branches were unsatisfiable")


def _branch_on_condition(
    state: State,
    condition: Expression,
    true_ip: int,
    false_ip: int,
) -> tuple[list[State], TerminalState | None]:
    condition = simplify(condition)
    if isinstance(condition, BoolConst):
        state.ip = true_ip if condition.value else false_ip
        return [state], None

    true_state = state.clone()
    false_state = state.clone()
    next_states: list[State] = []

    if _append_condition(true_state, condition):
        true_state.ip = true_ip
        next_states.append(true_state)
    if _append_condition(false_state, negate(condition)):
        false_state.ip = false_ip
        next_states.append(false_state)

    if next_states:
        return next_states, None
    return [], _terminal(state, "stopped", "branch conditions were unsatisfiable")


def _execute_symbolic_calla(
    state: State,
    instruction: Instruction,
    program: Program,
    pointer: Expression,
) -> tuple[list[State], TerminalState | None]:
    next_states: list[State] = []
    invalid_state = state.clone()
    invalid_possible = True

    for target in program.instruction_offsets:
        branch_state = state.clone()
        condition = make_binary("==", pointer, int_const(target))
        if not _append_condition(branch_state, condition):
            continue
        frame_error = _push_call_frame(branch_state, instruction.end_offset)
        if frame_error is not None:
            return [], frame_error
        branch_state.ip = target
        next_states.append(branch_state)
        if invalid_possible:
            invalid_possible = _append_condition(invalid_state, make_binary("!=", pointer, int_const(target)))

    fault = None
    if invalid_possible:
        fault = _terminal(invalid_state, "faulted", "CALLA target is not a valid instruction offset")

    if next_states:
        return next_states, fault
    if fault is not None:
        return [], fault
    return [], _terminal(state, "stopped", "CALLA branches were unsatisfiable")


def _append_condition(state: State, condition: Expression) -> bool:
    condition = simplify(condition)
    if isinstance(condition, BoolConst):
        return condition.value

    condition_key = render_expr(condition)
    inverse_key = render_expr(negate(condition))
    existing = {render_expr(entry) for entry in state.path_conditions}
    if inverse_key in existing:
        return False
    if condition_key not in existing:
        state.path_conditions.append(condition)
    return True


def _exception_handler_signature(handler: ExceptionHandler) -> tuple[object, ...]:
    return (handler.catch_ip, handler.finally_ip, handler.end_ip, handler.state)


def _signature(state: State) -> tuple[object, ...]:
    stack_key = tuple(render_expr(item) for item in state.stack)
    args_key = None if state.arguments is None else tuple(render_expr(item) for item in state.arguments)
    locals_key = None if state.local_variables is None else tuple(render_expr(item) for item in state.local_variables)
    statics_key = None if state.static_fields is None else tuple(render_expr(item) for item in state.static_fields)
    call_stack_key = tuple(
        (
            frame.return_ip,
            None if frame.arguments is None else tuple(render_expr(item) for item in frame.arguments),
            None if frame.local_variables is None else tuple(render_expr(item) for item in frame.local_variables),
            tuple(_exception_handler_signature(handler) for handler in frame.try_stack),
        )
        for frame in state.call_stack
    )
    heap_key = _heap_signature(state.heap)
    conditions_key = tuple(render_expr(item) for item in state.path_conditions)
    visits_key = tuple(sorted(state.visit_counts.items()))
    try_stack_key = tuple(_exception_handler_signature(handler) for handler in state.try_stack)
    uncaught_key = None if state.uncaught_exception is None else render_expr(state.uncaught_exception)
    return (
        state.ip,
        stack_key,
        args_key,
        locals_key,
        statics_key,
        call_stack_key,
        try_stack_key,
        uncaught_key,
        heap_key,
        state.next_heap_id,
        conditions_key,
        visits_key,
    )


def _trace_entry(instruction: Instruction) -> str:
    if instruction.line_no:
        return f"offset {instruction.offset} line {instruction.line_no}: {instruction.display}"
    return f"offset {instruction.offset}: {instruction.display}"


def _terminal(state: State, status: str, reason: str | None) -> TerminalState:
    return TerminalState(
        status=status,
        reason=reason,
        ip=state.ip,
        call_depth=len(state.call_stack),
        steps=state.steps,
        stack=tuple(state.stack),
        arguments=None if state.arguments is None else tuple(state.arguments),
        local_variables=None if state.local_variables is None else tuple(state.local_variables),
        static_fields=None if state.static_fields is None else tuple(state.static_fields),
        call_stack=tuple(
            (
                frame.return_ip,
                None if frame.arguments is None else tuple(frame.arguments),
                None if frame.local_variables is None else tuple(frame.local_variables),
            )
            for frame in state.call_stack
        ),
        heap=render_heap_snapshot(state.heap),
        path_conditions=tuple(state.path_conditions),
        trace=tuple(state.trace),
    )


def _pop(state: State) -> Expression | TerminalState:
    if not state.stack:
        return _terminal(state, "faulted", "stack underflow")
    return state.stack.pop()


def _peek(state: State) -> Expression | TerminalState:
    if not state.stack:
        return _terminal(state, "faulted", "stack underflow")
    return state.stack[-1]


def _pop2(state: State) -> tuple[Expression, Expression] | TerminalState:
    if len(state.stack) < 2:
        return _terminal(state, "faulted", "stack underflow")
    right = state.stack.pop()
    left = state.stack.pop()
    return left, right


def _push(state: State, value: Expression, opcode: str) -> TerminalState | None:
    if len(state.stack) >= state.max_stack_depth:
        return _terminal(state, "faulted", f"{opcode} stack depth exceeds limit {state.max_stack_depth}")
    state.stack.append(value)
    return None


def _slot_list(state: State, opcode: str) -> list[Expression] | TerminalState:
    if opcode.startswith("LDARG") or opcode.startswith("STARG"):
        if state.arguments is None:
            return _terminal(state, "faulted", "argument slot is not initialized")
        return state.arguments
    if opcode.startswith("LDLOC") or opcode.startswith("STLOC"):
        if state.local_variables is None:
            return _terminal(state, "faulted", "local slot is not initialized")
        return state.local_variables
    if state.static_fields is None:
        return _terminal(state, "faulted", "static field slot is not initialized")
    return state.static_fields


def _require_target(instruction: Instruction) -> int:
    if instruction.target is None:
        raise ValueError(f"Instruction {instruction.opcode} is missing a resolved target")
    return instruction.target


def _require_concrete_index(value: Expression, state: State, opcode: str) -> int | TerminalState:
    if not isinstance(value, IntConst):
        return _terminal(state, "stopped", f"{opcode} requires a concrete integer index")
    return value.value


def _push_call_frame(state: State, return_ip: int) -> TerminalState | None:
    current_depth = len(state.call_stack) + 1
    if current_depth + 1 > state.max_invocation_stack:
        return _terminal(state, "faulted", f"invocation stack exceeds limit {state.max_invocation_stack}")
    state.call_stack.append(
        CallFrame(
            return_ip=return_ip,
            arguments=None if state.arguments is None else list(state.arguments),
            local_variables=None if state.local_variables is None else list(state.local_variables),
            try_stack=[handler.clone() for handler in state.try_stack],
        )
    )
    state.arguments = None
    state.local_variables = None
    state.try_stack = []
    return None


def _restore_call_frame(state: State, frame: CallFrame) -> None:
    state.arguments = None if frame.arguments is None else list(frame.arguments)
    state.local_variables = None if frame.local_variables is None else list(frame.local_variables)
    state.try_stack = [handler.clone() for handler in frame.try_stack]
    state.ip = frame.return_ip


def _heap_signature(heap: dict[int, HeapObject]) -> tuple[object, ...]:
    signature: list[object] = []
    for object_id, obj in sorted(heap.items()):
        if isinstance(obj, ArrayObject):
            signature.append(("array", object_id, tuple(render_expr(item) for item in obj.elements)))
        elif isinstance(obj, StructObject):
            signature.append(("struct", object_id, tuple(render_expr(item) for item in obj.elements)))
        elif isinstance(obj, MapObject):
            signature.append(
                (
                    "map",
                    object_id,
                    tuple((render_expr(key), render_expr(value)) for key, value in obj.entries),
                )
            )
        else:
            signature.append(("buffer", object_id, bytes(obj.data).hex()))
    return tuple(signature)


def _alloc_array(state: State, elements: list[Expression]) -> HeapRef:
    _assert_heap_capacity(state)
    if len(elements) > state.max_collection_size:
        raise ExecutionLimitExceeded(f"array size {len(elements)} exceeds collection limit {state.max_collection_size}")
    object_id = state.next_heap_id
    state.next_heap_id += 1
    state.heap[object_id] = ArrayObject(elements=list(elements))
    return new_array_ref(object_id)


def _alloc_struct(state: State, elements: list[Expression]) -> HeapRef:
    _assert_heap_capacity(state)
    if len(elements) > state.max_collection_size:
        raise ExecutionLimitExceeded(
            f"struct size {len(elements)} exceeds collection limit {state.max_collection_size}"
        )
    object_id = state.next_heap_id
    state.next_heap_id += 1
    state.heap[object_id] = StructObject(elements=list(elements))
    return new_struct_ref(object_id)


def _alloc_map(state: State, entries: list[tuple[Expression, Expression]]) -> HeapRef:
    _assert_heap_capacity(state)
    if len(entries) > state.max_collection_size:
        raise ExecutionLimitExceeded(f"map size {len(entries)} exceeds collection limit {state.max_collection_size}")
    object_id = state.next_heap_id
    state.next_heap_id += 1
    state.heap[object_id] = MapObject(entries=list(entries))
    return new_map_ref(object_id)


def _alloc_buffer(state: State, data: bytearray) -> HeapRef:
    _assert_heap_capacity(state)
    if len(data) > state.max_item_size:
        raise ExecutionLimitExceeded(f"buffer size {len(data)} exceeds item size limit {state.max_item_size}")
    object_id = state.next_heap_id
    state.next_heap_id += 1
    state.heap[object_id] = BufferObject(data=bytearray(data))
    return new_buffer_ref(object_id)


def _require_heap_object(state: State, value: Expression, opcode: str) -> HeapObject | TerminalState:
    if not isinstance(value, HeapRef):
        return _terminal(state, "faulted", f"{opcode} expects a compound type")
    obj = state.heap.get(value.object_id)
    if obj is None:
        return _terminal(state, "faulted", f"{opcode} references missing heap object {value.object_id}")
    if value.ref_sort == Sort.ARRAY and isinstance(obj, ArrayObject):
        return obj
    if value.ref_sort == Sort.STRUCT and isinstance(obj, StructObject):
        return obj
    if value.ref_sort == Sort.MAP and isinstance(obj, MapObject):
        return obj
    if value.ref_sort == Sort.BUFFER and isinstance(obj, BufferObject):
        return obj
    return _terminal(state, "faulted", f"{opcode} encountered a corrupted heap reference")


def _assert_heap_capacity(state: State) -> None:
    if len(state.heap) >= state.max_heap_objects:
        raise ExecutionLimitExceeded(f"heap object limit {state.max_heap_objects} exceeded")


def _assert_collection_growth(state: State, current_size: int, kind: str) -> None:
    if current_size + 1 > state.max_collection_size:
        raise ExecutionLimitExceeded(
            f"{kind} size {current_size + 1} exceeds collection limit {state.max_collection_size}"
        )


def _require_buffer_object(state: State, value: Expression, opcode: str) -> BufferObject | TerminalState:
    obj = _require_heap_object(state, value, opcode)
    if isinstance(obj, TerminalState):
        return obj
    if not isinstance(obj, BufferObject):
        return _terminal(state, "faulted", f"{opcode} expects a buffer")
    return obj


def _require_map_key(value: Expression, state: State, opcode: str) -> Expression | TerminalState:
    if is_int(value) or is_bool(value) or value.sort == Sort.BYTES:
        return value
    return _terminal(state, "faulted", f"{opcode} expects a primitive map key")


def _default_value_for_stack_item_type(type_byte: int) -> Expression:
    if type_byte not in VALID_STACK_ITEM_TYPES:
        raise ValueError(f"Invalid stack item type {type_byte}")
    if type_byte == STACK_ITEM_TYPE_BOOLEAN:
        return bool_const(False)
    if type_byte == STACK_ITEM_TYPE_INTEGER:
        return int_const(0)
    if type_byte == STACK_ITEM_TYPE_BYTESTRING:
        return bytes_const(b"")
    return null_const()


MAX_STRUCT_DEPTH = 32


def _clone_struct_value(state: State, value: Expression, depth: int = 0) -> Expression | TerminalState:
    if depth > MAX_STRUCT_DEPTH:
        return _terminal(state, "faulted", "struct nesting depth exceeds limit")
    if not isinstance(value, HeapRef) or value.ref_sort != Sort.STRUCT:
        return value
    obj = _require_heap_object(state, value, "struct clone")
    if isinstance(obj, TerminalState):
        return obj
    assert isinstance(obj, StructObject)
    cloned_elements: list[Expression] = []
    for item in obj.elements:
        cloned = _clone_struct_value(state, item, depth + 1)
        if isinstance(cloned, TerminalState):
            return cloned
        cloned_elements.append(cloned)
    return _alloc_struct(state, cloned_elements)


def _copy_for_storage(state: State, value: Expression) -> Expression | TerminalState:
    return _clone_struct_value(state, value)


def _ensure_vm_integer_limit(state: State, value: Expression, opcode: str) -> TerminalState | None:
    if isinstance(value, IntConst) and _integer_byte_size(value.value) > INTEGER_MAX_SIZE:
        return _terminal(state, "faulted", f"{opcode} integer result exceeds {INTEGER_MAX_SIZE} bytes")
    return None


def _expression_stack_item_type(value: Expression) -> int:
    if isinstance(value, NullConst):
        return STACK_ITEM_TYPE_ANY
    if is_bool(value):
        return STACK_ITEM_TYPE_BOOLEAN
    if is_int(value):
        return STACK_ITEM_TYPE_INTEGER
    if value.sort == Sort.BYTES:
        return STACK_ITEM_TYPE_BYTESTRING
    if isinstance(value, HeapRef):
        if value.ref_sort == Sort.BUFFER:
            return STACK_ITEM_TYPE_BUFFER
        if value.ref_sort == Sort.ARRAY:
            return STACK_ITEM_TYPE_ARRAY
        if value.ref_sort == Sort.STRUCT:
            return STACK_ITEM_TYPE_STRUCT
        if value.ref_sort == Sort.MAP:
            return STACK_ITEM_TYPE_MAP
    raise ValueError(f"Unsupported expression sort {value.sort}")


def _primitive_bytes(state: State, value: Expression, opcode: str) -> bytes | TerminalState:
    if isinstance(value, BytesConst):
        return value.value
    if isinstance(value, BoolConst):
        return b"\x01" if value.value else b"\x00"
    if isinstance(value, IntConst):
        encoded = _int_to_signed_bytes(value.value)
        if len(encoded) > INTEGER_MAX_SIZE:
            return _terminal(state, "faulted", f"{opcode} integer operand exceeds {INTEGER_MAX_SIZE} bytes")
        return encoded
    if isinstance(value, HeapRef) and value.ref_sort == Sort.BUFFER:
        obj = _require_buffer_object(state, value, opcode)
        if isinstance(obj, TerminalState):
            return obj
        return bytes(obj.data)
    if value.sort in {Sort.INT, Sort.BOOL, Sort.BYTES}:
        return _terminal(state, "stopped", f"{opcode} on symbolic primitive bytes is not implemented yet")
    return _terminal(state, "faulted", f"{opcode} expects a primitive or buffer value")


def _primitive_int(state: State, value: Expression, opcode: str) -> int | TerminalState:
    if isinstance(value, IntConst):
        return value.value
    if isinstance(value, BoolConst):
        return 1 if value.value else 0
    if isinstance(value, BytesConst):
        if len(value.value) > INTEGER_MAX_SIZE:
            return _terminal(state, "faulted", f"{opcode} byte string operand exceeds {INTEGER_MAX_SIZE} bytes")
        return int.from_bytes(value.value, "little", signed=True)
    if value.sort in {Sort.INT, Sort.BOOL, Sort.BYTES}:
        return _terminal(state, "stopped", f"{opcode} on symbolic primitive integers is not implemented yet")
    return _terminal(state, "faulted", f"{opcode} expects a primitive integer-compatible value")


def _buffer_byte_value(state: State, value: Expression, opcode: str) -> int | TerminalState:
    integer = _primitive_int(state, value, opcode)
    if isinstance(integer, TerminalState):
        return integer
    if integer < -128 or integer > 255:
        return _terminal(state, "faulted", f"{opcode} byte value {integer} is out of range")
    return integer & 0xFF


def _render_message(value: Expression) -> str:
    if isinstance(value, BytesConst):
        try:
            return value.value.decode("utf-8")
        except UnicodeDecodeError:
            return render_expr(value)
    return render_expr(value)


def _branch_map_matches(
    state: State,
    obj: MapObject,
    key: Expression,
    opcode: str,
) -> tuple[list[tuple[State, int]], State | None, TerminalState | None]:
    matches: list[tuple[State, int]] = []
    pending: State | None = state

    for index, (entry_key, _entry_value) in enumerate(obj.entries):
        if pending is None:
            break
        try:
            comparison = simplify(make_binary("==", key, entry_key))
        except TypeError as exc:
            return [], None, _terminal(state, "faulted", str(exc))

        if isinstance(comparison, BoolConst):
            if comparison.value:
                matches.append((pending, index))
                pending = None
            continue

        match_state = pending.clone()
        miss_state = pending.clone()
        if _append_condition(match_state, comparison):
            matches.append((match_state, index))
        pending = miss_state if _append_condition(miss_state, negate(comparison)) else None

    return matches, pending, None


def _resolve_exception_target(
    state: State,
    program: Program,
    instruction: Instruction,
    offset: int,
    opcode: str,
    role: str,
) -> int | None | TerminalState:
    if offset == 0:
        return None
    target = instruction.offset + offset
    if not program.has_offset(target):
        return _terminal(state, "faulted", f"{opcode} {role} target {target} is not a valid instruction offset")
    return target


def _catchable_engine_exception(
    state: State,
    message: str,
) -> tuple[list[State], TerminalState | None]:
    return _execute_throw(state, bytes_const(message.encode("utf-8")))


def _execute_throw(state: State, exception: Expression) -> tuple[list[State], TerminalState | None]:
    state.uncaught_exception = exception

    frames: list[tuple[int, list[ExceptionHandler]]] = [(0, state.try_stack)]
    frames.extend((depth, state.call_stack[-depth].try_stack) for depth in range(1, len(state.call_stack) + 1))

    for depth, try_stack in frames:
        while try_stack:
            current_try = try_stack[-1]
            if current_try.state == "finally" or (current_try.state == "catch" and current_try.finally_ip is None):
                try_stack.pop()
                continue

            if depth > 0:
                frame = state.call_stack[-depth]
                _restore_call_frame(state, frame)
                state.call_stack = state.call_stack[:-depth]
                try_stack = state.try_stack
                current_try = try_stack[-1]

            if current_try.state == "try" and current_try.catch_ip is not None:
                current_try.state = "catch"
                terminal = _push(state, state.uncaught_exception, "THROW")
                if isinstance(terminal, TerminalState):
                    return [], terminal
                state.uncaught_exception = None
                state.ip = current_try.catch_ip
            else:
                current_try.state = "finally"
                assert current_try.finally_ip is not None
                state.ip = current_try.finally_ip
            return [state], None

    reason = _unhandled_exception_reason(state, exception)
    return [], _terminal(state, "faulted", reason)


def _unhandled_exception_reason(state: State, exception: Expression) -> str:
    detail = _exception_detail_text(state, exception)
    if detail is None:
        return "An unhandled exception was thrown."
    return f"An unhandled exception was thrown. {detail}"


def _exception_detail_text(state: State, exception: Expression) -> str | None:
    if isinstance(exception, BytesConst):
        return exception.value.decode("utf-8", errors="replace")
    if isinstance(exception, HeapRef) and exception.ref_sort == Sort.ARRAY:
        obj = state.heap.get(exception.object_id)
        if isinstance(obj, ArrayObject) and obj.elements and isinstance(obj.elements[0], BytesConst):
            return obj.elements[0].value.decode("utf-8", errors="replace")
    return None


def _primitive_size_expr(state: State, value: Expression, opcode: str) -> Expression | TerminalState:
    try:
        if is_bool(value) or is_int(value) or value.sort == Sort.BYTES:
            return make_unary("size", value)
    except TypeError as exc:
        return _terminal(state, "faulted", str(exc))
    return _terminal(state, "faulted", f"{opcode} expects a primitive value")


def _primitive_byte_expr(state: State, value: Expression, index: int, opcode: str) -> Expression | TerminalState:
    try:
        if is_bool(value) or is_int(value) or value.sort == Sort.BYTES:
            return make_binary("byte_at", value, int_const(index))
    except TypeError as exc:
        return _terminal(state, "faulted", str(exc))
    return _terminal(state, "faulted", f"{opcode} expects a primitive value")


def _power_expression(base: Expression, exponent: int) -> Expression:
    result: Expression = int_const(1)
    factor = base
    remaining = exponent
    while remaining > 0:
        if remaining & 1:
            result = make_binary("*", result, factor)
        remaining >>= 1
        if remaining:
            factor = make_binary("*", factor, factor)
    return result


def _integer_sqrt(value: int) -> int:
    if value < 0:
        raise ValueError("value can not be negative")
    if value == 0:
        return 0
    if value < 4:
        return 1
    z = value
    x = 1 << (((value - 1).bit_length() + 1) >> 1)
    while x < z:
        z = x
        x = (value // x + x) // 2
    return z


def _mod_inverse(value: int, modulus: int) -> int:
    if value <= 0:
        raise ValueError("MODPOW modular inverse requires a positive value")
    if modulus < 2:
        raise ValueError("MODPOW modular inverse requires modulus >= 2")
    r, old_r = value, modulus
    s, old_s = 1, 0
    while r > 0:
        quotient = old_r // r
        old_r, r = r, old_r % r
        old_s, s = s, old_s - quotient * s
    result = old_s % modulus
    if result < 0:
        result += modulus
    if (value * result) % modulus != 1:
        raise ValueError("MODPOW modular inverse does not exist")
    return result


def _range_exception_message(container_name: str, index: int, length: int) -> str:
    return f"The index of {container_name} is out of range, {index}/[0, {length})."


def _concrete_shift_failure_reason(value: int, limit: int) -> str:
    return f"Invalid shift value: {value}/{limit}"


def _symbolic_shift_failure_reason(limit: int) -> str:
    return f"Invalid shift value: outside [0, {limit}]"


def _execute_compound_or_type_op(
    state: State,
    opcode: str,
    instruction: Instruction,
) -> tuple[list[State], TerminalState | None]:
    if opcode == "SIZE":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        if is_array_like(value) or is_map(value) or is_buffer(value):
            obj = _require_heap_object(state, value, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            if isinstance(obj, MapObject):
                size = len(obj.entries)
            elif isinstance(obj, BufferObject):
                size = len(obj.data)
            else:
                size = len(obj.elements)
        elif is_bool(value) or is_int(value) or value.sort == Sort.BYTES:
            size = _primitive_size_expr(state, value, opcode)
            if isinstance(size, TerminalState):
                return [], size
        else:
            return [], _terminal(state, "faulted", f"{opcode} expects a primitive or compound value")
        terminal = _push(state, int_const(size) if isinstance(size, int) else size, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "HASKEY":
        values = _pop2(state)
        if isinstance(values, TerminalState):
            return [], values
        container, key = values
        if is_array_like(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0:
                return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
            result = bool_const(index < len(obj.elements))
        elif is_map(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            assert isinstance(obj, MapObject)
            key = _require_map_key(key, state, opcode)
            if isinstance(key, TerminalState):
                return [], key
            matches, miss_state, terminal = _branch_map_matches(state, obj, key, opcode)
            if terminal is not None:
                return [], terminal
            next_states: list[State] = []
            for branch_state, _index in matches:
                terminal = _push(branch_state, bool_const(True), opcode)
                if isinstance(terminal, TerminalState):
                    return [], terminal
                branch_state.ip = instruction.end_offset
                next_states.append(branch_state)
            if miss_state is not None:
                terminal = _push(miss_state, bool_const(False), opcode)
                if isinstance(terminal, TerminalState):
                    return [], terminal
                miss_state.ip = instruction.end_offset
                next_states.append(miss_state)
            if next_states:
                return next_states, None
            return [], _terminal(state, "stopped", "HASKEY branches were unsatisfiable")
        elif is_buffer(container):
            obj = _require_buffer_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0:
                return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
            result = bool_const(index < len(obj.data))
        elif isinstance(container, BytesConst):
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0:
                return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
            result = bool_const(index < len(container.value))
        elif container.sort == Sort.BYTES:
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0:
                return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
            size = _primitive_size_expr(state, container, opcode)
            if isinstance(size, TerminalState):
                return [], size
            condition = simplify(make_binary(">", size, int_const(index)))
            if isinstance(condition, BoolConst):
                result = condition
            else:
                hit_state = state.clone()
                miss_state = state.clone()
                next_states: list[State] = []
                if _append_condition(hit_state, condition):
                    terminal = _push(hit_state, bool_const(True), opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    hit_state.ip = instruction.end_offset
                    next_states.append(hit_state)
                if _append_condition(miss_state, negate(condition)):
                    terminal = _push(miss_state, bool_const(False), opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    miss_state.ip = instruction.end_offset
                    next_states.append(miss_state)
                if next_states:
                    return next_states, None
                return [], _terminal(state, "stopped", "HASKEY branches were unsatisfiable")
        else:
            return [], _terminal(state, "faulted", f"{opcode} expects an array, map, or byte string")
        terminal = _push(state, result, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "KEYS":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        obj = _require_heap_object(state, value, opcode)
        if isinstance(obj, TerminalState):
            return [], obj
        if not isinstance(obj, MapObject):
            return [], _terminal(state, "faulted", f"{opcode} expects a map")
        terminal = _push(state, _alloc_array(state, [key for key, _ in obj.entries]), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "VALUES":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        obj = _require_heap_object(state, value, opcode)
        if isinstance(obj, TerminalState):
            return [], obj
        source_values = [item for _, item in obj.entries] if isinstance(obj, MapObject) else list(obj.elements)
        copied_values: list[Expression] = []
        for item in source_values:
            copied = _copy_for_storage(state, item)
            if isinstance(copied, TerminalState):
                return [], copied
            copied_values.append(copied)
        terminal = _push(state, _alloc_array(state, copied_values), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "PICKITEM":
        values = _pop2(state)
        if isinstance(values, TerminalState):
            return [], values
        container, key = values
        if is_array_like(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0 or index >= len(obj.elements):
                return _catchable_engine_exception(state, _range_exception_message("VMArray", index, len(obj.elements)))
            result = obj.elements[index]
            terminal = _push(state, result, opcode)
            if isinstance(terminal, TerminalState):
                return [], terminal
            state.ip = instruction.end_offset
            return [state], None
        elif is_map(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            assert isinstance(obj, MapObject)
            key = _require_map_key(key, state, opcode)
            if isinstance(key, TerminalState):
                return [], key
            matches, miss_state, terminal = _branch_map_matches(state, obj, key, opcode)
            if terminal is not None:
                return [], terminal
            next_states: list[State] = []
            for branch_state, index in matches:
                branch_obj = _require_heap_object(branch_state, container, opcode)
                if isinstance(branch_obj, TerminalState):
                    return [], branch_obj
                assert isinstance(branch_obj, MapObject)
                terminal = _push(branch_state, branch_obj.entries[index][1], opcode)
                if isinstance(terminal, TerminalState):
                    return [], terminal
                branch_state.ip = instruction.end_offset
                next_states.append(branch_state)
            fault = None
            if miss_state is not None:
                miss_states, miss_terminal = _catchable_engine_exception(
                    miss_state,
                    f"Key {render_expr(key)} not found in Map.",
                )
                next_states.extend(miss_states)
                fault = miss_terminal
            if next_states:
                return next_states, fault
            if fault is not None:
                return [], fault
            return [], _terminal(state, "stopped", f"{opcode} branches were unsatisfiable")
        elif is_buffer(container):
            obj = _require_buffer_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0 or index >= len(obj.data):
                return _catchable_engine_exception(state, _range_exception_message("Buffer", index, len(obj.data)))
            result = int_const(obj.data[index])
        elif isinstance(container, BytesConst):
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0 or index >= len(container.value):
                return _catchable_engine_exception(
                    state,
                    _range_exception_message("PrimitiveType", index, len(container.value)),
                )
            result = int_const(container.value[index])
        elif is_bool(container) or is_int(container) or container.sort == Sort.BYTES:
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0:
                return _catchable_engine_exception(state, _range_exception_message("PrimitiveType", index, 0))
            size = _primitive_size_expr(state, container, opcode)
            if isinstance(size, TerminalState):
                return [], size
            condition = simplify(make_binary(">", size, int_const(index)))
            if isinstance(condition, BoolConst):
                if not condition.value:
                    if isinstance(size, IntConst):
                        return _catchable_engine_exception(
                            state,
                            _range_exception_message("PrimitiveType", index, size.value),
                        )
                    return _catchable_engine_exception(state, _range_exception_message("PrimitiveType", index, 0))
                result = _primitive_byte_expr(state, container, index, opcode)
                if isinstance(result, TerminalState):
                    return [], result
            else:
                hit_state = state.clone()
                miss_state = state.clone()
                next_states: list[State] = []
                if _append_condition(hit_state, condition):
                    hit_result = _primitive_byte_expr(hit_state, container, index, opcode)
                    if isinstance(hit_result, TerminalState):
                        return [], hit_result
                    terminal = _push(hit_state, hit_result, opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    hit_state.ip = instruction.end_offset
                    next_states.append(hit_state)
                fault = None
                if _append_condition(miss_state, negate(condition)):
                    miss_states, miss_terminal = _catchable_engine_exception(
                        miss_state,
                        _range_exception_message("PrimitiveType", index, 0),
                    )
                    next_states.extend(miss_states)
                    fault = miss_terminal
                if next_states:
                    return next_states, fault
                if fault is not None:
                    return [], fault
                return [], _terminal(state, "stopped", f"{opcode} branches were unsatisfiable")
        else:
            return [], _terminal(state, "faulted", f"{opcode} expects an array, map, or byte string")
        terminal = _push(state, result, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "APPEND":
        values = _pop2(state)
        if isinstance(values, TerminalState):
            return [], values
        container, value = values
        obj = _require_heap_object(state, container, opcode)
        if isinstance(obj, TerminalState):
            return [], obj
        if not isinstance(obj, (ArrayObject, StructObject)):
            return [], _terminal(state, "faulted", f"{opcode} expects an array or struct")
        stored = _copy_for_storage(state, value)
        if isinstance(stored, TerminalState):
            return [], stored
        _assert_collection_growth(state, len(obj.elements), "array")
        obj.elements.append(stored)
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "SETITEM":
        if len(state.stack) < 3:
            return [], _terminal(state, "faulted", "stack underflow")
        value = state.stack.pop()
        key = state.stack.pop()
        container = state.stack.pop()
        if is_array_like(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0 or index >= len(obj.elements):
                return _catchable_engine_exception(state, _range_exception_message("VMArray", index, len(obj.elements)))
            stored = _copy_for_storage(state, value)
            if isinstance(stored, TerminalState):
                return [], stored
            obj.elements[index] = stored
        elif is_map(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            assert isinstance(obj, MapObject)
            key = _require_map_key(key, state, opcode)
            if isinstance(key, TerminalState):
                return [], key
            stored = _copy_for_storage(state, value)
            if isinstance(stored, TerminalState):
                return [], stored
            matches, miss_state, terminal = _branch_map_matches(state, obj, key, opcode)
            if terminal is not None:
                return [], terminal
            next_states: list[State] = []
            for branch_state, index in matches:
                branch_obj = _require_heap_object(branch_state, container, opcode)
                if isinstance(branch_obj, TerminalState):
                    return [], branch_obj
                assert isinstance(branch_obj, MapObject)
                existing_key, _existing_value = branch_obj.entries[index]
                branch_obj.entries[index] = (existing_key, stored)
                branch_state.ip = instruction.end_offset
                next_states.append(branch_state)
            if miss_state is not None:
                miss_obj = _require_heap_object(miss_state, container, opcode)
                if isinstance(miss_obj, TerminalState):
                    return [], miss_obj
                assert isinstance(miss_obj, MapObject)
                _assert_collection_growth(miss_state, len(miss_obj.entries), "map")
                miss_obj.entries.append((key, stored))
                miss_state.ip = instruction.end_offset
                next_states.append(miss_state)
            if next_states:
                return next_states, None
            return [], _terminal(state, "stopped", f"{opcode} branches were unsatisfiable")
        elif is_buffer(container):
            obj = _require_buffer_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0 or index >= len(obj.data):
                return _catchable_engine_exception(state, _range_exception_message("Buffer", index, len(obj.data)))
            byte_value = _buffer_byte_value(state, value, opcode)
            if isinstance(byte_value, TerminalState):
                return [], byte_value
            obj.data[index] = byte_value
        else:
            return [], _terminal(state, "faulted", f"{opcode} expects an array, struct, map, or buffer")
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "REVERSEITEMS":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        obj = _require_heap_object(state, value, opcode)
        if isinstance(obj, TerminalState):
            return [], obj
        if isinstance(obj, (ArrayObject, StructObject)):
            obj.elements.reverse()
        elif isinstance(obj, BufferObject):
            obj.data.reverse()
        else:
            return [], _terminal(state, "faulted", f"{opcode} expects an array, struct, or buffer")
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "REMOVE":
        values = _pop2(state)
        if isinstance(values, TerminalState):
            return [], values
        container, key = values
        if is_array_like(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            index = _require_concrete_index(key, state, opcode)
            if isinstance(index, TerminalState):
                return [], index
            if index < 0 or index >= len(obj.elements):
                return [], _terminal(state, "faulted", f"{opcode} index {index} is out of range")
            del obj.elements[index]
        elif is_map(container):
            obj = _require_heap_object(state, container, opcode)
            if isinstance(obj, TerminalState):
                return [], obj
            assert isinstance(obj, MapObject)
            key = _require_map_key(key, state, opcode)
            if isinstance(key, TerminalState):
                return [], key
            matches, miss_state, terminal = _branch_map_matches(state, obj, key, opcode)
            if terminal is not None:
                return [], terminal
            next_states: list[State] = []
            for branch_state, index in matches:
                branch_obj = _require_heap_object(branch_state, container, opcode)
                if isinstance(branch_obj, TerminalState):
                    return [], branch_obj
                assert isinstance(branch_obj, MapObject)
                del branch_obj.entries[index]
                branch_state.ip = instruction.end_offset
                next_states.append(branch_state)
            if miss_state is not None:
                miss_state.ip = instruction.end_offset
                next_states.append(miss_state)
            if next_states:
                return next_states, None
            return [], _terminal(state, "stopped", f"{opcode} branches were unsatisfiable")
        else:
            return [], _terminal(state, "faulted", f"{opcode} expects an array, struct, or map")
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "CLEARITEMS":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        obj = _require_heap_object(state, value, opcode)
        if isinstance(obj, TerminalState):
            return [], obj
        if isinstance(obj, MapObject):
            obj.entries.clear()
        else:
            obj.elements.clear()
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "POPITEM":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        obj = _require_heap_object(state, value, opcode)
        if isinstance(obj, TerminalState):
            return [], obj
        if not isinstance(obj, (ArrayObject, StructObject)):
            return [], _terminal(state, "faulted", f"{opcode} expects an array or struct")
        if not obj.elements:
            return [], _terminal(state, "faulted", f"{opcode} expects a non-empty array")
        terminal = _push(state, obj.elements.pop(), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "ISNULL":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        terminal = _push(state, bool_const(is_null(value)), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "ISTYPE":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        type_byte = int(instruction.argument)
        if type_byte == STACK_ITEM_TYPE_ANY or type_byte not in VALID_STACK_ITEM_TYPES:
            return [], _terminal(state, "faulted", f"Invalid stack item type for {opcode}: {type_byte}")
        if type_byte in {STACK_ITEM_TYPE_POINTER, STACK_ITEM_TYPE_INTEROP}:
            return [], _terminal(
                state,
                "stopped",
                f"{opcode} for {STACK_ITEM_TYPE_CODE_TO_NAME[type_byte]} is not implemented yet",
            )
        terminal = _push(state, bool_const(_expression_stack_item_type(value) == type_byte), opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    if opcode == "CONVERT":
        value = _pop(state)
        if isinstance(value, TerminalState):
            return [], value
        type_byte = int(instruction.argument)
        if type_byte == STACK_ITEM_TYPE_ANY or type_byte not in VALID_STACK_ITEM_TYPES:
            return [], _terminal(state, "faulted", f"Invalid stack item type for {opcode}: {type_byte}")
        if type_byte in {STACK_ITEM_TYPE_POINTER, STACK_ITEM_TYPE_INTEROP}:
            return [], _terminal(
                state,
                "stopped",
                f"{opcode} to {STACK_ITEM_TYPE_CODE_TO_NAME[type_byte]} is not implemented yet",
            )
        if is_null(value):
            result = null_const()
        elif type_byte == STACK_ITEM_TYPE_BOOLEAN:
            if isinstance(value, BytesConst) and len(value.value) > INTEGER_MAX_SIZE:
                return [], _terminal(
                    state,
                    "faulted",
                    f"CONVERT cannot coerce byte strings larger than {INTEGER_MAX_SIZE} bytes to boolean",
                )
            result = truthy(value)
        elif type_byte == STACK_ITEM_TYPE_INTEGER:
            if isinstance(value, IntConst):
                result = value
            elif isinstance(value, BoolConst):
                result = int_const(1 if value.value else 0)
            elif is_buffer(value):
                obj = _require_buffer_object(state, value, opcode)
                if isinstance(obj, TerminalState):
                    return [], obj
                if len(obj.data) > INTEGER_MAX_SIZE:
                    return [], _terminal(
                        state,
                        "faulted",
                        f"CONVERT cannot coerce buffers larger than {INTEGER_MAX_SIZE} bytes to integers",
                    )
                result = int_const(int.from_bytes(bytes(obj.data), "little", signed=True))
            elif is_bool(value):
                result = make_unary("to_int", value)
            elif isinstance(value, BytesConst):
                if len(value.value) > INTEGER_MAX_SIZE:
                    return [], _terminal(
                        state,
                        "faulted",
                        f"CONVERT cannot coerce byte strings larger than {INTEGER_MAX_SIZE} bytes to integers",
                    )
                result = int_const(int.from_bytes(value.value, "little", signed=True))
            elif value.sort == Sort.BYTES:
                size = make_unary("size", value)
                condition = simplify(make_binary("<=", size, int_const(INTEGER_MAX_SIZE)))
                if isinstance(condition, BoolConst):
                    if not condition.value:
                        return [], _terminal(
                            state,
                            "faulted",
                            f"CONVERT cannot coerce byte strings larger than {INTEGER_MAX_SIZE} bytes to integers",
                        )
                    result = make_unary("to_int", value)
                else:
                    small_state = state.clone()
                    large_state = state.clone()
                    next_states: list[State] = []
                    if _append_condition(small_state, condition):
                        terminal = _push(small_state, make_unary("to_int", value), opcode)
                        if isinstance(terminal, TerminalState):
                            return [], terminal
                        small_state.ip = instruction.end_offset
                        next_states.append(small_state)
                    fault = None
                    if _append_condition(large_state, negate(condition)):
                        fault = _terminal(
                            large_state,
                            "faulted",
                            f"CONVERT cannot coerce byte strings larger than {INTEGER_MAX_SIZE} bytes to integers",
                        )
                    if next_states:
                        return next_states, fault
                    if fault is not None:
                        return [], fault
                    return [], _terminal(state, "stopped", "CONVERT integer branches were unsatisfiable")
            else:
                return [], _terminal(state, "faulted", f"{opcode} cannot convert {value.sort.value} to Integer")
        elif type_byte == STACK_ITEM_TYPE_BYTESTRING:
            if isinstance(value, BytesConst):
                result = value
            elif isinstance(value, BoolConst):
                result = bytes_const(b"\x01" if value.value else b"\x00")
            elif is_buffer(value):
                obj = _require_buffer_object(state, value, opcode)
                if isinstance(obj, TerminalState):
                    return [], obj
                result = bytes_const(bytes(obj.data))
            elif is_bool(value):
                result = make_unary("to_bytes", value)
            elif isinstance(value, IntConst):
                result = bytes_const(_int_to_signed_bytes(value.value))
            elif is_int(value):
                result = make_unary("to_bytes", value)
            else:
                return [], _terminal(state, "faulted", f"{opcode} cannot convert {value.sort.value} to ByteString")
        elif type_byte == STACK_ITEM_TYPE_BUFFER:
            if is_buffer(value):
                result = value
            elif isinstance(value, BoolConst):
                result = _alloc_buffer(state, bytearray(b"\x01" if value.value else b"\x00"))
            elif isinstance(value, IntConst):
                encoded = _int_to_signed_bytes(value.value)
                if len(encoded) > INTEGER_MAX_SIZE:
                    return [], _terminal(
                        state,
                        "faulted",
                        f"CONVERT cannot coerce integers larger than {INTEGER_MAX_SIZE} bytes to buffers",
                    )
                result = _alloc_buffer(state, bytearray(encoded))
            elif isinstance(value, BytesConst):
                result = _alloc_buffer(state, bytearray(value.value))
            elif is_bool(value):
                true_state = state.clone()
                false_state = state.clone()
                next_states: list[State] = []
                if _append_condition(true_state, value):
                    terminal = _push(true_state, _alloc_buffer(true_state, bytearray(b"\x01")), opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    true_state.ip = instruction.end_offset
                    next_states.append(true_state)
                if _append_condition(false_state, negate(value)):
                    terminal = _push(false_state, _alloc_buffer(false_state, bytearray(b"\x00")), opcode)
                    if isinstance(terminal, TerminalState):
                        return [], terminal
                    false_state.ip = instruction.end_offset
                    next_states.append(false_state)
                if next_states:
                    return next_states, None
                return [], _terminal(state, "stopped", "CONVERT buffer branches were unsatisfiable")
            elif is_int(value):
                return [], _terminal(
                    state,
                    "stopped",
                    "CONVERT from symbolic integers to buffers is not implemented yet",
                )
            elif value.sort == Sort.BYTES:
                return [], _terminal(
                    state,
                    "stopped",
                    "CONVERT from symbolic byte strings to buffers is not implemented yet",
                )
            else:
                return [], _terminal(state, "faulted", f"{opcode} cannot convert {value.sort.value} to Buffer")
        elif type_byte == STACK_ITEM_TYPE_ARRAY:
            if not isinstance(value, HeapRef):
                return [], _terminal(state, "faulted", f"{opcode} cannot convert {value.sort.value} to Array")
            if value.ref_sort == Sort.ARRAY:
                result = value
            elif value.ref_sort == Sort.STRUCT:
                obj = _require_heap_object(state, value, opcode)
                if isinstance(obj, TerminalState):
                    return [], obj
                assert isinstance(obj, StructObject)
                result = _alloc_array(state, list(obj.elements))
            else:
                return [], _terminal(state, "faulted", f"{opcode} cannot convert map to Array")
        elif type_byte == STACK_ITEM_TYPE_STRUCT:
            if not isinstance(value, HeapRef):
                return [], _terminal(state, "faulted", f"{opcode} cannot convert {value.sort.value} to Struct")
            if value.ref_sort == Sort.STRUCT:
                result = value
            elif value.ref_sort == Sort.ARRAY:
                obj = _require_heap_object(state, value, opcode)
                if isinstance(obj, TerminalState):
                    return [], obj
                assert isinstance(obj, ArrayObject)
                result = _alloc_struct(state, list(obj.elements))
            else:
                return [], _terminal(state, "faulted", f"{opcode} cannot convert map to Struct")
        elif type_byte == STACK_ITEM_TYPE_MAP:
            if is_map(value):
                result = value
            else:
                return [], _terminal(state, "faulted", f"{opcode} cannot convert {value.sort.value} to Map")
        else:
            return [], _terminal(state, "stopped", f"{opcode} target {type_byte} is not implemented yet")
        integer_limit = _ensure_vm_integer_limit(state, result, opcode)
        if integer_limit is not None:
            return [], integer_limit
        terminal = _push(state, result, opcode)
        if isinstance(terminal, TerminalState):
            return [], terminal
        state.ip = instruction.end_offset
        return [state], None

    raise ValueError(f"Unhandled compound or type opcode {opcode}")
