"""Bytecode, manifest, and execution-state generators for fuzzing."""
from __future__ import annotations

import json
import random
from typing import Sequence

from neo_sym.nef.opcodes import FIXED_OPERAND_SIZES, PREFIX_OPERAND_SIZES, OpCode
from neo_sym.nef.parser import CALL_FLAGS_ALL, NEF3_MAGIC, compute_nef_checksum
from neo_sym.nef.manifest import (
    ContractEvent,
    ContractMethod,
    ContractPermission,
    Manifest,
    MethodParameter,
)
from neo_sym.nef.syscalls import SYSCALLS_BY_ID
from neo_sym.engine.state import (
    ArithmeticOp,
    ExecutionState,
    ExternalCall,
    StorageOp,
    SymbolicValue,
)

R = random.Random()

SYSCALL_IDS: list[int] = list(SYSCALLS_BY_ID.keys()) or [0]

# Opcodes the engine dispatches (not just tracked as unknown).
HANDLED_OPS: list[OpCode] = [
    OpCode.PUSH0, OpCode.PUSH1, OpCode.PUSH2, OpCode.PUSH3, OpCode.PUSH4,
    OpCode.PUSH5, OpCode.PUSH8, OpCode.PUSH16,
    OpCode.PUSHINT8, OpCode.PUSHINT16, OpCode.PUSHINT32, OpCode.PUSHINT64,
    OpCode.PUSHINT128, OpCode.PUSHINT256,
    OpCode.PUSHDATA1, OpCode.PUSHT, OpCode.PUSHF, OpCode.PUSHM1, OpCode.PUSHNULL,
    OpCode.NOP, OpCode.DUP, OpCode.DROP, OpCode.SWAP, OpCode.OVER,
    OpCode.NIP, OpCode.CLEAR, OpCode.DEPTH, OpCode.ISNULL,
    OpCode.ROT, OpCode.TUCK, OpCode.REVERSE3, OpCode.REVERSE4,
    OpCode.ADD, OpCode.SUB, OpCode.MUL, OpCode.DIV, OpCode.MOD,
    OpCode.INC, OpCode.DEC, OpCode.NEGATE, OpCode.ABS, OpCode.SIGN,
    OpCode.NOT, OpCode.NZ, OpCode.BOOLAND, OpCode.BOOLOR,
    OpCode.AND, OpCode.OR, OpCode.XOR, OpCode.INVERT,
    OpCode.SHL, OpCode.SHR,
    OpCode.EQUAL, OpCode.NUMEQUAL, OpCode.NOTEQUAL, OpCode.NUMNOTEQUAL,
    OpCode.LT, OpCode.GT, OpCode.LE, OpCode.GE,
    OpCode.MIN, OpCode.MAX, OpCode.WITHIN,
    OpCode.INITSLOT, OpCode.LDLOC0, OpCode.STLOC0, OpCode.LDLOC, OpCode.STLOC,
    OpCode.LDARG0, OpCode.STARG0, OpCode.LDARG, OpCode.STARG,
    OpCode.ASSERT, OpCode.ABORT, OpCode.THROW,
    OpCode.JMPIF, OpCode.JMPIFNOT, OpCode.JMPEQ, OpCode.JMPNE,
    OpCode.JMPGT, OpCode.JMPGE, OpCode.JMPLT, OpCode.JMPLE,
    OpCode.JMP, OpCode.CALL,
    OpCode.TRY, OpCode.ENDTRY, OpCode.ENDFINALLY,
    OpCode.SYSCALL, OpCode.CALLT, OpCode.RET,
]

# Ops unsafe to place arbitrarily (need careful context).
_CONTEXT_OPS = frozenset({
    OpCode.INITSLOT, OpCode.RET, OpCode.ABORT, OpCode.THROW,
    OpCode.ENDFINALLY, OpCode.ENDTRY, OpCode.CALLT,
})

_SAFE_FILLERS = [OpCode.PUSH0, OpCode.PUSH1, OpCode.NOP, OpCode.DUP, OpCode.DROP]


def seed(value: int) -> None:
    R.seed(value)
    random.seed(value)


def _rand_bytes(n: int) -> bytes:
    return bytes(R.getrandbits(8) for _ in range(n))


def _emit_operand(buf: bytearray, op: OpCode) -> None:
    """Append the correct operand bytes for *op*."""
    prefix = PREFIX_OPERAND_SIZES.get(op)
    if prefix is not None:
        payload = _rand_bytes(R.randint(0, 16))
        if prefix == 1:
            buf.append(len(payload) & 0xFF)
        elif prefix == 2:
            buf.extend((len(payload) & 0xFFFF).to_bytes(2, "little"))
        else:
            buf.extend((len(payload) & 0xFFFFFFFF).to_bytes(4, "little"))
        buf.extend(payload)
        return
    fixed = FIXED_OPERAND_SIZES.get(op, 0)
    if not fixed:
        return
    if op == OpCode.SYSCALL:
        buf.extend(R.choice(SYSCALL_IDS).to_bytes(4, "little"))
    elif op in (OpCode.CALL, OpCode.JMP, OpCode.JMPIF, OpCode.JMPIFNOT,
                OpCode.JMPEQ, OpCode.JMPNE, OpCode.JMPGT, OpCode.JMPGE,
                OpCode.JMPLT, OpCode.JMPLE, OpCode.ENDTRY):
        buf.append(R.randint(0, 255))
    elif op == OpCode.TRY:
        buf.extend(bytes([R.randint(2, 20), R.choice([0, R.randint(2, 20)])]))
    else:
        buf.extend(_rand_bytes(fixed))


# ── Bytecode generators ────────────────────────────────────────────

def random_bytes(n: int = 64) -> bytes:
    return _rand_bytes(n)


def valid_program(size: int = 20) -> bytes:
    """Syntactically valid NeoVM program of *size* instructions."""
    buf = bytearray()
    for i in range(size - 1):
        op = R.choice(HANDLED_OPS)
        if op in _CONTEXT_OPS:
            op = R.choice(_SAFE_FILLERS)
        buf.append(op)
        _emit_operand(buf, op)
    buf.append(OpCode.RET)
    return bytes(buf)


def large_program(size: int = 200) -> bytes:
    """Large program with INITSLOT preamble."""
    buf = bytearray()
    buf.append(OpCode.INITSLOT)
    buf.extend(bytes([R.randint(1, 7), R.randint(0, 4)]))
    for _ in range(size - 1):
        op = R.choice(HANDLED_OPS)
        if op in _CONTEXT_OPS:
            op = R.choice(_SAFE_FILLERS)
        buf.append(op)
        _emit_operand(buf, op)
    buf.append(OpCode.RET)
    return bytes(buf)


def branch_explosion(depth: int = 8) -> bytes:
    """2^depth conditional branch paths."""
    buf = bytearray()
    for _ in range(depth):
        buf.append(OpCode.PUSHINT8)
        buf.append(R.randint(0, 255))
        buf.append(OpCode.PUSHINT8)
        buf.append(R.randint(0, 255))
        buf.append(R.choice([OpCode.JMPEQ, OpCode.JMPNE, OpCode.JMPGT,
                              OpCode.JMPGE, OpCode.JMPLT, OpCode.JMPLE,
                              OpCode.JMPIF, OpCode.JMPIFNOT]))
        buf.append(0x02)
        buf.append(OpCode.NOP)
    for _ in range(R.randint(5, 20)):
        buf.append(R.choice([OpCode.PUSH0, OpCode.PUSH1, OpCode.ADD,
                             OpCode.SUB, OpCode.DUP, OpCode.DROP]))
    buf.append(OpCode.RET)
    return bytes(buf)


def syscall_chain(length: int = 20) -> bytes:
    """Many syscalls interleaved with stack ops."""
    buf = bytearray()
    for _ in range(length):
        for _ in range(R.randint(0, 4)):
            buf.append(R.choice([OpCode.PUSH0, OpCode.PUSH1, OpCode.PUSHT,
                                 OpCode.PUSHF, OpCode.PUSHNULL, OpCode.DUP]))
        buf.append(OpCode.SYSCALL)
        buf.extend(R.choice(SYSCALL_IDS).to_bytes(4, "little"))
        if R.random() > 0.5:
            op = R.choice([OpCode.DROP, OpCode.ASSERT, OpCode.JMPIF, OpCode.JMPIFNOT])
            buf.append(op)
            if op in (OpCode.JMPIF, OpCode.JMPIFNOT):
                buf.append(0x02)
                buf.append(OpCode.NOP)
    buf.append(OpCode.RET)
    return bytes(buf)


def nested_try(depth: int = 4) -> bytes:
    """Nested try/catch/finally blocks."""
    buf = bytearray()
    for _ in range(depth):
        buf.append(OpCode.TRY)
        buf.extend(bytes([R.randint(3, 10) & 0xFF, R.choice([0, R.randint(3, 12) & 0xFF])]))
        for _ in range(R.randint(1, 3)):
            buf.append(R.choice(_SAFE_FILLERS))
    if R.random() > 0.5:
        buf.extend([OpCode.PUSH1, OpCode.THROW])
    else:
        buf.extend([OpCode.ENDTRY, 0x02, OpCode.NOP])
    for _ in range(depth * 3):
        buf.append(R.choice([OpCode.NOP, OpCode.DROP, OpCode.RET, OpCode.ENDFINALLY]))
    buf.append(OpCode.RET)
    return bytes(buf)


def arithmetic_torture(count: int = 50) -> bytes:
    """Extreme-value arithmetic."""
    buf = bytearray()
    size_map = {1: OpCode.PUSHINT8, 2: OpCode.PUSHINT16, 4: OpCode.PUSHINT32,
                8: OpCode.PUSHINT64, 16: OpCode.PUSHINT128, 32: OpCode.PUSHINT256}
    for _ in range(count):
        sz = R.choice(list(size_map))
        buf.append(size_map[sz])
        if R.random() > 0.5:
            extremes = [0, 1, -1, 127, -128, 2**15 - 1, -(2**15), 2**31 - 1, -(2**31)]
            val = R.choice(extremes)
            try:
                buf.extend(val.to_bytes(sz, "little", signed=True))
            except OverflowError:
                buf.extend(_rand_bytes(sz))
        else:
            buf.extend(_rand_bytes(sz))
        if R.random() > 0.3:
            buf.append(R.choice([
                OpCode.ADD, OpCode.SUB, OpCode.MUL, OpCode.DIV, OpCode.MOD,
                OpCode.SHL, OpCode.SHR, OpCode.AND, OpCode.OR, OpCode.XOR,
                OpCode.NEGATE, OpCode.ABS, OpCode.INC, OpCode.DEC,
                OpCode.INVERT, OpCode.SIGN, OpCode.NOT, OpCode.NZ,
                OpCode.MIN, OpCode.MAX, OpCode.EQUAL, OpCode.LT, OpCode.GT,
            ]))
    buf.append(OpCode.RET)
    return bytes(buf)


def realistic_contract() -> bytes:
    """Approximation of a NEP-17 contract: CheckWitness -> branch -> Storage.Put."""
    buf = bytearray()
    buf.append(OpCode.INITSLOT)
    buf.extend(bytes([3, 3]))
    buf.append(OpCode.LDARG0)
    buf.append(OpCode.SYSCALL)
    _emit_witness_syscall(buf)
    buf.extend([OpCode.JMPIF, 0x03, OpCode.PUSH0, OpCode.RET])
    buf.append(OpCode.LDARG0)
    buf.append(OpCode.SYSCALL)
    _emit_storage_ctx_syscall(buf)
    buf.extend([OpCode.LDARG1, OpCode.LDARG2])
    buf.append(OpCode.SYSCALL)
    _emit_storage_put_syscall(buf)
    for _ in range(R.randint(10, 50)):
        buf.append(R.choice(_SAFE_FILLERS + [OpCode.ADD, OpCode.SUB]))
    buf.extend([OpCode.PUSH1, OpCode.RET])
    return bytes(buf)


def _emit_witness_syscall(buf: bytearray) -> None:
    for sid, info in SYSCALLS_BY_ID.items():
        if "CheckWitness" in info.name:
            buf.extend(sid.to_bytes(4, "little"))
            return
    buf.extend(R.choice(SYSCALL_IDS).to_bytes(4, "little"))


def _emit_storage_ctx_syscall(buf: bytearray) -> None:
    for sid, info in SYSCALLS_BY_ID.items():
        if "Storage.GetContext" in info.name:
            buf.extend(sid.to_bytes(4, "little"))
            return
    buf.extend(R.choice(SYSCALL_IDS).to_bytes(4, "little"))


def _emit_storage_put_syscall(buf: bytearray) -> None:
    for sid, info in SYSCALLS_BY_ID.items():
        if "Storage.Put" in info.name:
            buf.extend(sid.to_bytes(4, "little"))
            return
    buf.extend(R.choice(SYSCALL_IDS).to_bytes(4, "little"))


def deep_stack(count: int = 30) -> bytes:
    """Push many values then manipulate the stack."""
    buf = bytearray()
    for _ in range(count):
        buf.append(R.choice([OpCode.PUSH0, OpCode.PUSH1, OpCode.PUSHT,
                             OpCode.PUSHF, OpCode.PUSHNULL]))
    for _ in range(R.randint(1, 10)):
        buf.append(R.choice([OpCode.DUP, OpCode.SWAP, OpCode.OVER, OpCode.DROP,
                             OpCode.NIP, OpCode.ROT, OpCode.TUCK, OpCode.REVERSE3,
                             OpCode.DEPTH, OpCode.CLEAR]))
    buf.append(OpCode.RET)
    return bytes(buf)


# ── Mutation engine ────────────────────────────────────────────────

def mutate(data: bytes, intensity: int = 0) -> bytes:
    """Mutate bytecode — bit flips, insertions, deletions, swaps.

    *intensity* 0 = light (1-3 mutations), 1 = medium (3-10), 2 = heavy (10-30).
    """
    buf = bytearray(data)
    if not buf:
        return data
    counts = [(1, 3), (3, 10), (10, 30)]
    lo, hi = counts[min(intensity, 2)]
    num = R.randint(lo, max(lo, min(hi, len(buf) // 4)))
    for _ in range(num):
        action = R.choice(["flip", "replace", "insert", "delete", "swap"])
        if action == "flip" and buf:
            i = R.randint(0, len(buf) - 1)
            buf[i] ^= 1 << R.randint(0, 7)
        elif action == "replace" and buf:
            buf[R.randint(0, len(buf) - 1)] = R.randint(0, 255)
        elif action == "insert":
            buf.insert(R.randint(0, len(buf)), R.randint(0, 255))
        elif action == "delete" and len(buf) > 1:
            del buf[R.randint(0, len(buf) - 1)]
        elif action == "swap" and len(buf) >= 2:
            i, j = R.sample(range(len(buf)), 2)
            buf[i], buf[j] = buf[j], buf[i]
    return bytes(buf)


# ── NEF envelope builder ───────────────────────────────────────────

def nef_envelope(script: bytes, *, num_tokens: int = 0, corrupt: bool = False) -> bytes:
    buf = bytearray()
    buf.extend(NEF3_MAGIC.to_bytes(4, "little"))
    buf.extend(b"fuzz-compiler\x00".ljust(64, b"\x00"))
    buf.append(0)  # empty source
    buf.append(0)  # reserved byte
    buf.append(num_tokens)
    for _ in range(num_tokens):
        buf.extend(_rand_bytes(20))
        name = R.choice([b"transfer", b"approve", _rand_bytes(R.randint(1, 10))])
        buf.append(len(name))
        buf.extend(name)
        buf.extend(R.randint(0, 10).to_bytes(2, "little"))
        buf.append(R.choice([0, 1]))
        buf.append(R.randint(0, CALL_FLAGS_ALL))
    buf.extend((0).to_bytes(2, "little"))
    if len(script) < 256:
        buf.append(len(script))
    else:
        buf.append(0xFD)
        buf.extend(len(script).to_bytes(2, "little"))
    buf.extend(script)
    cs = compute_nef_checksum(bytes(buf))
    if corrupt:
        cs ^= R.randint(1, 0xFFFFFFFF)
    buf.extend(cs.to_bytes(4, "little"))
    return bytes(buf)


# ── Manifest generators ────────────────────────────────────────────

def rich_manifest() -> Manifest:
    """Feature-rich manifest for detector coverage."""
    methods = []
    for name in ["transfer", "balanceOf", "symbol", "decimals", "totalSupply",
                  "update", "destroy", "_deploy", "onNEP17Payment"]:
        if R.random() > 0.3:
            methods.append(ContractMethod(
                name=name, offset=R.randint(0, 200),
                parameters=[MethodParameter(name=f"p{i}", type=R.choice(["Hash160", "Integer", "ByteArray", "Any"]))
                            for i in range(R.randint(0, 5))],
                return_type=R.choice(["Boolean", "Void", "Integer", None]),
                safe=R.choice([True, False]),
            ))
    perms = [ContractPermission(
        contract=R.choice(["*", "0x" + _rand_bytes(20).hex()]),
        methods=R.choice([["*"], ["transfer", "approve"], []]),
    ) for _ in range(R.randint(0, 4))]
    return Manifest(
        name=R.choice(["FuzzToken", "TestDAO", ""]),
        supported_standards=R.choice([[], ["NEP-17"], ["NEP-11"]]),
        abi_methods=methods,
        abi_events=[ContractEvent(name="Transfer", parameters=[
            MethodParameter(name="from", type="Hash160"),
            MethodParameter(name="to", type="Hash160"),
            MethodParameter(name="amount", type="Integer"),
        ])] if R.random() > 0.3 else [],
        permissions=perms,
    )


def malformed_manifest_json() -> str:
    """JSON that hammers manifest parser edge cases."""
    methods = []
    for _ in range(R.randint(0, 15)):
        methods.append({
            "name": R.choice(["transfer", "", None, 42, "x" * 200]),
            "offset": R.choice([0, -1, 2**31, 3.14, "bad", None, float("inf")]),
            "parameters": R.choice([[], "not-a-list", None, 42,
                                     [{"name": "a", "type": "Hash160"}] * R.randint(0, 10)]),
            "returntype": R.choice(["Boolean", None, 42, ["list"]]),
            "safe": R.choice([True, False, "yes", None]),
        })
    perms = [{
        "contract": R.choice(["*", "0xabc", "", None, 42]),
        "methods": R.choice(["*", ["transfer"], [], None, 42]),
    } for _ in range(R.randint(0, 5))]
    obj = {
        "name": R.choice(["Test", "", None, 42]),
        "supportedstandards": R.choice([[], ["NEP-17"], "not-a-list", None]),
        "abi": R.choice([{"methods": methods, "events": []}, "not-a-dict", None]),
        "permissions": perms,
        "trusts": R.choice([[], None]),
        "groups": R.choice([[], None, [{}]]),
        "extra": R.choice([{}, None, "string"]),
    }
    raw = json.dumps(obj)
    if R.random() < 0.1:
        raw = mutate(raw.encode(), intensity=0).decode("utf-8", errors="replace")
    return raw


# ── Execution state generators ─────────────────────────────────────

def random_state() -> ExecutionState:
    """Random ExecutionState for detector fuzzing."""
    state = ExecutionState(pc=R.randint(0, 1000), halted=True,
                           gas_cost=R.randint(0, 200_000),
                           max_call_stack_depth=R.randint(0, 20),
                           reentrancy_guard=R.choice([True, False]))
    for _ in range(R.randint(0, 10)):
        state.stack.append(SymbolicValue(
            concrete=R.choice([None, R.randint(-2**64, 2**64), True, False]),
            name=R.choice([None, f"sym_{R.randint(0, 999)}", f"witness_ok_{R.randint(0, 100)}"]),
        ))
    for _ in range(R.randint(0, 5)):
        state.storage_ops.append(StorageOp(
            op_type=R.choice(["put", "get", "delete"]),
            key=SymbolicValue(concrete=R.choice([R.randint(0, 255), b"key", None])),
            offset=R.randint(-1, 500),
        ))
    for _ in range(R.randint(0, 4)):
        state.external_calls.append(ExternalCall(
            contract_hash=R.choice([_rand_bytes(20), None]),
            method=R.choice(["transfer", "Contract.Call:approve", "ContractManagement.Update", ""]),
            offset=R.randint(-1, 500),
            return_checked=R.choice([True, False]),
            target_hash_dynamic=R.choice([True, False]),
            method_dynamic=R.choice([True, False]),
            call_flags=R.choice([None, 0, CALL_FLAGS_ALL, R.randint(0, 15)]),
            call_flags_dynamic=R.choice([True, False]),
            has_return_value=R.choice([True, False]),
        ))
    if R.random() > 0.4:
        state.witness_checks = [R.randint(0, 500) for _ in range(R.randint(1, 3))]
    if R.random() > 0.5:
        state.witness_checks_enforced = [R.randint(0, 500) for _ in range(R.randint(0, 2))]
    if R.random() > 0.6:
        state.time_accesses = [R.randint(0, 500)]
    if R.random() > 0.7:
        state.randomness_accesses = [R.randint(0, 500)]
    for _ in range(R.randint(0, 3)):
        state.arithmetic_ops.append(ArithmeticOp(
            opcode=R.choice(["ADD", "SUB", "MUL", "DIV"]),
            offset=R.randint(0, 500),
            left=SymbolicValue(concrete=R.randint(-2**128, 2**128)),
            right=SymbolicValue(concrete=R.choice([0, 1, -1, 2**63])),
            overflow_possible=R.choice([True, False]),
            checked=R.choice([True, False]),
        ))
    if R.random() > 0.5:
        state.loops_detected = [R.randint(0, 500)]
    state.events_emitted = [R.choice(["Transfer", ""]) for _ in range(R.randint(0, 3))]
    for _ in range(R.randint(0, 5)):
        state.constraints.append(R.choice([
            ("eq", R.randint(0, 100)), [R.randint(0, 100)], {"k": [1, 2]}, 42,
        ]))
    return state


def extreme_state() -> ExecutionState:
    """Boundary-value ExecutionState."""
    state = ExecutionState(halted=True,
                           gas_cost=R.choice([0, 49999, 50000, 50001, 2**31]),
                           max_call_stack_depth=R.choice([0, 7, 8, 9, 100]),
                           depth=R.choice([0, 127, 128, 1000]))
    n_ops = R.choice([0, 1, 31, 32, 33, 100])
    for _ in range(n_ops):
        state.storage_ops.append(StorageOp(
            op_type="put", key=SymbolicValue(concrete=R.randint(0, 255)), offset=R.randint(0, 500)))
    for _ in range(R.choice([0, 1, 5, 10])):
        state.external_calls.append(ExternalCall(
            contract_hash=_rand_bytes(20),
            method=R.choice(["transfer", "Contract.Call:transfer", "ContractManagement.Update"]),
            offset=R.randint(0, 500), call_flags=R.choice([None, 0, CALL_FLAGS_ALL]),
        ))
    if R.random() > 0.3:
        state.witness_checks = [R.randint(0, 500)]
        if R.random() > 0.5:
            state.witness_checks_enforced = [R.randint(0, 500)]
    return state
