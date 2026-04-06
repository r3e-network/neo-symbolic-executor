#!/usr/bin/env python3
"""
Structured fuzzing harness for NeoVM bytecode generation and execution.

This harness uses the fuzzer input to generate structured, valid-looking
NeoVM bytecode sequences rather than completely random bytes. This helps
reach deeper code paths in the execution engine.
"""
from __future__ import annotations

import sys
from dataclasses import replace
from typing import TYPE_CHECKING

import atheris

try:
    from ._bootstrap import configure_repo_root
except ImportError:
    from _bootstrap import configure_repo_root

configure_repo_root()

with atheris.instrument_imports():
    from neo_symbolic_executor.bytecode import DecodeError, decode_script
    from neo_symbolic_executor.engine import ExecutionOptions, explore_program
    from neo_symbolic_executor.expr import int_symbol
    from neo_symbolic_executor.opcodes import OPCODE_BY_NAME

if TYPE_CHECKING:
    from neo_symbolic_executor.opcodes import OpCodeSpec


# Safe execution limits
SAFE_LIMITS = ExecutionOptions(
    max_steps=500,
    max_states=50,
    max_visits_per_instruction=5,
    max_item_size=512,
    max_collection_size=50,
    max_heap_objects=30,
    max_invocation_stack=5,
    max_try_nesting_depth=3,
    max_shift=64,
)

# Opcodes that are safe to fuzz (no external effects, bounded execution)
SAFE_OPCODES: list[OpCodeSpec] = [
    OPCODE_BY_NAME[name]
    for name in [
        # Constants
        "PUSH0", "PUSH1", "PUSH2", "PUSH3", "PUSH4", "PUSH5",
        "PUSHM1", "PUSH10", "PUSH16",
        "PUSHNULL", "PUSHT", "PUSHF",
        # Stack ops
        "DROP", "DUP", "SWAP", "OVER", "PICK", "ROLL", "ROT",
        "DEPTH", "NIP", "TUCK",
        "REVERSE3", "REVERSE4",
        # Arithmetic
        "ADD", "SUB", "MUL", "DIV", "MOD",
        "ABS", "NEGATE", "INC", "DEC",
        "SHL", "SHR",
        "AND", "OR", "XOR", "INVERT", "NOT",
        # Comparison
        "EQUAL", "NOTEQUAL", "NUMEQUAL", "NUMNOTEQUAL",
        "LT", "LE", "GT", "GE",
        "SIGN", "NZ",
        # Control flow (simple forms)
        "RET", "NOP",
        # Logic
        "BOOLAND", "BOOLOR",
        "MIN", "MAX", "WITHIN",
        # Type checking
        "ISNULL",
        # Collection basics
        "NEWARRAY0", "NEWSTRUCT0", "NEWMAP",
        "PACK", "UNPACK", "SIZE",
    ]
    if name in OPCODE_BY_NAME
]

# Opcodes with operands that we can generate
OPERAND_OPCODES: dict[str, tuple[int, callable]] = {
    "PUSHINT8": (1, lambda d, i: d[i:i+1].ljust(1, b'\x00')),
    "PUSHINT16": (2, lambda d, i: d[i:i+2].ljust(2, b'\x00')),
    "PUSHINT32": (4, lambda d, i: d[i:i+4].ljust(4, b'\x00')),
    "PUSHDATA1": (1, lambda d, i: _make_pushdata(d, i, 1, 0xFF)),
    "PUSHDATA2": (2, lambda d, i: _make_pushdata(d, i, 2, 0xFFFF)),
    "JMP": (1, lambda d, i: d[i:i+1].ljust(1, b'\x00')),
    "JMPEQ": (1, lambda d, i: d[i:i+1].ljust(1, b'\x00')),
    "JMPNE": (1, lambda d, i: d[i:i+1].ljust(1, b'\x00')),
    "INITSLOT": (2, lambda d, i: d[i:i+2].ljust(2, b'\x00')),
    "LDSFLD0": (0, lambda d, i: b""),
    "STSFLD0": (0, lambda d, i: b""),
    "LDLOC0": (0, lambda d, i: b""),
    "STLOC0": (0, lambda d, i: b""),
    "LDARG0": (0, lambda d, i: b""),
    "STARG0": (0, lambda d, i: b""),
}


def _make_pushdata(data: bytes, idx: int, size_bytes: int, max_len: int) -> bytes:
    """Generate a PUSHDATA payload with length prefix."""
    length = 0 if idx >= len(data) else data[idx] if size_bytes == 1 else int.from_bytes(data[idx:idx+2], "little")
    length = min(length, max_len, 100)  # Cap payload size
    payload_start = idx + size_bytes
    payload = data[payload_start:payload_start + length]
    prefix = length.to_bytes(size_bytes, 'little')
    return prefix + payload


def generate_bytecode(data: bytes) -> bytes:
    """Generate NeoVM bytecode from fuzzer input."""
    if len(data) < 2:
        return b"\x00"  # Invalid opcode

    result = bytearray()
    i = 0

    # First byte determines generation mode
    mode = data[0] % 4
    i += 1

    if mode == 0:
        # Mode 0: Random safe opcodes
        while i < len(data) and len(result) < 200:
            opcode_idx = data[i] % len(SAFE_OPCODES)
            spec = SAFE_OPCODES[opcode_idx]
            result.append(spec.code)
            i += 1

    elif mode == 1:
        # Mode 1: Opcodes with operands
        while i < len(data) and len(result) < 200:
            op_name = list(OPERAND_OPCODES.keys())[data[i] % len(OPERAND_OPCODES)]
            spec = OPCODE_BY_NAME[op_name]
            result.append(spec.code)
            i += 1
            size, generator = OPERAND_OPCODES[op_name]
            if size > 0:
                operand = generator(data, i)
                result.extend(operand)
                i += size

    elif mode == 2:
        # Mode 2: Try to build valid programs with init
        if len(data) > i:
            # Add INITSLOT
            result.append(OPCODE_BY_NAME["INITSLOT"].code)
            locals_count = data[i] % 5
            args_count = (data[i] >> 4) % 3
            result.extend([locals_count, args_count])
            i += 1

            # Add some opcodes
            while i < len(data) and len(result) < 200:
                if data[i] % 8 == 0:
                    result.append(OPCODE_BY_NAME["RET"].code)
                    break
                opcode_idx = data[i] % len(SAFE_OPCODES)
                spec = SAFE_OPCODES[opcode_idx]
                result.append(spec.code)
                i += 1

    else:
        # Mode 3: Raw bytes (may be invalid)
        result.extend(data[i:i+100])

    # Ensure program ends with RET if it doesn't have one
    if b"\x40" not in result and len(result) < 200:  # RET = 0x40
        result.append(0x40)

    return bytes(result)


def test_one_input(data: bytes) -> None:
    """Test execution with structured bytecode."""
    try:
        bytecode = generate_bytecode(data)
        program = decode_script(bytecode)

        # Sometimes use symbolic inputs
        if len(data) > 0 and data[-1] % 2 == 0:
            options = replace(
                SAFE_LIMITS,
                initial_stack=(int_symbol("x"), int_symbol("y")) if len(data) > 2 else (),
            )
        else:
            options = SAFE_LIMITS

        report = explore_program(program, options)
        assert report.to_dict() == explore_program(program, options).to_dict()
    except DecodeError:
        # Raw-mode generation can still produce invalid bytecode.
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
