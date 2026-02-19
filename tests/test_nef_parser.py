"""Tests for NEF parser."""
import struct
from neo_sym.nef.opcodes import OpCode
from neo_sym.nef.parser import disassemble, Instruction


def test_disassemble_push():
    script = bytes([OpCode.PUSH0, OpCode.PUSH1, OpCode.PUSH16])
    instrs = disassemble(script)
    assert len(instrs) == 3
    assert instrs[0].opcode == OpCode.PUSH0
    assert instrs[1].opcode == OpCode.PUSH1
    assert instrs[2].opcode == OpCode.PUSH16


def test_disassemble_arithmetic():
    script = bytes([OpCode.PUSH1, OpCode.PUSH2, OpCode.ADD])
    instrs = disassemble(script)
    assert len(instrs) == 3
    assert instrs[2].opcode == OpCode.ADD


def test_disassemble_jmp():
    script = bytes([OpCode.JMP, 0x03, OpCode.NOP, OpCode.RET])
    instrs = disassemble(script)
    assert instrs[0].opcode == OpCode.JMP
    assert instrs[0].operand == bytes([0x03])


def test_disassemble_syscall():
    script = bytes([OpCode.SYSCALL]) + struct.pack("<I", 0x12345678)
    instrs = disassemble(script)
    assert instrs[0].opcode == OpCode.SYSCALL
    assert len(instrs[0].operand) == 4


def test_disassemble_pushdata1():
    data = b"\x01\x02\x03"
    script = bytes([OpCode.PUSHDATA1, len(data)]) + data
    instrs = disassemble(script)
    assert instrs[0].opcode == OpCode.PUSHDATA1
    assert data in instrs[0].operand


def test_disassemble_pushdata2():
    data = bytes([i % 256 for i in range(260)])
    script = bytes([OpCode.PUSHDATA2]) + struct.pack("<H", len(data)) + data
    instrs = disassemble(script)
    assert len(instrs) == 1
    assert instrs[0].opcode == OpCode.PUSHDATA2
    assert instrs[0].operand[2:] == data


def test_disassemble_pushdata4():
    data = b"A" * 300
    script = bytes([OpCode.PUSHDATA4]) + struct.pack("<I", len(data)) + data
    instrs = disassemble(script)
    assert len(instrs) == 1
    assert instrs[0].opcode == OpCode.PUSHDATA4
    assert instrs[0].operand[4:] == data
