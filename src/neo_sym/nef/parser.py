"""NEF parser and NeoVM disassembler."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from .opcodes import FIXED_OPERAND_SIZES, PREFIX_OPERAND_SIZES, OpCode


NEF3_MAGIC = 0x3346454E
MAX_SOURCE_LENGTH = 256
MAX_METHOD_TOKENS = 128
MAX_METHOD_NAME_LENGTH = 32
MAX_SCRIPT_LENGTH = 65_535 * 2
CALL_FLAGS_ALL = 0x0F


@dataclass(slots=True)
class Instruction:
    opcode: OpCode
    offset: int
    operand: bytes = b""
    size: int = 1


@dataclass(slots=True)
class MethodToken:
    hash: bytes
    method: str
    parameters_count: int
    has_return_value: bool
    call_flags: int


@dataclass(slots=True)
class NefFile:
    script: bytes
    instructions: list[Instruction]
    compiler: str = "unknown"
    source: str = ""
    tokens: list[MethodToken] = field(default_factory=list)
    checksum: int | None = None
    checksum_valid: bool | None = None
    magic: int | None = None

    instruction_map: dict[int, Instruction] = field(init=False)

    def __post_init__(self) -> None:
        self.instruction_map = {instr.offset: instr for instr in self.instructions}


class _BufferReader:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    @property
    def remaining(self) -> int:
        return len(self._data) - self._offset

    def read_bytes(self, length: int) -> bytes:
        if length < 0:
            raise ValueError("negative length")
        end = self._offset + length
        if end > len(self._data):
            raise ValueError("Unexpected end of NEF data")
        value = self._data[self._offset : end]
        self._offset = end
        return value

    def read_u8(self) -> int:
        return self.read_bytes(1)[0]

    def read_u16(self) -> int:
        return int.from_bytes(self.read_bytes(2), "little", signed=False)

    def read_u32(self) -> int:
        return int.from_bytes(self.read_bytes(4), "little", signed=False)

    def read_var_int(self, max_value: int | None = None) -> int:
        prefix = self.read_u8()
        if prefix == 0xFD:
            value = self.read_u16()
        elif prefix == 0xFE:
            value = self.read_u32()
        elif prefix == 0xFF:
            value = int.from_bytes(self.read_bytes(8), "little", signed=False)
        else:
            value = prefix
        if max_value is not None and value > max_value:
            raise ValueError(f"Variable integer exceeds max allowed value {max_value}")
        return value

    def read_var_bytes(self, max_length: int | None = None) -> bytes:
        length = self.read_var_int(max_length)
        return self.read_bytes(length)

    def read_var_string(self, max_length: int | None = None) -> str:
        data = self.read_var_bytes(max_length)
        return data.decode("utf-8", errors="strict")


def _read_fixed_string(data: bytes) -> str:
    return data.split(b"\x00", 1)[0].decode("utf-8", errors="ignore")


def compute_nef_checksum(data_without_checksum: bytes) -> int:
    first = hashlib.sha256(data_without_checksum).digest()
    second = hashlib.sha256(first).digest()
    return int.from_bytes(second[:4], "little", signed=False)


def disassemble(script: bytes) -> list[Instruction]:
    """Disassemble NeoVM script bytes into instructions."""
    instructions: list[Instruction] = []
    i = 0
    length = len(script)

    while i < length:
        raw_opcode = script[i]
        try:
            opcode = OpCode(raw_opcode)
        except ValueError as exc:
            raise ValueError(f"Unknown opcode 0x{raw_opcode:02X} at offset {i}") from exc

        prefix_size = PREFIX_OPERAND_SIZES.get(opcode)
        if prefix_size is not None:
            if i + 1 + prefix_size > length:
                raise ValueError(f"Malformed {opcode.name} at offset {i}: missing size field")
            raw_len = script[i + 1 : i + 1 + prefix_size]
            payload_len = int.from_bytes(raw_len, byteorder="little", signed=False)
            end = i + 1 + prefix_size + payload_len
            if end > length:
                raise ValueError(f"Malformed {opcode.name} at offset {i}: truncated payload")
            operand = script[i + 1 : end]
            size = 1 + prefix_size + payload_len
        else:
            operand_size = FIXED_OPERAND_SIZES.get(opcode, 0)
            end = i + 1 + operand_size
            if end > length:
                raise ValueError(f"Malformed {opcode.name} at offset {i}: truncated operand")
            operand = script[i + 1 : end]
            size = 1 + operand_size

        instructions.append(Instruction(opcode=opcode, offset=i, operand=operand, size=size))
        i += size

    return instructions


def _parse_nef3(data: bytes, *, verify_checksum: bool) -> NefFile:
    reader = _BufferReader(data)
    magic = reader.read_u32()
    if magic != NEF3_MAGIC:
        raise ValueError(f"Invalid NEF magic: 0x{magic:08X}")

    compiler = _read_fixed_string(reader.read_bytes(64))
    source = reader.read_var_string(MAX_SOURCE_LENGTH)
    if reader.read_u8() != 0:
        raise ValueError("Reserved byte after source must be 0")

    token_count = reader.read_var_int(MAX_METHOD_TOKENS)
    tokens: list[MethodToken] = []
    for _ in range(token_count):
        contract_hash = reader.read_bytes(20)
        method = reader.read_var_string(MAX_METHOD_NAME_LENGTH)
        if method.startswith("_"):
            raise ValueError(f"Method token name cannot start with underscore: {method}")
        parameters_count = reader.read_u16()
        has_return_value = bool(reader.read_u8())
        call_flags = reader.read_u8()
        if call_flags & ~CALL_FLAGS_ALL:
            raise ValueError(f"Invalid call flags: 0x{call_flags:02X}")
        tokens.append(
            MethodToken(
                hash=contract_hash,
                method=method,
                parameters_count=parameters_count,
                has_return_value=has_return_value,
                call_flags=call_flags,
            )
        )

    if reader.read_u16() != 0:
        raise ValueError("Reserved ushort before script must be 0")

    script = reader.read_var_bytes(MAX_SCRIPT_LENGTH)
    if len(script) == 0:
        raise ValueError("Script cannot be empty")

    checksum = reader.read_u32()
    if reader.remaining != 0:
        raise ValueError("Unexpected trailing bytes after NEF checksum")

    expected_checksum = compute_nef_checksum(data[:-4])
    checksum_valid = checksum == expected_checksum
    if verify_checksum and not checksum_valid:
        raise ValueError(
            f"NEF checksum mismatch: expected 0x{expected_checksum:08X}, got 0x{checksum:08X}"
        )

    instructions = disassemble(script)
    return NefFile(
        script=script,
        instructions=instructions,
        compiler=compiler or "unknown",
        source=source,
        tokens=tokens,
        checksum=checksum,
        checksum_valid=checksum_valid,
        magic=magic,
    )


def parse_nef(data: bytes, *, verify_checksum: bool = True) -> NefFile:
    """Parse a NEF3 envelope or raw script bytes."""
    if not data:
        raise ValueError("Empty NEF input")

    if len(data) >= 4 and int.from_bytes(data[:4], "little", signed=False) == NEF3_MAGIC:
        return _parse_nef3(data, verify_checksum=verify_checksum)

    instructions = disassemble(data)
    return NefFile(
        script=data,
        instructions=instructions,
        compiler="raw-script",
        checksum_valid=None,
        magic=None,
    )
