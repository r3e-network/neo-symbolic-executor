from __future__ import annotations

import shlex
from dataclasses import dataclass, replace

from .bytecode import DecodeError, decode_script
from .model import Program
from .opcodes import (
    JUMP_OPCODES,
    OPCODE_BY_NAME,
    PUSH_LITERAL_BY_VALUE,
    STACK_ITEM_TYPE_NAME_TO_CODE,
    opcode_with_embedded_index,
)


class ParseError(ValueError):
    pass


LABEL_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-")


@dataclass
class _AssemblyInstruction:
    offset: int
    opcode: str
    operand_bytes: bytes
    line_no: int
    source: str
    target_label: str | None = None

    @property
    def size(self) -> int:
        return 1 + len(self.operand_bytes)


def parse_program(source: str) -> Program:
    labels: dict[str, int] = {}
    assembled: list[_AssemblyInstruction] = []
    offset = 0

    for line_no, raw_line in enumerate(source.splitlines(), start=1):
        tokens = _tokenize(raw_line, line_no)
        if not tokens:
            continue

        label, tokens = _split_label(tokens, line_no)
        if label is not None:
            if label in labels:
                raise ParseError(f"Line {line_no}: duplicate label '{label}'")
            labels[label] = offset
            if not tokens:
                continue

        opcode = tokens[0].upper()
        instruction = _assemble_instruction(opcode, tokens[1:], line_no, raw_line.rstrip(), offset)
        assembled.append(instruction)
        offset += instruction.size

    resolved_bytes = bytearray()
    source_by_offset: dict[int, tuple[int, str]] = {}
    for instruction in assembled:
        operand = instruction.operand_bytes
        if instruction.target_label is not None:
            if instruction.target_label not in labels:
                raise ParseError(
                    f"Line {instruction.line_no}: jump target '{instruction.target_label}' was not defined"
                )
            target = labels[instruction.target_label]
            operand = _encode_relative_operand(instruction.opcode, instruction.offset, target, instruction.line_no)
        spec = OPCODE_BY_NAME[instruction.opcode]
        resolved_bytes.append(spec.code)
        resolved_bytes.extend(operand)
        source_by_offset[instruction.offset] = (instruction.line_no, instruction.source)

    try:
        program = decode_script(
            bytes(resolved_bytes),
            labels=labels,
            metadata={"source_type": "assembly"},
        )
    except DecodeError as exc:
        raise ParseError(str(exc)) from exc
    instructions = tuple(
        replace(
            entry,
            line_no=source_by_offset.get(entry.offset, (0, ""))[0],
            source=source_by_offset.get(entry.offset, (0, ""))[1],
        )
        for entry in program.instructions
    )
    return Program(
        instructions=instructions,
        script=program.script,
        labels=labels,
        metadata=program.metadata,
    )


def parse_file(path: str) -> Program:
    with open(path, encoding="utf-8") as handle:
        return parse_program(handle.read())


def parse_script_items(items: list[str]) -> Program:
    raw = bytearray()
    for item in items:
        token = item.upper()
        if token in OPCODE_BY_NAME:
            raw.append(OPCODE_BY_NAME[token].code)
            continue
        if item.startswith("0x") or item.startswith("0X"):
            try:
                raw.extend(bytes.fromhex(item[2:]))
            except ValueError as exc:
                raise ParseError(f"Unsupported hex script item '{item}'") from exc
            continue
        raise ParseError(f"Unsupported script item '{item}'")
    return decode_script(bytes(raw), metadata={"source_type": "json-script"})


def _assemble_instruction(
    opcode: str,
    operands: list[str],
    line_no: int,
    source: str,
    offset: int,
) -> _AssemblyInstruction:
    if opcode == "PUSH":
        _expect_arity(opcode, operands, 1, line_no)
        value = _parse_int(operands[0], line_no, opcode)
        real_opcode, operand_bytes = _encode_push(value, line_no)
        return _AssemblyInstruction(offset, real_opcode, operand_bytes, line_no, source)

    if opcode == "PUSHDATA":
        _expect_arity(opcode, operands, 1, line_no)
        data = _parse_bytes_literal(operands[0], line_no, opcode)
        real_opcode, operand_bytes = _encode_pushdata(data, None, line_no)
        return _AssemblyInstruction(offset, real_opcode, operand_bytes, line_no, source)

    if opcode not in OPCODE_BY_NAME:
        raise ParseError(f"Line {line_no}: unsupported opcode '{opcode}'")

    spec = OPCODE_BY_NAME[opcode]
    embedded_index = opcode_with_embedded_index(opcode)
    if embedded_index is not None:
        _expect_arity(opcode, operands, 0, line_no)
        return _AssemblyInstruction(offset, opcode, b"", line_no, source)

    simple_opcodes = {
        "PUSHT",
        "PUSHF",
        "PUSHNULL",
        "NOP",
        "DEPTH",
        "DROP",
        "NIP",
        "XDROP",
        "CLEAR",
        "DUP",
        "OVER",
        "PICK",
        "TUCK",
        "SWAP",
        "ROT",
        "ROLL",
        "REVERSE3",
        "REVERSE4",
        "REVERSEN",
        "ABORT",
        "ASSERT",
        "RET",
        "CALLA",
        "ENDFINALLY",
        "THROW",
        "NEWBUFFER",
        "MEMCPY",
        "CAT",
        "SUBSTR",
        "LEFT",
        "RIGHT",
        "INVERT",
        "AND",
        "OR",
        "XOR",
        "EQUAL",
        "NOTEQUAL",
        "SIGN",
        "ABS",
        "NEGATE",
        "INC",
        "DEC",
        "ADD",
        "SUB",
        "MUL",
        "DIV",
        "MOD",
        "POW",
        "SQRT",
        "MODMUL",
        "MODPOW",
        "SHL",
        "SHR",
        "NOT",
        "BOOLAND",
        "BOOLOR",
        "NZ",
        "NUMEQUAL",
        "NUMNOTEQUAL",
        "LT",
        "LE",
        "GT",
        "GE",
        "MIN",
        "MAX",
        "WITHIN",
        "PACKMAP",
        "PACKSTRUCT",
        "PACK",
        "UNPACK",
        "NEWARRAY0",
        "NEWARRAY",
        "NEWSTRUCT0",
        "NEWSTRUCT",
        "NEWMAP",
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
        "ABORTMSG",
        "ASSERTMSG",
    }
    if opcode in PUSH_LITERAL_BY_VALUE.values() or opcode in simple_opcodes:
        _expect_arity(opcode, operands, 0, line_no)
        return _AssemblyInstruction(offset, opcode, b"", line_no, source)

    if opcode in JUMP_OPCODES:
        _expect_arity(opcode, operands, 1, line_no)
        target = operands[0]
        if _looks_like_label(target):
            width = spec.operand_size
            return _AssemblyInstruction(
                offset=offset,
                opcode=opcode,
                operand_bytes=b"\x00" * width,
                line_no=line_no,
                source=source,
                target_label=target,
            )
        relative = _parse_int(target, line_no, opcode)
        try:
            operand_bytes = relative.to_bytes(spec.operand_size, "little", signed=True)
        except OverflowError as exc:
            bit_width = spec.operand_size * 8
            raise ParseError(f"Line {line_no}: {opcode} expects a {bit_width}-bit signed offset") from exc
        return _AssemblyInstruction(offset, opcode, operand_bytes, line_no, source)

    if opcode in {"PUSHINT8", "PUSHINT16", "PUSHINT32", "PUSHINT64", "PUSHINT128", "PUSHINT256"}:
        _expect_arity(opcode, operands, 1, line_no)
        value = _parse_int(operands[0], line_no, opcode)
        width = spec.operand_size
        lower = -(2 ** (width * 8 - 1))
        upper = (2 ** (width * 8 - 1)) - 1
        if not lower <= value <= upper:
            raise ParseError(f"Line {line_no}: {opcode} expects a {width * 8}-bit signed integer")
        return _AssemblyInstruction(
            offset,
            opcode,
            value.to_bytes(width, "little", signed=True),
            line_no,
            source,
        )

    if opcode in {"PUSHDATA1", "PUSHDATA2", "PUSHDATA4"}:
        _expect_arity(opcode, operands, 1, line_no)
        data = _parse_bytes_literal(operands[0], line_no, opcode)
        _, operand_bytes = _encode_pushdata(data, opcode, line_no)
        return _AssemblyInstruction(offset, opcode, operand_bytes, line_no, source)

    if opcode in {"INITSSLOT", "LDSFLD", "STSFLD", "LDLOC", "STLOC", "LDARG", "STARG"}:
        _expect_arity(opcode, operands, 1, line_no)
        index = _parse_non_negative_int(operands[0], line_no, opcode)
        if not 0 <= index <= 255:
            raise ParseError(f"Line {line_no}: {opcode} expects a byte-sized operand")
        return _AssemblyInstruction(offset, opcode, bytes([index]), line_no, source)

    if opcode in {"NEWARRAY_T", "ISTYPE", "CONVERT"}:
        _expect_arity(opcode, operands, 1, line_no)
        type_byte = _parse_stack_item_type(operands[0], line_no, opcode)
        return _AssemblyInstruction(offset, opcode, bytes([type_byte]), line_no, source)

    if opcode == "INITSLOT":
        if len(operands) == 1 and operands[0].startswith(("0x", "0X")):
            try:
                raw = bytes.fromhex(operands[0][2:])
            except ValueError as exc:
                raise ParseError(f"Line {line_no}: INITSLOT expects a valid hex operand") from exc
            if len(raw) != 2:
                raise ParseError(f"Line {line_no}: INITSLOT hex operand must be exactly 2 bytes")
            return _AssemblyInstruction(offset, opcode, raw, line_no, source)
        _expect_arity(opcode, operands, 2, line_no)
        locals_count = _parse_non_negative_int(operands[0], line_no, opcode)
        args_count = _parse_non_negative_int(operands[1], line_no, opcode)
        if locals_count > 255 or args_count > 255:
            raise ParseError(f"Line {line_no}: INITSLOT counts must fit in one byte")
        return _AssemblyInstruction(offset, opcode, bytes([locals_count, args_count]), line_no, source)

    if opcode in {"TRY", "TRY_L"}:
        _expect_arity(opcode, operands, 2, line_no)
        first = _parse_int(operands[0], line_no, opcode)
        second = _parse_int(operands[1], line_no, opcode)
        try:
            if opcode == "TRY":
                operand_bytes = first.to_bytes(1, "little", signed=True) + second.to_bytes(1, "little", signed=True)
            else:
                operand_bytes = first.to_bytes(4, "little", signed=True) + second.to_bytes(4, "little", signed=True)
        except OverflowError as exc:
            bit_width = 8 if opcode == "TRY" else 32
            raise ParseError(f"Line {line_no}: {opcode} expects {bit_width}-bit signed offsets") from exc
        return _AssemblyInstruction(offset, opcode, operand_bytes, line_no, source)

    if opcode == "CALLT":
        _expect_arity(opcode, operands, 1, line_no)
        token = _parse_non_negative_int(operands[0], line_no, opcode)
        if token > 0xFFFF:
            raise ParseError(f"Line {line_no}: CALLT expects a 16-bit unsigned integer")
        return _AssemblyInstruction(offset, opcode, token.to_bytes(2, "little"), line_no, source)

    if opcode == "SYSCALL":
        _expect_arity(opcode, operands, 1, line_no)
        token = _parse_non_negative_int(operands[0], line_no, opcode)
        if token > 0xFFFFFFFF:
            raise ParseError(f"Line {line_no}: SYSCALL expects a 32-bit unsigned integer")
        return _AssemblyInstruction(offset, opcode, token.to_bytes(4, "little"), line_no, source)

    raise ParseError(f"Line {line_no}: unsupported assembly form for opcode '{opcode}'")


def _tokenize(raw_line: str, line_no: int) -> list[str]:
    lexer = shlex.shlex(raw_line, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = "#;"
    try:
        return list(lexer)
    except ValueError as exc:
        raise ParseError(f"Line {line_no}: invalid quoting in assembly source") from exc


def _split_label(tokens: list[str], line_no: int) -> tuple[str | None, list[str]]:
    head = tokens[0]
    if not head.endswith(":"):
        return None, tokens
    label = head[:-1]
    if not label or any(char not in LABEL_CHARS for char in label):
        raise ParseError(f"Line {line_no}: invalid label '{label}'")
    return label, tokens[1:]


def _looks_like_label(token: str) -> bool:
    return bool(token) and (token[0].isalpha() or token[0] == "_")


def _expect_arity(opcode: str, tokens: list[str], expected: int, line_no: int) -> None:
    if len(tokens) != expected:
        raise ParseError(
            f"Line {line_no}: {opcode} expects {expected} operand(s), got {len(tokens)}"
        )


def _parse_int(value: str, line_no: int, opcode: str) -> int:
    try:
        return int(value, 0)
    except ValueError as exc:
        raise ParseError(f"Line {line_no}: {opcode} expects an integer, got '{value}'") from exc


def _parse_non_negative_int(value: str, line_no: int, opcode: str) -> int:
    parsed = _parse_int(value, line_no, opcode)
    if parsed < 0:
        raise ParseError(f"Line {line_no}: {opcode} expects a non-negative integer")
    return parsed


def _parse_bytes_literal(token: str, line_no: int, opcode: str) -> bytes:
    if token.startswith(("0x", "0X")):
        try:
            return bytes.fromhex(token[2:])
        except ValueError as exc:
            raise ParseError(f"Line {line_no}: {opcode} expects a valid hex byte string") from exc
    return token.encode("utf-8")


def _encode_push(value: int, line_no: int) -> tuple[str, bytes]:
    if value in PUSH_LITERAL_BY_VALUE:
        return PUSH_LITERAL_BY_VALUE[value], b""
    for bits in (8, 16, 32, 64, 128, 256):
        lower = -(2 ** (bits - 1))
        upper = (2 ** (bits - 1)) - 1
        if lower <= value <= upper:
            width = bits // 8
            return (
                f"PUSHINT{bits}",
                value.to_bytes(width, "little", signed=True),
            )
    raise ParseError(f"Line {line_no}: PUSH integer does not fit in NeoVM PUSHINT256")


def _encode_pushdata(data: bytes, opcode: str | None, line_no: int) -> tuple[str, bytes]:
    if opcode is None:
        if len(data) <= 0xFF:
            opcode = "PUSHDATA1"
        elif len(data) <= 0xFFFF:
            opcode = "PUSHDATA2"
        elif len(data) <= 0xFFFFFFFF:
            opcode = "PUSHDATA4"
        else:
            raise ParseError(f"Line {line_no}: PUSHDATA payload is too large")

    spec = OPCODE_BY_NAME[opcode]
    prefix_size = spec.size_prefix
    max_length = (1 << (prefix_size * 8)) - 1
    if len(data) > max_length:
        raise ParseError(f"Line {line_no}: {opcode} payload is too large")
    prefix = len(data).to_bytes(prefix_size, "little")
    return opcode, prefix + data


def _encode_relative_operand(opcode: str, current_offset: int, target_offset: int, line_no: int) -> bytes:
    spec = OPCODE_BY_NAME[opcode]
    delta = target_offset - current_offset
    width = spec.operand_size
    lower = -(2 ** (width * 8 - 1))
    upper = (2 ** (width * 8 - 1)) - 1
    if not lower <= delta <= upper:
        raise ParseError(
            f"Line {line_no}: {opcode} target is out of range for a {width * 8}-bit relative offset"
        )
    return delta.to_bytes(width, "little", signed=True)


def _parse_stack_item_type(value: str, line_no: int, opcode: str) -> int:
    candidate = value.upper()
    if candidate in STACK_ITEM_TYPE_NAME_TO_CODE:
        return STACK_ITEM_TYPE_NAME_TO_CODE[candidate]
    parsed = _parse_non_negative_int(value, line_no, opcode)
    if not 0 <= parsed <= 255:
        raise ParseError(f"Line {line_no}: {opcode} expects a byte-sized stack item type")
    return parsed
