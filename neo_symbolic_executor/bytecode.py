from __future__ import annotations

from .model import Instruction, Program
from .opcodes import JUMP_OPCODES, OPCODE_BY_BYTE, PUSH_LITERAL_BY_VALUE, opcode_with_embedded_index


class DecodeError(ValueError):
    pass


def decode_hex_string(text: str, metadata: dict[str, object] | None = None) -> Program:
    compact = "".join(text.split())
    if compact.startswith(("0x", "0X")):
        compact = compact[2:]
    if len(compact) % 2 != 0:
        raise DecodeError("Hex script must contain an even number of hex digits")
    try:
        script = bytes.fromhex(compact)
    except ValueError as exc:
        raise DecodeError("Hex script contains non-hex characters") from exc
    return decode_script(script, metadata=metadata or {"source_type": "hex"})


def decode_script(
    script: bytes,
    labels: dict[str, int] | None = None,
    metadata: dict[str, object] | None = None,
) -> Program:
    instructions: list[Instruction] = []
    offset = 0

    while offset < len(script):
        opcode_byte = script[offset]
        if opcode_byte not in OPCODE_BY_BYTE:
            raise DecodeError(f"Unknown NeoVM opcode 0x{opcode_byte:02x} at offset {offset}")
        spec = OPCODE_BY_BYTE[opcode_byte]
        operand, size, argument, target = _decode_operand(spec.name, script, offset)
        instructions.append(
            Instruction(
                offset=offset,
                opcode=spec.name,
                opcode_byte=opcode_byte,
                size=size,
                operand=operand,
                argument=argument,
                target=target,
            )
        )
        offset += size

    program = Program(
        instructions=tuple(instructions),
        script=script,
        labels=labels or {},
        metadata=metadata or {},
    )
    _validate_targets(program)
    return program


def _decode_operand(name: str, script: bytes, offset: int) -> tuple[bytes, int, object | None, int | None]:
    spec = OPCODE_BY_BYTE[script[offset]]
    cursor = offset + 1
    target = None
    argument: object | None = None

    if spec.size_prefix:
        if cursor + spec.size_prefix > len(script):
            raise DecodeError(f"Opcode {name} at offset {offset} extends past the end of the script")
        length = int.from_bytes(script[cursor : cursor + spec.size_prefix], "little")
        cursor += spec.size_prefix
        end = cursor + length
        if end > len(script):
            raise DecodeError(f"Opcode {name} at offset {offset} extends past the end of the script")
        payload = script[cursor:end]
        return script[offset + 1 : end], 1 + spec.size_prefix + length, payload, None

    if spec.operand_size:
        end = cursor + spec.operand_size
        if end > len(script):
            raise DecodeError(f"Opcode {name} at offset {offset} extends past the end of the script")
        operand = script[cursor:end]
        if name == "INITSLOT":
            argument = (operand[0], operand[1])
        elif name == "TRY":
            argument = (
                int.from_bytes(operand[:1], "little", signed=True),
                int.from_bytes(operand[1:], "little", signed=True),
            )
        elif name == "TRY_L":
            argument = (
                int.from_bytes(operand[:4], "little", signed=True),
                int.from_bytes(operand[4:], "little", signed=True),
            )
        elif name in JUMP_OPCODES:
            argument = int.from_bytes(operand, "little", signed=True)
            target = offset + int(argument)
        elif name == "PUSHA":
            argument = int.from_bytes(operand, "little", signed=True)
            target = offset + argument
        elif name.startswith("PUSHINT"):
            argument = int.from_bytes(operand, "little", signed=True)
        else:
            argument = int.from_bytes(operand, "little", signed=False)
        return operand, 1 + spec.operand_size, argument, target

    embedded_index = opcode_with_embedded_index(name)
    if embedded_index is not None:
        argument = embedded_index
    elif name in PUSH_LITERAL_BY_VALUE.values():
        reverse = {opcode: value for value, opcode in PUSH_LITERAL_BY_VALUE.items()}
        argument = reverse[name]
    elif name == "PUSHT":
        argument = True
    elif name == "PUSHF":
        argument = False
    elif name == "PUSHNULL":
        argument = None
    return b"", 1, argument, target


def _validate_targets(program: Program) -> None:
    valid_offsets = set(program.instruction_offsets)
    for instruction in program.instructions:
        if instruction.opcode in JUMP_OPCODES and instruction.target not in valid_offsets:
            raise DecodeError(
                f"{instruction.opcode} at offset {instruction.offset} targets invalid offset {instruction.target}"
            )
        if instruction.opcode == "PUSHA" and instruction.target not in valid_offsets:
            raise DecodeError(
                f"PUSHA at offset {instruction.offset} targets invalid offset {instruction.target}"
            )
        if instruction.opcode in {"TRY", "TRY_L"}:
            catch_offset, finally_offset = instruction.argument
            base = f"{instruction.opcode} at offset {instruction.offset}"
            if catch_offset == 0 and finally_offset == 0:
                raise DecodeError(f"{base} requires a catch or finally target")
            if catch_offset != 0 and instruction.offset + catch_offset not in valid_offsets:
                raise DecodeError(
                    f"{base} catch target invalid offset {instruction.offset + catch_offset}"
                )
            if finally_offset != 0 and instruction.offset + finally_offset not in valid_offsets:
                raise DecodeError(
                    f"{base} finally target invalid offset {instruction.offset + finally_offset}"
                )
