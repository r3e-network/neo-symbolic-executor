from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Instruction:
    offset: int
    opcode: str
    opcode_byte: int
    size: int
    operand: bytes = b""
    argument: Any = None
    target: int | None = None
    line_no: int = 0
    source: str = ""

    @property
    def end_offset(self) -> int:
        return self.offset + self.size

    @property
    def display(self) -> str:
        if _argument_is_encoded_in_opcode(self.opcode):
            return self.opcode
        if self.opcode in {"PUSHT", "PUSHF", "PUSHNULL"}:
            return self.opcode
        if self.argument is None:
            return self.opcode
        if isinstance(self.argument, bytes):
            return f"{self.opcode} 0x{self.argument.hex()}"
        if isinstance(self.argument, tuple):
            return f"{self.opcode} {' '.join(str(item) for item in self.argument)}"
        return f"{self.opcode} {self.argument}"


@dataclass(frozen=True)
class Program:
    instructions: tuple[Instruction, ...]
    script: bytes
    labels: dict[str, int] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    _instruction_by_offset: dict[int, Instruction] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "_instruction_by_offset",
            {instruction.offset: instruction for instruction in self.instructions},
        )

    @property
    def length(self) -> int:
        return len(self.script)

    def instruction_at_offset(self, offset: int) -> Instruction:
        return self._instruction_by_offset[offset]

    def has_offset(self, offset: int) -> bool:
        return offset in self._instruction_by_offset

    @property
    def instruction_offsets(self) -> tuple[int, ...]:
        return tuple(instruction.offset for instruction in self.instructions)


def _argument_is_encoded_in_opcode(opcode: str) -> bool:
    if opcode == "PUSHM1":
        return True
    if opcode.startswith("PUSH") and opcode[4:].isdigit():
        return True
    for prefix in ("LDSFLD", "STSFLD", "LDLOC", "STLOC", "LDARG", "STARG"):
        if opcode.startswith(prefix) and opcode.removeprefix(prefix).isdigit():
            return True
    return False
