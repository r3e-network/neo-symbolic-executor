from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class OperandKind(StrEnum):
    NONE = "none"
    SIGNED_INT = "signed_int"
    SIGNED_OFFSET = "signed_offset"
    UNSIGNED_BYTE = "unsigned_byte"
    UNSIGNED_SHORT = "unsigned_short"
    UNSIGNED_INT = "unsigned_int"
    VAR_BYTES = "var_bytes"
    SLOT_PAIR = "slot_pair"


@dataclass(frozen=True)
class OpCodeSpec:
    name: str
    code: int
    operand_kind: OperandKind = OperandKind.NONE
    operand_size: int = 0
    size_prefix: int = 0

    @property
    def has_operand(self) -> bool:
        return self.operand_kind != OperandKind.NONE


def _spec(
    name: str,
    code: int,
    operand_kind: OperandKind = OperandKind.NONE,
    operand_size: int = 0,
    size_prefix: int = 0,
) -> OpCodeSpec:
    return OpCodeSpec(
        name=name,
        code=code,
        operand_kind=operand_kind,
        operand_size=operand_size,
        size_prefix=size_prefix,
    )


OPCODE_SPECS = (
    _spec("PUSHINT8", 0x00, OperandKind.SIGNED_INT, operand_size=1),
    _spec("PUSHINT16", 0x01, OperandKind.SIGNED_INT, operand_size=2),
    _spec("PUSHINT32", 0x02, OperandKind.SIGNED_INT, operand_size=4),
    _spec("PUSHINT64", 0x03, OperandKind.SIGNED_INT, operand_size=8),
    _spec("PUSHINT128", 0x04, OperandKind.SIGNED_INT, operand_size=16),
    _spec("PUSHINT256", 0x05, OperandKind.SIGNED_INT, operand_size=32),
    _spec("PUSHT", 0x08),
    _spec("PUSHF", 0x09),
    _spec("PUSHA", 0x0A, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("PUSHNULL", 0x0B),
    _spec("PUSHDATA1", 0x0C, OperandKind.VAR_BYTES, size_prefix=1),
    _spec("PUSHDATA2", 0x0D, OperandKind.VAR_BYTES, size_prefix=2),
    _spec("PUSHDATA4", 0x0E, OperandKind.VAR_BYTES, size_prefix=4),
    _spec("PUSHM1", 0x0F),
    _spec("PUSH0", 0x10),
    _spec("PUSH1", 0x11),
    _spec("PUSH2", 0x12),
    _spec("PUSH3", 0x13),
    _spec("PUSH4", 0x14),
    _spec("PUSH5", 0x15),
    _spec("PUSH6", 0x16),
    _spec("PUSH7", 0x17),
    _spec("PUSH8", 0x18),
    _spec("PUSH9", 0x19),
    _spec("PUSH10", 0x1A),
    _spec("PUSH11", 0x1B),
    _spec("PUSH12", 0x1C),
    _spec("PUSH13", 0x1D),
    _spec("PUSH14", 0x1E),
    _spec("PUSH15", 0x1F),
    _spec("PUSH16", 0x20),
    _spec("NOP", 0x21),
    _spec("JMP", 0x22, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMP_L", 0x23, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPIF", 0x24, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPIF_L", 0x25, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPIFNOT", 0x26, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPIFNOT_L", 0x27, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPEQ", 0x28, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPEQ_L", 0x29, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPNE", 0x2A, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPNE_L", 0x2B, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPGT", 0x2C, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPGT_L", 0x2D, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPGE", 0x2E, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPGE_L", 0x2F, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPLT", 0x30, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPLT_L", 0x31, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("JMPLE", 0x32, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("JMPLE_L", 0x33, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("CALL", 0x34, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("CALL_L", 0x35, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("CALLA", 0x36),
    _spec("CALLT", 0x37, OperandKind.UNSIGNED_SHORT, operand_size=2),
    _spec("ABORT", 0x38),
    _spec("ASSERT", 0x39),
    _spec("THROW", 0x3A),
    _spec("TRY", 0x3B, OperandKind.SLOT_PAIR, operand_size=2),
    _spec("TRY_L", 0x3C, OperandKind.SLOT_PAIR, operand_size=8),
    _spec("ENDTRY", 0x3D, OperandKind.SIGNED_OFFSET, operand_size=1),
    _spec("ENDTRY_L", 0x3E, OperandKind.SIGNED_OFFSET, operand_size=4),
    _spec("ENDFINALLY", 0x3F),
    _spec("RET", 0x40),
    _spec("SYSCALL", 0x41, OperandKind.UNSIGNED_INT, operand_size=4),
    _spec("DEPTH", 0x43),
    _spec("DROP", 0x45),
    _spec("NIP", 0x46),
    _spec("XDROP", 0x48),
    _spec("CLEAR", 0x49),
    _spec("DUP", 0x4A),
    _spec("OVER", 0x4B),
    _spec("PICK", 0x4D),
    _spec("TUCK", 0x4E),
    _spec("SWAP", 0x50),
    _spec("ROT", 0x51),
    _spec("ROLL", 0x52),
    _spec("REVERSE3", 0x53),
    _spec("REVERSE4", 0x54),
    _spec("REVERSEN", 0x55),
    _spec("INITSSLOT", 0x56, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("INITSLOT", 0x57, OperandKind.SLOT_PAIR, operand_size=2),
    _spec("LDSFLD0", 0x58),
    _spec("LDSFLD1", 0x59),
    _spec("LDSFLD2", 0x5A),
    _spec("LDSFLD3", 0x5B),
    _spec("LDSFLD4", 0x5C),
    _spec("LDSFLD5", 0x5D),
    _spec("LDSFLD6", 0x5E),
    _spec("LDSFLD", 0x5F, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("STSFLD0", 0x60),
    _spec("STSFLD1", 0x61),
    _spec("STSFLD2", 0x62),
    _spec("STSFLD3", 0x63),
    _spec("STSFLD4", 0x64),
    _spec("STSFLD5", 0x65),
    _spec("STSFLD6", 0x66),
    _spec("STSFLD", 0x67, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("LDLOC0", 0x68),
    _spec("LDLOC1", 0x69),
    _spec("LDLOC2", 0x6A),
    _spec("LDLOC3", 0x6B),
    _spec("LDLOC4", 0x6C),
    _spec("LDLOC5", 0x6D),
    _spec("LDLOC6", 0x6E),
    _spec("LDLOC", 0x6F, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("STLOC0", 0x70),
    _spec("STLOC1", 0x71),
    _spec("STLOC2", 0x72),
    _spec("STLOC3", 0x73),
    _spec("STLOC4", 0x74),
    _spec("STLOC5", 0x75),
    _spec("STLOC6", 0x76),
    _spec("STLOC", 0x77, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("LDARG0", 0x78),
    _spec("LDARG1", 0x79),
    _spec("LDARG2", 0x7A),
    _spec("LDARG3", 0x7B),
    _spec("LDARG4", 0x7C),
    _spec("LDARG5", 0x7D),
    _spec("LDARG6", 0x7E),
    _spec("LDARG", 0x7F, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("STARG0", 0x80),
    _spec("STARG1", 0x81),
    _spec("STARG2", 0x82),
    _spec("STARG3", 0x83),
    _spec("STARG4", 0x84),
    _spec("STARG5", 0x85),
    _spec("STARG6", 0x86),
    _spec("STARG", 0x87, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("NEWBUFFER", 0x88),
    _spec("MEMCPY", 0x89),
    _spec("CAT", 0x8B),
    _spec("SUBSTR", 0x8C),
    _spec("LEFT", 0x8D),
    _spec("RIGHT", 0x8E),
    _spec("INVERT", 0x90),
    _spec("AND", 0x91),
    _spec("OR", 0x92),
    _spec("XOR", 0x93),
    _spec("EQUAL", 0x97),
    _spec("NOTEQUAL", 0x98),
    _spec("SIGN", 0x99),
    _spec("ABS", 0x9A),
    _spec("NEGATE", 0x9B),
    _spec("INC", 0x9C),
    _spec("DEC", 0x9D),
    _spec("ADD", 0x9E),
    _spec("SUB", 0x9F),
    _spec("MUL", 0xA0),
    _spec("DIV", 0xA1),
    _spec("MOD", 0xA2),
    _spec("POW", 0xA3),
    _spec("SQRT", 0xA4),
    _spec("MODMUL", 0xA5),
    _spec("MODPOW", 0xA6),
    _spec("SHL", 0xA8),
    _spec("SHR", 0xA9),
    _spec("NOT", 0xAA),
    _spec("BOOLAND", 0xAB),
    _spec("BOOLOR", 0xAC),
    _spec("NZ", 0xB1),
    _spec("NUMEQUAL", 0xB3),
    _spec("NUMNOTEQUAL", 0xB4),
    _spec("LT", 0xB5),
    _spec("LE", 0xB6),
    _spec("GT", 0xB7),
    _spec("GE", 0xB8),
    _spec("MIN", 0xB9),
    _spec("MAX", 0xBA),
    _spec("WITHIN", 0xBB),
    _spec("PACKMAP", 0xBE),
    _spec("PACKSTRUCT", 0xBF),
    _spec("PACK", 0xC0),
    _spec("UNPACK", 0xC1),
    _spec("NEWARRAY0", 0xC2),
    _spec("NEWARRAY", 0xC3),
    _spec("NEWARRAY_T", 0xC4, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("NEWSTRUCT0", 0xC5),
    _spec("NEWSTRUCT", 0xC6),
    _spec("NEWMAP", 0xC8),
    _spec("SIZE", 0xCA),
    _spec("HASKEY", 0xCB),
    _spec("KEYS", 0xCC),
    _spec("VALUES", 0xCD),
    _spec("PICKITEM", 0xCE),
    _spec("APPEND", 0xCF),
    _spec("SETITEM", 0xD0),
    _spec("REVERSEITEMS", 0xD1),
    _spec("REMOVE", 0xD2),
    _spec("CLEARITEMS", 0xD3),
    _spec("POPITEM", 0xD4),
    _spec("ISNULL", 0xD8),
    _spec("ISTYPE", 0xD9, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("CONVERT", 0xDB, OperandKind.UNSIGNED_BYTE, operand_size=1),
    _spec("ABORTMSG", 0xE0),
    _spec("ASSERTMSG", 0xE1),
)

OPCODE_BY_NAME = {spec.name: spec for spec in OPCODE_SPECS}
OPCODE_BY_BYTE = {spec.code: spec for spec in OPCODE_SPECS}

JUMP_OPCODES = {
    "JMP",
    "JMP_L",
    "JMPIF",
    "JMPIF_L",
    "JMPIFNOT",
    "JMPIFNOT_L",
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
    "CALL",
    "CALL_L",
    "ENDTRY",
    "ENDTRY_L",
    "PUSHA",
}

SHORT_INDEXED_PREFIXES = ("LDSFLD", "STSFLD", "LDLOC", "STLOC", "LDARG", "STARG")
PUSH_LITERAL_BY_VALUE = {-1: "PUSHM1", **{value: f"PUSH{value}" for value in range(17)}}


def supports_opcode(name: str) -> bool:
    return name in OPCODE_BY_NAME


# Stack item type codes (NeoVM StackItem types)
STACK_ITEM_TYPE_ANY = 0x00
STACK_ITEM_TYPE_POINTER = 0x10
STACK_ITEM_TYPE_BOOLEAN = 0x20
STACK_ITEM_TYPE_INTEGER = 0x21
STACK_ITEM_TYPE_BYTESTRING = 0x28
STACK_ITEM_TYPE_BUFFER = 0x30
STACK_ITEM_TYPE_ARRAY = 0x40
STACK_ITEM_TYPE_STRUCT = 0x41
STACK_ITEM_TYPE_MAP = 0x48
STACK_ITEM_TYPE_INTEROP = 0x60

STACK_ITEM_TYPE_NAME_TO_CODE = {
    "ANY": STACK_ITEM_TYPE_ANY,
    "POINTER": STACK_ITEM_TYPE_POINTER,
    "BOOLEAN": STACK_ITEM_TYPE_BOOLEAN,
    "INTEGER": STACK_ITEM_TYPE_INTEGER,
    "BYTESTRING": STACK_ITEM_TYPE_BYTESTRING,
    "BUFFER": STACK_ITEM_TYPE_BUFFER,
    "ARRAY": STACK_ITEM_TYPE_ARRAY,
    "STRUCT": STACK_ITEM_TYPE_STRUCT,
    "MAP": STACK_ITEM_TYPE_MAP,
    "INTEROPINTERFACE": STACK_ITEM_TYPE_INTEROP,
}

STACK_ITEM_TYPE_CODE_TO_NAME = {
    STACK_ITEM_TYPE_ANY: "Any",
    STACK_ITEM_TYPE_POINTER: "Pointer",
    STACK_ITEM_TYPE_BOOLEAN: "Boolean",
    STACK_ITEM_TYPE_INTEGER: "Integer",
    STACK_ITEM_TYPE_BYTESTRING: "ByteString",
    STACK_ITEM_TYPE_BUFFER: "Buffer",
    STACK_ITEM_TYPE_ARRAY: "Array",
    STACK_ITEM_TYPE_STRUCT: "Struct",
    STACK_ITEM_TYPE_MAP: "Map",
    STACK_ITEM_TYPE_INTEROP: "InteropInterface",
}

VALID_STACK_ITEM_TYPES = set(STACK_ITEM_TYPE_CODE_TO_NAME)

INTEGER_MAX_SIZE = 32
MAX_EVENT_NAME_LENGTH = 32


def opcode_with_embedded_index(name: str) -> int | None:
    for prefix in SHORT_INDEXED_PREFIXES:
        if name.startswith(prefix):
            suffix = name.removeprefix(prefix)
            if suffix.isdigit():
                return int(suffix, 10)
    return None
