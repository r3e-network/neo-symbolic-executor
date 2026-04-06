from __future__ import annotations

import hashlib
from dataclasses import dataclass

NEF_MAGIC = 0x3346454E
NEF_MAX_SOURCE_LENGTH = 256
NEF_MAX_METHOD_TOKENS = 128
NEF_MAX_METHOD_NAME_LENGTH = 32
NEF_MAX_SCRIPT_LENGTH = 131_070


class NefParseError(ValueError):
    pass


@dataclass(frozen=True)
class NefFile:
    compiler: str
    source: str
    method_tokens: tuple[MethodToken, ...]
    script: bytes
    checksum: bytes


@dataclass(frozen=True)
class MethodToken:
    hash: str
    method: str
    parameters_count: int
    has_return_value: bool
    call_flags: int

    def to_dict(self) -> dict[str, object]:
        return {
            "hash": self.hash,
            "method": self.method,
            "parameters_count": self.parameters_count,
            "has_return_value": self.has_return_value,
            "call_flags": self.call_flags,
        }


def parse_nef(data: bytes) -> NefFile:
    if len(data) < 4 + 64 + 1 + 1 + 2 + 1 + 4:
        raise NefParseError("NEF file is too small")
    if int.from_bytes(data[:4], "little") != NEF_MAGIC:
        raise NefParseError("Invalid NEF magic")

    computed_checksum = hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4]
    checksum = data[-4:]
    if checksum != computed_checksum:
        raise NefParseError("Invalid NEF checksum")

    cursor = 4
    compiler = data[cursor : cursor + 64].rstrip(b"\x00").decode("ascii", errors="ignore")
    cursor += 64

    source, cursor = _read_var_bytes(data, cursor, decode_text=True, max_length=NEF_MAX_SOURCE_LENGTH)
    reserved = data[cursor]
    cursor += 1
    if reserved != 0:
        raise NefParseError("Invalid NEF reserved byte")

    token_count, cursor = _read_var_int(data, cursor)
    if token_count > NEF_MAX_METHOD_TOKENS:
        raise NefParseError(f"NEF method token count {token_count} exceeds limit {NEF_MAX_METHOD_TOKENS}")
    method_tokens: list[MethodToken] = []
    for _ in range(token_count):
        token, cursor = _read_method_token(data, cursor)
        method_tokens.append(token)

    if data[cursor : cursor + 2] != b"\x00\x00":
        raise NefParseError("Invalid NEF reserved uint16")
    cursor += 2

    script, cursor = _read_var_bytes(data, cursor, max_length=NEF_MAX_SCRIPT_LENGTH)
    if cursor != len(data) - 4:
        raise NefParseError("Unexpected trailing bytes before NEF checksum")
    if not script:
        raise NefParseError("NEF script payload is empty")
    return NefFile(
        compiler=compiler,
        source=source,
        method_tokens=tuple(method_tokens),
        script=script,
        checksum=checksum,
    )


def _read_var_int(data: bytes, cursor: int) -> tuple[int, int]:
    if cursor >= len(data):
        raise NefParseError("Unexpected end of NEF while reading compact integer")
    prefix = data[cursor]
    cursor += 1
    if prefix < 0xFD:
        return prefix, cursor
    if prefix == 0xFD:
        if cursor + 2 > len(data):
            raise NefParseError("Unexpected end of NEF while reading uint16 compact integer")
        return int.from_bytes(data[cursor : cursor + 2], "little"), cursor + 2
    if prefix == 0xFE:
        if cursor + 4 > len(data):
            raise NefParseError("Unexpected end of NEF while reading uint32 compact integer")
        return int.from_bytes(data[cursor : cursor + 4], "little"), cursor + 4
    if cursor + 8 > len(data):
        raise NefParseError("Unexpected end of NEF while reading uint64 compact integer")
    return int.from_bytes(data[cursor : cursor + 8], "little"), cursor + 8


def _read_var_bytes(
    data: bytes,
    cursor: int,
    decode_text: bool = False,
    max_length: int | None = None,
) -> tuple[bytes | str, int]:
    length, cursor = _read_var_int(data, cursor)
    if max_length is not None and length > max_length:
        raise NefParseError(f"Variable payload length {length} exceeds limit {max_length}")
    if cursor + length > len(data):
        raise NefParseError("Unexpected end of NEF while reading variable payload")
    payload = data[cursor : cursor + length]
    cursor += length
    if decode_text:
        return payload.decode("utf-8", errors="ignore"), cursor
    return payload, cursor


def _read_method_token(data: bytes, cursor: int) -> tuple[MethodToken, int]:
    if cursor + 20 > len(data):
        raise NefParseError("Unexpected end of NEF while reading method token hash")
    hash_bytes = data[cursor : cursor + 20]
    cursor += 20
    method, cursor = _read_var_bytes(
        data,
        cursor,
        decode_text=True,
        max_length=NEF_MAX_METHOD_NAME_LENGTH,
    )
    if method.startswith("_"):
        raise NefParseError("NEF method token names cannot start with '_'")
    if cursor + 2 + 1 + 1 > len(data):
        raise NefParseError("Unexpected end of NEF while reading method token tail")
    parameters_count = int.from_bytes(data[cursor : cursor + 2], "little")
    has_return_value = bool(data[cursor + 2])
    call_flags = data[cursor + 3]
    if call_flags & ~0x0F:
        raise NefParseError(f"Invalid NEF method token call flags: {call_flags}")
    cursor += 4
    return (
        MethodToken(
            hash=_render_uint160(hash_bytes),
            method=method,
            parameters_count=parameters_count,
            has_return_value=has_return_value,
            call_flags=call_flags,
        ),
        cursor,
    )


def _render_uint160(value: bytes) -> str:
    return "0x" + value[::-1].hex()
