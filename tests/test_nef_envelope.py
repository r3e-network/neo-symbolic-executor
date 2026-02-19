"""Tests for full NEF3 envelope parsing."""
from __future__ import annotations

import struct

import pytest

from neo_sym.nef.opcodes import OpCode
from neo_sym.nef.parser import compute_nef_checksum, parse_nef


def _encode_var_int(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xFD" + struct.pack("<H", value)
    if value <= 0xFFFFFFFF:
        return b"\xFE" + struct.pack("<I", value)
    return b"\xFF" + struct.pack("<Q", value)


def _encode_var_bytes(data: bytes) -> bytes:
    return _encode_var_int(len(data)) + data


def _build_test_nef(script: bytes) -> bytes:
    magic = struct.pack("<I", 0x3346454E)
    compiler = b"neo-unit-test".ljust(64, b"\x00")
    source = _encode_var_bytes(b"https://example.invalid/source")
    reserved1 = b"\x00"

    token_hash = bytes(range(1, 21))
    token_method = _encode_var_bytes(b"transfer")
    token_body = token_hash + token_method + struct.pack("<H", 2) + b"\x01" + b"\x0F"
    tokens = _encode_var_int(1) + token_body

    reserved2 = b"\x00\x00"
    script_field = _encode_var_bytes(script)

    payload_without_checksum = magic + compiler + source + reserved1 + tokens + reserved2 + script_field
    checksum = struct.pack("<I", compute_nef_checksum(payload_without_checksum))
    return payload_without_checksum + checksum


def test_parse_nef3_with_tokens_and_checksum():
    script = bytes([OpCode.PUSH1, OpCode.RET])
    nef_bytes = _build_test_nef(script)
    nef = parse_nef(nef_bytes)

    assert nef.magic == 0x3346454E
    assert nef.compiler == "neo-unit-test"
    assert nef.source == "https://example.invalid/source"
    assert nef.checksum_valid is True
    assert len(nef.tokens) == 1
    assert nef.tokens[0].method == "transfer"
    assert nef.script == script
    assert len(nef.instructions) == 2


def test_parse_nef3_checksum_mismatch_raises():
    script = bytes([OpCode.PUSH1, OpCode.RET])
    nef_bytes = bytearray(_build_test_nef(script))
    nef_bytes[-1] ^= 0xFF

    with pytest.raises(ValueError):
        parse_nef(bytes(nef_bytes))

    parsed = parse_nef(bytes(nef_bytes), verify_checksum=False)
    assert parsed.checksum_valid is False


def test_parse_nef3_rejects_nonzero_reserved_byte():
    script = bytes([OpCode.PUSH1, OpCode.RET])
    nef_bytes = bytearray(_build_test_nef(script))
    source_field = _encode_var_bytes(b"https://example.invalid/source")
    reserved1_index = 4 + 64 + len(source_field)
    nef_bytes[reserved1_index] = 1

    with pytest.raises(ValueError):
        parse_nef(bytes(nef_bytes), verify_checksum=False)
