from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from neo_symbolic_executor.assembly import ParseError, parse_program, parse_script_items
from neo_symbolic_executor.bytecode import DecodeError, decode_hex_string
from neo_symbolic_executor.nef import NefParseError
from neo_symbolic_executor.source import load_program_file


def _encode_var_int(value: int) -> bytes:
    if value < 0xFD:
        return bytes([value])
    if value <= 0xFFFF:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xFFFFFFFF:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def _encode_var_bytes(payload: bytes) -> bytes:
    return _encode_var_int(len(payload)) + payload


def _build_method_token(
    hash_bytes: bytes,
    method: str,
    parameters_count: int,
    has_return_value: bool,
    call_flags: int,
) -> bytes:
    return (
        hash_bytes
        + _encode_var_bytes(method.encode("utf-8"))
        + parameters_count.to_bytes(2, "little")
        + bytes([1 if has_return_value else 0, call_flags])
    )


def _build_nef(
    script: bytes,
    compiler: str = "neo-symbolic-executor",
    source: str = "",
    method_tokens: list[bytes] | None = None,
) -> bytes:
    header = bytearray()
    header.extend((0x3346454E).to_bytes(4, "little"))
    header.extend(compiler.encode("ascii")[:64].ljust(64, b"\x00"))
    source_bytes = source.encode("utf-8")
    header.extend(_encode_var_int(len(source_bytes)))
    header.extend(source_bytes)
    header.append(0)
    method_tokens = method_tokens or []
    header.extend(_encode_var_int(len(method_tokens)))
    for token in method_tokens:
        header.extend(token)
    header.extend((0).to_bytes(2, "little"))
    header.extend(_encode_var_int(len(script)))
    header.extend(script)
    checksum = hashlib.sha256(hashlib.sha256(bytes(header)).digest()).digest()[:4]
    return bytes(header) + checksum


class ParserTests(unittest.TestCase):
    def test_assembly_uses_real_neovm_offsets(self) -> None:
        program = parse_program(
            """
            PUSH1
            PUSH0
            JMPEQ done
            RET
            done:
            RET
            """
        )

        self.assertEqual(program.script.hex(), "111028034040")
        self.assertEqual(program.instructions[2].offset, 2)
        self.assertEqual(program.instructions[2].target, 5)
        self.assertEqual(program.labels["done"], 5)

    def test_decode_hex_script(self) -> None:
        program = decode_hex_string("111028034040")
        self.assertEqual([instruction.offset for instruction in program.instructions], [0, 1, 2, 4, 5])
        self.assertEqual(program.instructions[2].opcode, "JMPEQ")
        self.assertEqual(program.instructions[2].target, 5)

    def test_parse_script_items_matches_neo_vm_json_style(self) -> None:
        program = parse_script_items(["PUSH1", "PUSH0", "JMPEQ", "0x03", "RET", "RET"])
        self.assertEqual(program.script.hex(), "111028034040")

    def test_rejects_unknown_jump_target(self) -> None:
        with self.assertRaises(ParseError):
            parse_program("JMP missing")

    def test_invalid_jump_target_in_hex_is_rejected(self) -> None:
        with self.assertRaises(DecodeError):
            decode_hex_string("2201")

    def test_invalid_try_target_in_hex_is_rejected(self) -> None:
        with self.assertRaises(DecodeError):
            decode_hex_string("3b0500")

    def test_loads_nef_and_extracts_script(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.nef"
            path.write_bytes(_build_nef(bytes.fromhex("111040"), source="unit-test"))
            program = load_program_file(str(path))

        self.assertEqual(program.script.hex(), "111040")
        self.assertEqual(program.metadata["source_type"], "nef")
        self.assertEqual(program.metadata["nef_source"], "unit-test")
        self.assertEqual(program.metadata["method_tokens"], [])

    def test_loads_nef_method_tokens_into_metadata(self) -> None:
        token = _build_method_token(
            bytes.fromhex("00112233445566778899aabbccddeeff00112233"),
            "transfer",
            2,
            True,
            5,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "sample.nef"
            path.write_bytes(_build_nef(bytes.fromhex("370040"), method_tokens=[token]))
            program = load_program_file(str(path))

        self.assertEqual(
            program.metadata["method_tokens"],
            [
                {
                    "hash": "0x33221100ffeeddccbbaa99887766554433221100",
                    "method": "transfer",
                    "parameters_count": 2,
                    "has_return_value": True,
                    "call_flags": 5,
                }
            ],
        )

    def test_assembles_callt_and_syscall_operands(self) -> None:
        program = parse_program(
            """
            CALLT 4660
            SYSCALL 305419896
            """
        )

        self.assertEqual(program.script.hex(), "3734124178563412")
        self.assertEqual(program.instructions[0].argument, 4660)
        self.assertEqual(program.instructions[1].argument, 305419896)

    # --- NEF parser error paths ---

    def test_nef_too_small_raises(self) -> None:
        with self.assertRaises(NefParseError), tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "tiny.nef"
                path.write_bytes(b"NEF3")
                load_program_file(str(path))

    def test_nef_invalid_magic_raises(self) -> None:
        with self.assertRaises(NefParseError), tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "bad.nef"
                header = bytearray()
                header.extend((0xDEADBEEF).to_bytes(4, "little"))
                header.extend(b"\x00" * 64)
                header.append(0)
                header.extend((0).to_bytes(2, "little"))
                header.extend(_encode_var_int(1))
                header.append(0x40)
                checksum = hashlib.sha256(hashlib.sha256(bytes(header)).digest()).digest()[:4]
                path.write_bytes(bytes(header) + checksum)
                load_program_file(str(path))

    def test_nef_bad_checksum_raises(self) -> None:
        with self.assertRaises(NefParseError), tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "bad.nef"
                path.write_bytes(_build_nef(bytes.fromhex("111040"))[:-1] + b"\x00")
                load_program_file(str(path))

    def test_nef_empty_script_raises(self) -> None:
        with self.assertRaises(NefParseError), tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "empty.nef"
                path.write_bytes(_build_nef(b""))
                load_program_file(str(path))

    # --- Assembly error paths ---

    def test_duplicate_label_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse_program("foo:\nPUSH1\nfoo:\nPUSH2")

    def test_wrong_operand_count_raises(self) -> None:
        with self.assertRaises(ParseError):
            parse_program("PUSH")

    def test_comment_handling(self) -> None:
        program = parse_program("PUSH1 # this is a comment\nRET")
        self.assertEqual(len(program.instructions), 2)

    def test_semicolon_comment(self) -> None:
        program = parse_program("PUSH1 ; this is also a comment\nRET")
        self.assertEqual(len(program.instructions), 2)

    def test_unterminated_quote_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            parse_program('"unterminated')

    def test_malformed_escape_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            parse_program("\\")

    def test_invalid_hex_literal_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            parse_program("PUSHDATA1 0x0")

    def test_parse_script_items_invalid_hex_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            parse_script_items(["PUSH1", "0x0"])

    def test_jump_to_label_without_instruction_raises_parse_error(self) -> None:
        with self.assertRaises(ParseError):
            parse_program(
                """
                JMP end
                end:
                ; comment only
                """
            )

    # --- Source auto-detection ---

    def test_loads_hex_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "script.hex"
            path.write_text("111040")
            program = load_program_file(str(path))
        self.assertEqual(program.metadata["source_type"], "hex")
        self.assertEqual(len(program.instructions), 3)

    def test_loads_binary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "script.bin"
            path.write_bytes(bytes.fromhex("1140"))
            program = load_program_file(str(path))
        self.assertEqual(program.metadata["source_type"], "binary")

    def test_loads_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "script.json"
            path.write_text('["PUSH1", "RET"]')
            program = load_program_file(str(path))
        self.assertEqual(program.metadata["source_type"], "json")
        self.assertEqual(len(program.instructions), 2)

    def test_invalid_json_payload_raises(self) -> None:
        with self.assertRaises(DecodeError), tempfile.TemporaryDirectory() as temp_dir:
                path = Path(temp_dir) / "bad.json"
                path.write_text('{"not_script": true}')
                load_program_file(str(path))

    # --- Bytecode error paths ---

    def test_odd_hex_string_raises(self) -> None:
        with self.assertRaises(DecodeError):
            decode_hex_string("123")

    def test_non_hex_characters_raises(self) -> None:
        with self.assertRaises(DecodeError):
            decode_hex_string("zz")


if __name__ == "__main__":
    unittest.main()
