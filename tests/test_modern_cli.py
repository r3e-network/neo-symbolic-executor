from __future__ import annotations

import contextlib
import io
import json
import unittest
from pathlib import Path

from neo_symbolic_executor import __version__
from neo_symbolic_executor.__main__ import main

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"


class CliTests(unittest.TestCase):
    def _invoke(self, *args: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = main(list(args))
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def test_json_output_includes_program_metadata(self) -> None:
        exit_code, stdout, stderr = self._invoke("--json", str(EXAMPLES_DIR / "buffer.neoasm"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")

        payload = json.loads(stdout)
        self.assertEqual(payload["program"]["metadata"]["source_type"], "assembly")
        self.assertEqual(payload["program"]["instruction_count"], 11)
        self.assertEqual(payload["returned"][0]["heap"]["buffer#2"], "0x3344")

    def test_invalid_limit_is_reported_to_stderr(self) -> None:
        exit_code, stdout, stderr = self._invoke(
            "--max-item-size",
            "0",
            str(EXAMPLES_DIR / "buffer.neoasm"),
        )
        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("max_item_size must be positive", stderr)

    def test_invalid_shift_limit_is_reported_to_stderr(self) -> None:
        exit_code, stdout, stderr = self._invoke(
            "--max-shift",
            "0",
            str(EXAMPLES_DIR / "buffer.neoasm"),
        )
        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("max_shift must be positive", stderr)

    def test_invalid_script_hash_is_reported_to_stderr(self) -> None:
        exit_code, stdout, stderr = self._invoke(
            "--script-hash",
            "0x1234",
            str(EXAMPLES_DIR / "buffer.neoasm"),
        )
        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("script_hash must be exactly 20 bytes", stderr)

    def test_disassemble_flag_prints_instructions(self) -> None:
        exit_code, stdout, stderr = self._invoke("--disassemble", str(EXAMPLES_DIR / "buffer.neoasm"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Disassembly:", stdout)

    def test_human_readable_output(self) -> None:
        exit_code, stdout, stderr = self._invoke(str(EXAMPLES_DIR / "buffer.neoasm"))
        self.assertEqual(exit_code, 0)
        self.assertEqual(stderr, "")
        self.assertIn("Program length:", stdout)
        self.assertIn("Returned paths:", stdout)

    def test_version_flag(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(__version__, stdout.getvalue())

    def test_file_not_found(self) -> None:
        exit_code, stdout, stderr = self._invoke("/nonexistent/path.neoasm")
        self.assertEqual(exit_code, 2)
        self.assertNotEqual(stderr, "")

    def test_stack_item_flag(self) -> None:
        exit_code, stdout, stderr = self._invoke(
            "--stack-item", "42",
            "--stack-item", "true",
            str(EXAMPLES_DIR / "buffer.neoasm"),
        )
        self.assertEqual(exit_code, 0)

    def test_arg_flag_with_symbolic(self) -> None:
        exit_code, stdout, stderr = self._invoke(
            "--arg", "amount",
            "--json",
            str(EXAMPLES_DIR / "branching.neoasm"),
        )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        self.assertGreater(len(payload["returned"]), 0)

    def test_trigger_flag(self) -> None:
        exit_code, stdout, stderr = self._invoke(
            "--trigger", "verification",
            "--json",
            str(EXAMPLES_DIR / "buffer.neoasm"),
        )
        self.assertEqual(exit_code, 0)

    def test_source_type_override(self) -> None:
        exit_code, stdout, stderr = self._invoke(
            "--source-type", "assembly",
            "--json",
            str(EXAMPLES_DIR / "buffer.neoasm"),
        )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout)
        self.assertEqual(payload["program"]["metadata"]["source_type"], "assembly")


if __name__ == "__main__":
    unittest.main()
