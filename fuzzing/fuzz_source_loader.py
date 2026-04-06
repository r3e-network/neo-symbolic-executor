#!/usr/bin/env python3
"""
Fuzzing harness for source type detection and loading.

This harness tests the source loading pipeline with various input formats.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import atheris

try:
    from ._bootstrap import configure_repo_root
except ImportError:
    from _bootstrap import configure_repo_root

configure_repo_root()

with atheris.instrument_imports():
    from neo_symbolic_executor.assembly import ParseError
    from neo_symbolic_executor.bytecode import DecodeError
    from neo_symbolic_executor.nef import NefParseError
    from neo_symbolic_executor.source import load_program_file


def test_one_input(data: bytes) -> None:
    """Test source loading with arbitrary input via temporary file."""
    # Try different file extensions to test auto-detection
    extensions = [".neoasm", ".hex", ".nef", ".json", ".bin"]

    for ext in extensions:
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as f:
                f.write(data)
                temp_path = Path(f.name)

            try:
                program = load_program_file(str(temp_path))
            except (DecodeError, ParseError, NefParseError, UnicodeDecodeError, json.JSONDecodeError):
                # Expected for invalid inputs
                pass
            else:
                assert len(program.instructions) >= 0
                assert len(program.script) >= 0
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
