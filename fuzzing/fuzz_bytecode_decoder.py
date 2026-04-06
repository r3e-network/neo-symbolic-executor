#!/usr/bin/env python3
"""
Fuzzing harness for NeoVM bytecode decoding.

This harness tests decode_script() with arbitrary bytecode sequences
to find crashes, incorrect instruction decoding, and validation issues.
"""
from __future__ import annotations

import sys

import atheris

try:
    from ._bootstrap import configure_repo_root
except ImportError:
    from _bootstrap import configure_repo_root

configure_repo_root()

with atheris.instrument_imports():
    from neo_symbolic_executor.bytecode import DecodeError, decode_script


def test_one_input(data: bytes) -> None:
    """Test bytecode decoding with arbitrary input."""
    try:
        program = decode_script(data)
    except DecodeError:
        # Expected for invalid bytecode
        pass
    else:
        offsets = [instruction.offset for instruction in program.instructions]
        assert offsets == sorted(offsets)
        assert all(0 <= offset < len(program.script) for offset in offsets)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
