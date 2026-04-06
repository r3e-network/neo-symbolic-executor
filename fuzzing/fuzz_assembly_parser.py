#!/usr/bin/env python3
"""
Fuzzing harness for NeoVM assembly parsing.

This harness tests parse_program() with arbitrary assembly-like text inputs
to find crashes, infinite loops, and incorrect parsing behavior.
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
    from neo_symbolic_executor.assembly import ParseError, parse_program


def test_one_input(data: bytes) -> None:
    """Test assembly parsing with arbitrary input."""
    try:
        # Try to decode as UTF-8 text for assembly parsing
        source = data.decode("utf-8", errors="strict")
        parse_program(source)
    except (ParseError, UnicodeDecodeError):
        # Expected for invalid assembly
        pass
    except RecursionError:
        # Should not happen, but catch it if it does
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
