#!/usr/bin/env python3
"""
Fuzzing harness for NEF file parsing.

This harness feeds arbitrary bytes to parse_nef() to find crashes,
memory issues, and incorrect parsing behavior.
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
    from neo_symbolic_executor.nef import NefParseError, parse_nef


def test_one_input(data: bytes) -> None:
    """Test NEF parsing with arbitrary input."""
    try:
        nef = parse_nef(data)
    except NefParseError:
        # Expected error for invalid inputs
        pass
    except UnicodeDecodeError:
        # Can happen during string decoding - should be handled
        pass
    else:
        assert nef.script
        assert len(nef.checksum) == 4
        assert all(token.call_flags & ~0x0F == 0 for token in nef.method_tokens)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
