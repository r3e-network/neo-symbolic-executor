#!/usr/bin/env python3
"""
Fuzzing harness for NeoVM execution engine.

This harness tests explore_program() with generated programs to find
crashes, infinite loops, and incorrect execution behavior.
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
    from neo_symbolic_executor.engine import ExecutionOptions, explore_program

# Safe execution limits to prevent infinite loops during fuzzing
SAFE_LIMITS = ExecutionOptions(
    max_steps=1000,
    max_states=100,
    max_visits_per_instruction=10,
    max_item_size=1024,
    max_collection_size=100,
    max_heap_objects=50,
    max_invocation_stack=10,
    max_try_nesting_depth=5,
    max_shift=256,
)


def test_one_input(data: bytes) -> None:
    """Test program execution with arbitrary bytecode."""
    try:
        program = decode_script(data)
        report = explore_program(program, SAFE_LIMITS)
        assert report.to_dict() == explore_program(program, SAFE_LIMITS).to_dict()
    except DecodeError:
        # Expected for invalid bytecode
        pass
    except RecursionError:
        # Should not happen with limits, but catch it
        pass


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
