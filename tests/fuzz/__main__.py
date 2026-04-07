"""CLI entry point: python -m tests.fuzz [OPTIONS]

Modes:
  --ci          Bounded run, fail-fast on first crash (default: 200 rounds)
  --daemon      Infinite run for long-duration fuzzing
  --rounds N    Override round count (0 = infinite)

Examples:
  PYTHONPATH=src python -m tests.fuzz --ci --rounds 500
  PYTHONPATH=src nohup python -m tests.fuzz --daemon &
"""
from __future__ import annotations

import argparse
import sys

from .harness import run


def main() -> None:
    p = argparse.ArgumentParser(prog="tests.fuzz", description="neo-sym fuzzer")
    mode_group = p.add_mutually_exclusive_group()
    mode_group.add_argument("--ci", action="store_true", help="CI mode: bounded, fail on crash")
    mode_group.add_argument("--daemon", action="store_true", help="Daemon mode: infinite, heavy")
    p.add_argument("--rounds", type=int, default=None, help="Round count (0 = infinite)")
    p.add_argument("--seed", type=int, default=None, help="Random seed")
    args = p.parse_args()

    mode = "daemon" if args.daemon else "ci"
    if args.rounds is not None:
        rounds = args.rounds
    else:
        rounds = 0 if mode == "daemon" else 200

    sys.exit(run(mode=mode, rounds=rounds, seed=args.seed))


main()
