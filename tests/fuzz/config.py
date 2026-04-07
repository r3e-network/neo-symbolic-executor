"""Fuzz configuration — all tunables in one place."""
from __future__ import annotations

from pathlib import Path

# ── Output ──────────────────────────────────────────────────────────
OUTPUT_DIR = Path("/tmp/neo-fuzz")
CRASH_DIR = OUTPUT_DIR / "crashes"
CORPUS_DIR = OUTPUT_DIR / "corpus"
STATUS_FILE = OUTPUT_DIR / "status.txt"
LOG_FILE = OUTPUT_DIR / "fuzz.log"

# ── Engine limits (per-mode) ────────────────────────────────────────
CI_MAX_PATHS = 32
CI_MAX_DEPTH = 64
CI_PROGRAM_SIZE = (5, 50)

DAEMON_MAX_PATHS = 256
DAEMON_MAX_DEPTH = 256
DAEMON_PROGRAM_SIZE = (50, 2000)

# ── Harness ─────────────────────────────────────────────────────────
STATUS_INTERVAL_SECS = 60
LOG_INTERVAL_ROUNDS = 50
MAX_CORPUS_SIZE = 500
CORPUS_PRUNE_TARGET = 250

# ── Crash dedup ─────────────────────────────────────────────────────
MAX_CRASH_FILES = 1000
