"""Fuzz harness — main loop, stats, crash handling, daemon mode."""
from __future__ import annotations

import hashlib
import os
import signal
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

from . import generators as gen
from . import targets
from .config import (
    CI_MAX_DEPTH,
    CI_MAX_PATHS,
    CI_PROGRAM_SIZE,
    CRASH_DIR,
    DAEMON_MAX_DEPTH,
    DAEMON_MAX_PATHS,
    DAEMON_PROGRAM_SIZE,
    LOG_FILE,
    LOG_INTERVAL_ROUNDS,
    MAX_CORPUS_SIZE,
    CORPUS_PRUNE_TARGET,
    MAX_CRASH_FILES,
    OUTPUT_DIR,
    STATUS_FILE,
    STATUS_INTERVAL_SECS,
)


# ── Stats ──────────────────────────────────────────────────────────

class Stats:
    __slots__ = ("runs", "crashes", "by_target", "total_paths", "start_time",
                 "_crash_hashes", "_crash_file_count")

    def __init__(self) -> None:
        self.runs = 0
        self.crashes = 0
        self.by_target: dict[str, list[int]] = {}  # name -> [ok, crash]
        self.total_paths = 0
        self.start_time = time.monotonic()
        self._crash_hashes: set[str] = set()
        self._crash_file_count = 0

    def record_ok(self, target: str, paths: int = 0) -> None:
        self.runs += 1
        self.total_paths += paths
        self.by_target.setdefault(target, [0, 0])[0] += 1

    def record_crash(self, target: str, error: str, round_num: int) -> bool:
        """Record a crash. Returns True if this is a NEW unique crash."""
        self.runs += 1
        self.crashes += 1
        self.by_target.setdefault(target, [0, 0])[1] += 1
        sig = _crash_signature(error)
        if sig in self._crash_hashes:
            return False
        self._crash_hashes.add(sig)
        if self._crash_file_count < MAX_CRASH_FILES:
            _save_crash(target, error, round_num, sig)
            self._crash_file_count += 1
        return True

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def rate(self) -> float:
        e = self.elapsed
        return self.runs / e if e > 0 else 0

    @property
    def unique_crashes(self) -> int:
        return len(self._crash_hashes)

    def summary(self, round_num: int) -> str:
        h = self.elapsed / 3600
        return (f"round={round_num} runs={self.runs} crashes={self.crashes} "
                f"unique={self.unique_crashes} paths={self.total_paths} "
                f"rate={self.rate:.0f}/s elapsed={h:.2f}h")


# ── Crash handling ─────────────────────────────────────────────────

def _crash_signature(error: str) -> str:
    """Dedup crashes by hashing (exception type + last frame location)."""
    lines = error.strip().splitlines()
    # Last line is the exception, second-to-last is the frame.
    key_parts = lines[-1:] if len(lines) < 2 else lines[-2:]
    return hashlib.sha256("\n".join(key_parts).encode()).hexdigest()[:16]


def _save_crash(target: str, error: str, round_num: int, sig: str) -> None:
    CRASH_DIR.mkdir(parents=True, exist_ok=True)
    path = CRASH_DIR / f"crash_{sig}_{target}.txt"
    try:
        path.write_text(
            f"Target: {target}\n"
            f"Round: {round_num}\n"
            f"Time: {datetime.now(timezone.utc).isoformat()}\n"
            f"Signature: {sig}\n\n"
            f"{error[:5000]}\n"
        )
    except OSError:
        pass


# ── Logging ────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except OSError:
        pass


def _write_status(stats: Stats, round_num: int) -> None:
    try:
        h = stats.elapsed / 3600
        lines = [
            "neo-sym fuzzer",
            "=" * 50,
            f"Updated: {datetime.now(timezone.utc).isoformat()}",
            f"Round: {round_num}",
            f"Executions: {stats.runs}",
            f"Crashes: {stats.crashes} ({stats.unique_crashes} unique)",
            f"Paths explored: {stats.total_paths}",
            f"Rate: {stats.rate:.0f} exec/s",
            f"Elapsed: {h:.2f}h ({stats.elapsed:.0f}s)",
            "",
            "Per-target:",
        ]
        for name, (ok, crash) in sorted(stats.by_target.items()):
            tag = "OK" if crash == 0 else f"CRASH({crash})"
            lines.append(f"  {name:30s}  ok={ok:>7d}  crash={crash:>3d}  [{tag}]")
        STATUS_FILE.write_text("\n".join(lines) + "\n")
    except OSError:
        pass


# ── Target dispatch ────────────────────────────────────────────────

# (target_fn_name, weight_ci, weight_daemon)
TARGET_TABLE: list[tuple[str, int, int]] = [
    ("disassembler", 2, 1),
    ("nef_raw", 2, 1),
    ("nef_envelope", 2, 2),
    ("manifest_parser", 2, 2),
    ("engine_valid", 4, 3),
    ("engine_mutation", 3, 4),
    ("detectors", 3, 2),
    ("clone_isolation", 2, 2),
    ("report_generator", 1, 1),
    ("full_pipeline", 2, 3),
]


def _dispatch(name: str, corpus: list[bytes], **kw) -> tuple[bool, str | None, int]:
    """Run a target by name. Returns (ok, error, paths)."""
    fn = getattr(targets, name)
    result = fn(**kw) if name != "engine_mutation" else fn(corpus, **kw)
    if len(result) == 2:
        return result[0], result[1], 0
    return result


# ── Main loop ──────────────────────────────────────────────────────

def run(*, mode: str = "ci", rounds: int = 100, seed: int | None = None,
        workers: int = 1) -> int:
    """Main entry point.

    *mode*: "ci" (bounded, fail-fast), "daemon" (infinite, heavy).
    Returns exit code (0 = clean, 1 = crashes found).
    """
    effective_seed = seed if seed is not None else int(time.time() * 1000) % (2**32)
    gen.seed(effective_seed)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    CRASH_DIR.mkdir(exist_ok=True)

    is_daemon = mode == "daemon"
    max_paths = DAEMON_MAX_PATHS if is_daemon else CI_MAX_PATHS
    max_depth = DAEMON_MAX_DEPTH if is_daemon else CI_MAX_DEPTH
    program_size = DAEMON_PROGRAM_SIZE if is_daemon else CI_PROGRAM_SIZE
    weights = [(name, wd if is_daemon else wc) for name, wc, wd in TARGET_TABLE]
    iters_per_round = sum(w for _, w in weights)

    corpus: list[bytes] = []
    # Seed the corpus.
    for _ in range(20):
        corpus.append(gen.valid_program(gen.R.randint(30, 300)))
    corpus.append(gen.realistic_contract())
    corpus.append(gen.branch_explosion(8))

    stats = Stats()
    round_num = 0
    last_status = time.monotonic()
    infinite = rounds <= 0

    _log(f"neo-sym fuzzer | mode={mode} seed={effective_seed} "
         f"rounds={'inf' if infinite else rounds} max_paths={max_paths}")

    # Graceful shutdown.
    def _shutdown(signum, _frame):
        _log(f"Signal {signum} — stopping")
        _write_status(stats, round_num)
        _log(stats.summary(round_num))
        sys.exit(0 if stats.crashes == 0 else 1)

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    kw = dict(max_paths=max_paths, max_depth=max_depth, program_size=program_size)

    try:
        while True:
            round_num += 1
            if not infinite and round_num > rounds:
                break

            for name, weight in weights:
                for _ in range(weight):
                    try:
                        ok, error, paths = _dispatch(name, corpus, **kw)
                    except Exception:
                        ok, error, paths = False, traceback.format_exc(), 0

                    if ok:
                        stats.record_ok(name, paths)
                    else:
                        is_new = stats.record_crash(name, error or "", round_num)
                        if is_new:
                            _log(f"NEW CRASH [{name}]: {(error or '')[:200]}")
                        if mode == "ci":
                            _log(f"FAIL — crash in {name} at round {round_num}")
                            _write_status(stats, round_num)
                            return 1

            # Periodic housekeeping.
            if round_num % LOG_INTERVAL_ROUNDS == 0:
                _log(f"{stats.summary(round_num)} corpus={len(corpus)}")

            now = time.monotonic()
            if now - last_status >= STATUS_INTERVAL_SECS:
                _write_status(stats, round_num)
                last_status = now

            if len(corpus) > MAX_CORPUS_SIZE:
                corpus[:] = gen.R.sample(corpus, CORPUS_PRUNE_TARGET)

    except KeyboardInterrupt:
        pass

    _write_status(stats, round_num)
    _log(stats.summary(round_num))
    return 1 if stats.crashes > 0 else 0
