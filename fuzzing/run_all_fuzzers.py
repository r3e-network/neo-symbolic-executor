#!/usr/bin/env python3
"""
Script to run all fuzzing harnesses sequentially.
"""
from __future__ import annotations

import argparse
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

FUZZING_DIR = Path(__file__).resolve().parent
REPO_ROOT = FUZZING_DIR.parent
DEFAULT_SEED_CORPUS = FUZZING_DIR / "corpus"
LEGACY_SEED_CORPUS = FUZZING_DIR / "seeds"

FUZZERS = [
    "fuzz_nef_parser.py",
    "fuzz_bytecode_decoder.py",
    "fuzz_assembly_parser.py",
    "fuzz_execution_engine.py",
    "fuzz_source_loader.py",
    "fuzz_structured_bytecode.py",
]


@contextlib.contextmanager
def _prepare_corpus_workspace(fuzzer_name: str, corpus_dir: Path | None) -> Path | None:
    if corpus_dir is None:
        yield None
        return
    with tempfile.TemporaryDirectory(prefix=f"{Path(fuzzer_name).stem}-corpus-") as temp_dir:
        workspace = Path(temp_dir) / "corpus"
        shutil.copytree(corpus_dir.resolve(), workspace)
        yield workspace


@contextlib.contextmanager
def _prepare_artifact_dir(fuzzer_name: str, artifacts_dir: Path | None) -> Path:
    if artifacts_dir is None:
        with tempfile.TemporaryDirectory(prefix=f"{Path(fuzzer_name).stem}-artifacts-") as temp_dir:
            yield Path(temp_dir)
        return
    target = artifacts_dir.resolve() / Path(fuzzer_name).stem
    target.mkdir(parents=True, exist_ok=True)
    yield target


def _build_env() -> dict[str, str]:
    env = os.environ.copy()
    python_path = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(REPO_ROOT)
        if not python_path
        else os.pathsep.join([str(REPO_ROOT), python_path])
    )
    return env


def _resolve_corpus_dir(corpus_dir: Path | None) -> Path | None:
    if corpus_dir is not None:
        return corpus_dir
    if DEFAULT_SEED_CORPUS.is_dir():
        return DEFAULT_SEED_CORPUS
    if LEGACY_SEED_CORPUS.is_dir():
        return LEGACY_SEED_CORPUS
    return None


def run_fuzzer(
    fuzzer_name: str,
    duration: int,
    corpus_dir: Path | None = None,
    artifacts_dir: Path | None = None,
) -> int:
    """Run a single fuzzer and return its exit code."""
    fuzzer_path = FUZZING_DIR / fuzzer_name
    resolved_corpus = _resolve_corpus_dir(corpus_dir)
    cmd = [sys.executable, str(fuzzer_path), f"-max_total_time={duration}"]

    with _prepare_corpus_workspace(fuzzer_name, resolved_corpus) as workspace, _prepare_artifact_dir(
        fuzzer_name, artifacts_dir
    ) as artifact_dir:
        if workspace is not None:
            cmd.append(str(workspace))
        cmd.append(f"-artifact_prefix={artifact_dir.as_posix()}/")

        print(f"\n{'='*60}")
        print(f"Running {fuzzer_name} for {duration} seconds...")
        if resolved_corpus is not None:
            print(f"Seed corpus: {resolved_corpus}")
        print(f"Artifacts: {artifact_dir}")
        print(f"{'='*60}\n")

        result = subprocess.run(cmd, check=False, cwd=REPO_ROOT, env=_build_env())  # noqa: S603
        return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Run all fuzzing harnesses")
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Duration in seconds for each fuzzer (default: 60)",
    )
    parser.add_argument(
        "--corpus",
        type=Path,
        help="Seed corpus directory. Defaults to fuzzing/corpus when present.",
    )
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        help="Persist crash artifacts under this directory instead of a temporary location.",
    )
    parser.add_argument(
        "--fuzzers",
        nargs="+",
        choices=FUZZERS,
        help="Specific fuzzers to run (default: all)",
    )

    args = parser.parse_args()
    if args.corpus is not None and not args.corpus.is_dir():
        parser.error(f"Corpus directory does not exist: {args.corpus}")

    fuzzers_to_run = args.fuzzers or FUZZERS
    results = {}

    for fuzzer in fuzzers_to_run:
        exit_code = run_fuzzer(fuzzer, args.duration, args.corpus, args.artifacts_dir)
        results[fuzzer] = exit_code

    print(f"\n{'='*60}")
    print("FUZZING SUMMARY")
    print(f"{'='*60}")

    all_passed = True
    for fuzzer, exit_code in results.items():
        status = "PASS" if exit_code == 0 else "FAIL"
        print(f"  {fuzzer}: {status} (exit code {exit_code})")
        if exit_code != 0:
            all_passed = False

    return 0 if all_passed else 1


if __name__ == "__main__":
    sys.exit(main())
