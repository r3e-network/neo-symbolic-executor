from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fuzzing.run_all_fuzzers import (
    DEFAULT_SEED_CORPUS,
    _prepare_artifact_dir,
    _prepare_corpus_workspace,
    _resolve_corpus_dir,
)


class FuzzingRunnerTests(unittest.TestCase):
    def test_resolve_corpus_defaults_to_curated_seeds(self) -> None:
        self.assertEqual(_resolve_corpus_dir(None), DEFAULT_SEED_CORPUS)

    def test_prepare_corpus_workspace_copies_without_mutating_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            source = Path(temp_dir) / "seed-corpus"
            source.mkdir()
            (source / "seed.bin").write_bytes(b"\x01\x02")

            with _prepare_corpus_workspace("fuzz_execution_engine.py", source) as workspace:
                assert workspace is not None
                self.assertNotEqual(workspace, source)
                self.assertEqual((workspace / "seed.bin").read_bytes(), b"\x01\x02")
                (workspace / "generated.bin").write_bytes(b"\x03")

            self.assertFalse((source / "generated.bin").exists())
            self.assertEqual((source / "seed.bin").read_bytes(), b"\x01\x02")

    def test_prepare_artifact_dir_uses_named_subdirectory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifacts_root = Path(temp_dir)
            with _prepare_artifact_dir("fuzz_execution_engine.py", artifacts_root) as artifact_dir:
                self.assertEqual(artifact_dir, artifacts_root / "fuzz_execution_engine")
                self.assertTrue(artifact_dir.is_dir())
