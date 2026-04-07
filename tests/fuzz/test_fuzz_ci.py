"""Pytest-discoverable fuzz tests.

Run:  PYTHONPATH=src pytest tests/fuzz/test_fuzz_ci.py -v
      PYTHONPATH=src pytest tests/fuzz/test_fuzz_ci.py -k heavy

Each test function runs a bounded fuzz campaign and fails on any crash.
"""
from __future__ import annotations

import pytest

from . import generators as gen
from . import targets


@pytest.fixture(autouse=True)
def _seed_rng():
    gen.seed(12345)


# ── Parser fuzz tests ──────────────────────────────────────────────

class TestParserFuzz:
    @pytest.mark.parametrize("_round", range(100))
    def test_disassembler(self, _round):
        ok, err = targets.disassembler()
        assert ok, err

    @pytest.mark.parametrize("_round", range(100))
    def test_nef_raw(self, _round):
        ok, err = targets.nef_raw()
        assert ok, err

    @pytest.mark.parametrize("_round", range(50))
    def test_nef_envelope(self, _round):
        ok, err = targets.nef_envelope()
        assert ok, err

    @pytest.mark.parametrize("_round", range(100))
    def test_manifest(self, _round):
        ok, err = targets.manifest_parser()
        assert ok, err


# ── Engine fuzz tests ──────────────────────────────────────────────

class TestEngineFuzz:
    @pytest.mark.parametrize("_round", range(50))
    def test_engine_valid(self, _round):
        ok, err, _paths = targets.engine_valid(max_paths=32, max_depth=64)
        assert ok, err

    @pytest.mark.parametrize("_round", range(50))
    def test_engine_mutation(self, _round):
        corpus: list[bytes] = [gen.valid_program(50)]
        ok, err, _paths = targets.engine_mutation(corpus, max_paths=32, max_depth=64)
        assert ok, err


# ── Detector fuzz tests ────────────────────────────────────────────

class TestDetectorFuzz:
    @pytest.mark.parametrize("_round", range(50))
    def test_detectors(self, _round):
        ok, err = targets.detectors()
        assert ok, err


# ── Clone isolation tests ──────────────────────────────────────────

class TestCloneFuzz:
    @pytest.mark.parametrize("_round", range(50))
    def test_clone_isolation(self, _round):
        ok, err = targets.clone_isolation()
        assert ok, err


# ── Report fuzz tests ──────────────────────────────────────────────

class TestReportFuzz:
    @pytest.mark.parametrize("_round", range(30))
    def test_report_generator(self, _round):
        ok, err = targets.report_generator()
        assert ok, err


# ── Full pipeline fuzz tests ───────────────────────────────────────

class TestPipelineFuzz:
    @pytest.mark.parametrize("_round", range(20))
    def test_full_pipeline(self, _round):
        ok, err, _paths = targets.full_pipeline(
            max_paths=32, max_depth=64, program_size=(10, 80))
        assert ok, err


# ── Heavy fuzz (opt-in via -k heavy or --run-heavy) ────────────────

class TestHeavyFuzz:
    """Longer-running fuzz tests. Skipped by default; run with -k heavy."""

    @pytest.mark.parametrize("_round", range(200))
    def test_heavy_engine(self, _round):
        ok, err, _paths = targets.engine_valid(
            max_paths=128, max_depth=128, program_size=(50, 500))
        assert ok, err

    @pytest.mark.parametrize("_round", range(100))
    def test_heavy_pipeline(self, _round):
        ok, err, _paths = targets.full_pipeline(
            max_paths=128, max_depth=128, program_size=(100, 800))
        assert ok, err
