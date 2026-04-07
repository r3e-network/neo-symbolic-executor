"""Fuzz targets — each function exercises one subsystem and returns (ok, error)."""
from __future__ import annotations

import json
import traceback

from neo_sym.nef.parser import NefFile, disassemble, parse_nef
from neo_sym.nef.manifest import parse_manifest
from neo_sym.engine.state import ExecutionState, ExternalCall, StorageOp, SymbolicValue
from neo_sym.engine.symbolic import SymbolicEngine
from neo_sym.detectors import ALL_DETECTORS
from neo_sym.detectors.base import Finding, Severity
from neo_sym.report.generator import ReportGenerator

from . import generators as gen


def _run_engine(script: bytes, *, max_paths: int, max_depth: int,
                manifest=None) -> list[ExecutionState]:
    instructions = disassemble(script)
    nef = NefFile(script=script, instructions=instructions)
    engine = SymbolicEngine(nef, manifest)
    engine.MAX_PATHS = max_paths
    engine.MAX_DEPTH = max_depth
    return engine.run()


# ── Target: disassembler ───────────────────────────────────────────

def disassembler(max_paths: int = 32, **_kw) -> tuple[bool, str | None]:
    data = gen.random_bytes(gen.R.randint(1, 256))
    try:
        disassemble(data)
        return True, None
    except ValueError:
        return True, None
    except Exception:
        return False, traceback.format_exc()


# ── Target: NEF parser ─────────────────────────────────────────────

def nef_raw(max_paths: int = 32, **_kw) -> tuple[bool, str | None]:
    data = gen.random_bytes(gen.R.randint(1, 512))
    try:
        parse_nef(data, verify_checksum=False)
        return True, None
    except ValueError:
        return True, None
    except Exception:
        return False, traceback.format_exc()


def nef_envelope(max_paths: int = 32, **_kw) -> tuple[bool, str | None]:
    script = gen.valid_program(gen.R.randint(2, 30))
    corrupt = gen.R.random() < 0.2
    data = gen.nef_envelope(script, num_tokens=gen.R.randint(0, 5), corrupt=corrupt)
    if gen.R.random() < 0.3:
        data = gen.mutate(data, intensity=0)
    try:
        parse_nef(data, verify_checksum=False)
        return True, None
    except ValueError:
        return True, None
    except Exception:
        return False, traceback.format_exc()


# ── Target: manifest parser ────────────────────────────────────────

def manifest_parser(max_paths: int = 32, **_kw) -> tuple[bool, str | None]:
    raw = gen.malformed_manifest_json()
    try:
        parse_manifest(raw)
        return True, None
    except (ValueError, json.JSONDecodeError):
        return True, None
    except Exception:
        return False, traceback.format_exc()


# ── Target: engine (valid programs) ────────────────────────────────

def engine_valid(max_paths: int = 128, max_depth: int = 128,
                 program_size: tuple[int, int] = (5, 50),
                 **_kw) -> tuple[bool, str | None, int]:
    """Returns (ok, error, paths_explored)."""
    lo, hi = program_size
    fn = gen.R.choice([
        lambda: gen.valid_program(gen.R.randint(lo, hi)),
        lambda: gen.branch_explosion(gen.R.randint(4, min(12, hi // 3))),
        lambda: gen.syscall_chain(gen.R.randint(5, min(40, hi))),
        lambda: gen.nested_try(gen.R.randint(2, 6)),
        lambda: gen.arithmetic_torture(gen.R.randint(10, min(100, hi))),
        lambda: gen.realistic_contract(),
        lambda: gen.deep_stack(gen.R.randint(10, min(50, hi))),
    ])
    script = fn()
    try:
        instructions = disassemble(script)
    except ValueError:
        return True, None, 0
    try:
        states = _run_engine(script, max_paths=max_paths, max_depth=max_depth)
        for s in states:
            assert s.halted, "final state must be halted"
        return True, None, len(states)
    except Exception:
        return False, traceback.format_exc(), 0


# ── Target: engine (mutation-based) ────────────────────────────────

def engine_mutation(corpus: list[bytes], max_paths: int = 128, max_depth: int = 128,
                    **_kw) -> tuple[bool, str | None, int]:
    if not corpus:
        corpus.append(gen.valid_program(100))
    parent = gen.R.choice(corpus)
    mutated = gen.mutate(parent, intensity=gen.R.choice([0, 1, 2]))
    try:
        instructions = disassemble(mutated)
    except ValueError:
        return True, None, 0
    try:
        states = _run_engine(mutated, max_paths=max_paths, max_depth=max_depth)
        if len(states) > 3 and len(corpus) < 500:
            corpus.append(mutated)
        return True, None, len(states)
    except Exception:
        return False, traceback.format_exc(), 0


# ── Target: all detectors ─────────────────────────────────────────

def detectors(max_paths: int = 32, **_kw) -> tuple[bool, str | None]:
    states = [gen.R.choice([gen.random_state, gen.extreme_state])()
              for _ in range(gen.R.randint(1, 5))]
    manifest = gen.rich_manifest() if gen.R.random() > 0.3 else None
    for name, det_cls in ALL_DETECTORS.items():
        try:
            findings = det_cls().detect(states, manifest)
            for f in findings:
                assert isinstance(f.severity, Severity), f"bad severity from {name}"
                assert 0.0 <= f.confidence <= 1.0, f"confidence OOB from {name}: {f.confidence}"
        except Exception:
            return False, f"[det:{name}] {traceback.format_exc()}"
    return True, None


# ── Target: state clone isolation ──────────────────────────────────

def clone_isolation(max_paths: int = 32, **_kw) -> tuple[bool, str | None]:
    state = gen.random_state()
    state.constraints.append({"key": [1, 2, [3, 4]]})
    state.constraints.append([10, 20, [30, 40]])
    try:
        clone = state.clone()
        clone.stack.append(SymbolicValue(concrete=999))
        clone.constraints.append("SENTINEL")
        clone.storage_ops.append(StorageOp(op_type="put", key=SymbolicValue(concrete=b"FUZZ")))
        clone.external_calls.append(ExternalCall(contract_hash=None, method="FUZZ"))
        clone.path.append(999)
        if isinstance(clone.constraints[-2], list) and len(clone.constraints[-2]) > 2:
            inner = clone.constraints[-2][2]
            if isinstance(inner, list):
                inner.append(999)
        if isinstance(clone.constraints[-3], dict):
            k = clone.constraints[-3].get("key")
            if isinstance(k, list):
                k.append(999)
        # Verify original
        assert "SENTINEL" not in state.constraints, "constraint list leak"
        assert 999 not in [v.concrete for v in state.stack], "stack leak"
        assert not any(op.key.concrete == b"FUZZ" for op in state.storage_ops), "storage leak"
        assert not any(c.method == "FUZZ" for c in state.external_calls), "call leak"
        assert 999 not in state.path, "path leak"
        for c in state.constraints:
            if isinstance(c, dict) and "key" in c:
                assert 999 not in c["key"], "deep dict constraint leak"
            if isinstance(c, list):
                for item in c:
                    if isinstance(item, list):
                        assert 999 not in item, "deep list constraint leak"
        return True, None
    except AssertionError as e:
        return False, f"ISOLATION BUG: {e}"
    except Exception:
        return False, traceback.format_exc()


# ── Target: full end-to-end pipeline ───────────────────────────────

def full_pipeline(max_paths: int = 256, max_depth: int = 128,
                  program_size: tuple[int, int] = (50, 500),
                  **_kw) -> tuple[bool, str | None, int]:
    lo, hi = program_size
    script = gen.R.choice([
        lambda: gen.large_program(gen.R.randint(lo, hi)),
        lambda: gen.branch_explosion(gen.R.randint(6, 10)),
        lambda: gen.realistic_contract(),
        lambda: gen.syscall_chain(gen.R.randint(15, min(50, hi))),
    ])()
    try:
        instructions = disassemble(script)
    except ValueError:
        return True, None, 0
    manifest = gen.rich_manifest()
    try:
        states = _run_engine(script, max_paths=max_paths, max_depth=max_depth,
                             manifest=manifest)
        all_findings: list[Finding] = []
        for name, det_cls in ALL_DETECTORS.items():
            all_findings.extend(det_cls().detect(states, manifest))
        rg = ReportGenerator(manifest.name or "FuzzContract")
        report = rg.to_dict(all_findings)
        json.dumps(report)
        rg.to_markdown(all_findings)
        return True, None, len(states)
    except Exception:
        return False, traceback.format_exc(), 0


# ── Target: report generator ──────────────────────────────────────

def report_generator(max_paths: int = 32, **_kw) -> tuple[bool, str | None]:
    findings = [
        Finding(
            detector=gen.R.choice(list(ALL_DETECTORS.keys())),
            title=gen.R.choice(["Finding A", "", "x" * 200]),
            severity=gen.R.choice(list(Severity)),
            description=gen.R.choice(["desc", "", "a" * 500]),
            offset=gen.R.randint(-1, 1000),
            confidence=gen.R.uniform(0.0, 1.0),
            recommendation=gen.R.choice(["fix it", "", None]),
            confidence_reason=gen.R.choice(["reason", None]),
            tags=tuple(gen.R.choice(["tag1", "authorization", ""]) for _ in range(gen.R.randint(0, 3))),
        )
        for _ in range(gen.R.randint(0, 10))
    ]
    rg = ReportGenerator(gen.R.choice(["TestContract", ""]))
    try:
        d = rg.to_dict(findings)
        json.dumps(d)
        rg.to_markdown(findings)
        return True, None
    except Exception:
        return False, traceback.format_exc()
