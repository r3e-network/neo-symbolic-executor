# Neo N3 Symbolic Executor Hardening Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rebuild the analyzer into a deterministic, test-backed security scanner that covers major Neo N3 smart-contract threat classes.

**Architecture:** The analyzer is split into typed layers: bytecode/manifest parsing (`neo_sym.nef`), symbolic state and execution engine (`neo_sym.engine`), rule detectors (`neo_sym.detectors`), and output/reporting (`neo_sym.report`). Detector inputs are standardized through `ExecutionState` telemetry (storage, calls, auth checks, arithmetic risk, gas, loops), allowing new detectors without engine rewrites.

**Tech Stack:** Python 3.12, pytest, click, rich, lightweight symbolic backend (`src/z3.py` fallback).

### Task 1: Reconstruct Core Analyzer Modules

**Files:**
- Create: `src/neo_sym/nef/opcodes.py`
- Create: `src/neo_sym/nef/parser.py`
- Create: `src/neo_sym/nef/manifest.py`
- Create: `src/neo_sym/engine/state.py`
- Create: `src/neo_sym/engine/symbolic.py`
- Create: `src/neo_sym/engine/__init__.py`
- Create: `src/neo_sym/nef/__init__.py`
- Create: `src/neo_sym/__init__.py`
- Create: `src/z3.py`

### Task 2: Build Detector Framework + Coverage Expansion

**Files:**
- Create: `src/neo_sym/detectors/base.py`
- Create: `src/neo_sym/detectors/reentrancy.py`
- Create: `src/neo_sym/detectors/overflow.py`
- Create: `src/neo_sym/detectors/access_control.py`
- Create: `src/neo_sym/detectors/unchecked_return.py`
- Create: `src/neo_sym/detectors/upgradeability.py`
- Create: `src/neo_sym/detectors/permissions.py`
- Modify: `src/neo_sym/detectors/__init__.py`
- Modify: `src/neo_sym/detectors/admin_centralization.py`
- Modify: `src/neo_sym/detectors/dos.py`
- Modify: `src/neo_sym/detectors/gas_exhaustion.py`
- Modify: `src/neo_sym/detectors/nep17.py`
- Modify: `src/neo_sym/detectors/randomness.py`
- Modify: `src/neo_sym/detectors/storage.py`
- Modify: `src/neo_sym/detectors/timestamp.py`

### Task 3: Harden CLI + Reporting Determinism

**Files:**
- Modify: `src/neo_sym/cli.py`
- Modify: `src/neo_sym/report/generator.py`

### Task 4: Add Regression + Capability Tests

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/test_manifest.py`
- Create: `tests/test_advanced_detectors.py`
- Create: `tests/test_reporting.py`
- Existing tests validated: `tests/test_nef_parser.py`, `tests/test_engine.py`, `tests/test_detectors.py`

### Task 5: Verification Commands

Run:
- `pytest -q`
- `python3 -m compileall -q src tests`
- `PYTHONPATH=src python3 -m neo_sym.cli --help`
- `PYTHONPATH=src python3 examples/sample_audit.py`

Expected:
- All tests pass.
- CLI command works.
- Sample audit runs and emits findings.

## Threat Coverage Implemented

- Reentrancy and checks-effects ordering
- Authorization gaps / late auth checks
- Unchecked external call returns
- Unchecked arithmetic overflow/underflow risk
- DoS via loops or excessive storage writes
- Gas-heavy execution paths
- Storage key collisions
- Timestamp dependence / randomness misuse
- Admin centralization risk
- NEP-17 ABI compliance checks
- Upgradeability path hardening (update/destroy)
- Overbroad manifest permissions

## Phase 2 Hardening (Completed)

- Replaced placeholder NeoVM opcode subset with full opcode + operand metadata from `neo-vm` upstream.
- Implemented full NEF3 envelope parsing:
  - source URL
  - method tokens
  - reserved-byte validation
  - script extraction
  - checksum verification (double SHA256, first 4 bytes little-endian)
- Added official Neo N3 syscall registry (name, syscall ID, fixed price) from upstream `ApplicationEngine` registrations.
- Updated symbolic engine syscall handling to use real syscall IDs and metadata, including `System.Contract.Call` argument extraction and `CALLT` token modeling.

## Phase 3 Hardening (Completed)

- Added exception-frame tracking (`TryFrame`) to execution state with deep-clone isolation.
- Implemented NeoVM TRY-family control-flow semantics in the symbolic engine:
  - `TRY`, `TRY_L`
  - `ENDTRY`, `ENDTRY_L`
  - `ENDFINALLY`
  - `THROW` propagation through catch/finally frames with unhandled throw faulting.
- Added and validated regression tests for:
  - short and long try/catch flow
  - short and long try/finally flow
  - unhandled throw propagation through finally
  - nested inner-finally to outer-catch propagation

## Phase 4 Hardening (Completed)

- Added explicit dynamic external call target analysis for `System.Contract.Call`:
  - dynamic contract hash classification
  - dynamic method selector classification
  - fully dynamic dispatch escalation
- Extended `ExternalCall` telemetry with:
  - `target_hash_dynamic`
  - `method_dynamic`
- Implemented `dynamic_call_target` detector and wired it into CLI detector registry.
- Added engine + detector regression tests for static, partially dynamic, and fully dynamic external call scenarios.

## Phase 5 Hardening (Completed)

- Implemented explicit VM fault semantics for:
  - `ABORT` (immediate non-catchable halt)
  - `ABORTMSG` (immediate non-catchable halt with surfaced message)
- Added engine regression tests proving abort instructions are not handled by `TRY/CATCH`.
- Corrected `System.Runtime.CheckWitness` modeling to return a symbolic boolean result instead of hardcoded `True`.
- Added witness-enforcement telemetry (`witness_checks_enforced`) and propagation through control-flow cloning.
- Updated access-control detector to distinguish:
  - missing authorization checks
  - unenforced/fail-open witness checks
  - late authorization checks
- Added regression tests for witness enforcement tracking and fail-open authorization detection.

## Phase 6 Hardening (Completed)

- Expanded witness-enforcement tracking to comparison-based control-flow guards:
  - `JMPEQ`, `JMPNE`, `JMPGT`, `JMPGE`, `JMPLT`, `JMPLE`
  - long-form variants (`*_L`) via shared comparison branch path
- Added engine regressions for `CheckWitness` consumed through:
  - `JMPEQ` authorization branching
  - `JMPNE` authorization branching
- Added end-to-end detector integration regression proving access-control findings are suppressed for properly enforced `CheckWitness` comparisons before sensitive external calls.

## Phase 7 Hardening (Completed)

- Extended external call return-check tracking beyond `ASSERT`:
  - `JMPIF` / `JMPIFNOT` now mark matching external call results as checked.
  - comparison branches (`JMPEQ`, `JMPNE`, `JMPGT`, `JMPGE`, `JMPLT`, `JMPLE`, including `*_L`) now mark matching external call results as checked.
- Added engine regressions for:
  - `CALLT` return consumed by `JMPIF`
  - `CALLT` return consumed by `JMPEQ`
- Added detector integration regression proving `unchecked_return` does not report when external call results are explicitly used in branch guards.

## Phase 8 Hardening (Completed)

- Added external call flag telemetry to execution state:
  - `call_flags`
  - `call_flags_dynamic`
- Extended syscall modeling to capture call flags from:
  - `System.Contract.Call` stack arguments
  - `CALLT` method-token metadata
- Added `dangerous_call_flags` detector for:
  - dynamic runtime-selected call flags
  - over-privileged `CallFlags.All` usage
- Added regressions for:
  - static/dynamic call-flag extraction in engine execution states
  - detector severity behavior for dynamic, dangerous, and safe call-flag values
  - end-to-end detection from real engine-produced states.

## Phase 9 Hardening (Completed)

- Hardened reentrancy detector severity scoring with amplification signals:
  - multiple external calls before the first storage write
  - dynamic external call targets before state effects
  - dynamic or over-privileged external call flags before state effects
- Preserved existing guard suppression behavior (`reentrancy_guard`) and baseline severity for non-amplified witness-gated paths.
- Added regression tests proving:
  - witness-gated single-call path remains `HIGH`
  - witness-gated amplified paths escalate to `CRITICAL`
  - guarded paths still suppress findings.

## Phase 10 Hardening (Completed)

- Added internal call-depth telemetry:
  - `max_call_stack_depth` in `ExecutionState`
  - clone-safe propagation across branched states
  - runtime tracking on `CALL`, `CALL_L`, and `CALLA`
- Added engine regression verifying nested call-depth tracking for chained subroutine calls.
- Extended reentrancy amplification scoring to include deep internal call-chain risk before state effects.
- Added regression proving witness-gated paths with deep internal call depth escalate from `HIGH` to `CRITICAL`.

## Phase 11 Hardening (Completed)

- Reworked detector-level finding deduplication to preserve worst-case risk across explored states:
  - dedupe key remains `(detector, title, offset)`
  - highest severity now wins when duplicate findings collide
  - confidence is merged conservatively using max()
  - tags are merged to preserve context from all matching findings
- Added regression proving reentrancy duplicates at same offset keep `CRITICAL` when an amplified state exists, instead of silently retaining a weaker `HIGH` finding.

## Phase 12 Hardening (Completed)

- Tightened reentrancy severity gating to rely on effective authorization, not mere witness invocation:
  - severity reduction from `CRITICAL` to `HIGH` now requires `witness_checks_enforced`
  - unenforced/fail-open `CheckWitness` usage no longer downgrades reentrancy risk
- Updated and added reentrancy regressions validating:
  - enforced witness-gated baseline remains `HIGH`
  - unenforced witness paths remain `CRITICAL`
  - existing amplification and guard-suppression behaviors remain intact.

## Phase 13 Hardening (Completed)

- Added explicit recursion/call-chain DoS detection using internal call-depth telemetry:
  - flags potential recursive call exhaustion when `max_call_stack_depth` reaches threshold
- Added regression proving deep internal call chains now emit DoS findings instead of being silently ignored.
- Preserved existing loop-based and storage-write DoS checks.

## Phase 14 Hardening (Completed)

- Added cross-state risk aggregation to reporting outputs:
  - `overall_max_severity`
  - per-detector max severity map
  - deterministic weighted composite score
- Extended JSON report schema with `risk_profile` for machine-readable risk gating in CI.
- Extended Markdown report with a dedicated "Risk Profile" section and detector-level severity table.
- Added report regressions validating:
  - worst-case severity aggregation across findings
  - deterministic weighted scoring
  - markdown rendering of aggregated risk profile.

## Phase 15 Hardening (Completed)

- Added path-aware confidence calibration for detector findings based on symbolic path uncertainty:
  - generalized constraint complexity traversal for nested containers and z3-style expression trees
  - `BaseDetector.path_uncertainty_score(...)` for deterministic uncertainty scoring
  - `BaseDetector.calibrated_confidence(...)` for bounded confidence adjustment
  - `BaseDetector.finding(..., state=...)` now applies calibrated confidence when execution context is provided
- Applied state-aware confidence calibration to high-impact detectors without changing severity logic:
  - `reentrancy`
  - `access_control`
  - `unchecked_return`
  - `dynamic_call_target`
  - `dangerous_call_flags`
- Added regression coverage for confidence downgrades on uncertainty-heavy paths while preserving severity:
  - reentrancy confidence calibration
  - access-control confidence calibration
  - unchecked-return confidence calibration
- Verification evidence:
  - `pytest -q` (86 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Phase 16 Hardening (Completed)

- Expanded path-aware confidence calibration to remaining state-driven detectors for consistent uncertainty handling:
  - `overflow`
  - `dos`
  - `upgradeability`
  - `timestamp`
  - `randomness`
  - `gas_exhaustion`
  - `storage_collision` (calibrated using source state of collision candidate key)
- Added regression coverage proving confidence downgrades on uncertainty-heavy symbolic paths while preserving severity for:
  - overflow findings
  - recursive-call DoS findings
  - insecure upgradeability findings
- Preserved existing detector severity and title semantics; only confidence scoring behavior changed.
- Verification evidence:
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py` (37 passed)

## Phase 17 Hardening (Completed)

- Added explicit confidence-calibration regressions for remaining state-driven detectors:
  - `timestamp`
  - `randomness`
  - `gas_exhaustion`
  - `storage_collision`
- Fixed `storage_collision` confidence semantics for cross-state key collisions:
  - confidence now conservatively reflects both colliding states (minimum calibrated confidence across pair).
  - avoids optimistic confidence when one side of a collision comes from a highly uncertain symbolic path.
- Preserved existing storage-collision severity and matching logic; only confidence computation changed.
- Verification evidence:
  - `pytest -q tests/test_advanced_detectors.py -k "timestamp_confidence_downgraded or randomness_confidence_downgraded or gas_exhaustion_confidence_downgraded or storage_collision_confidence_downgraded"` (4 passed)
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py` (41 passed)
  - `pytest -q` (93 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Phase 18 Hardening (Completed)

- Extended report risk aggregation with confidence-aware metrics for CI/risk gating:
  - `confidence_weighted_score`: severity-weighted risk score scaled by finding confidence.
  - `detector_average_confidence`: per-detector mean confidence map for triage prioritization.
- Updated markdown report rendering to surface confidence-weighted risk directly in the "Risk Profile" section.
- Added report regressions validating:
  - deterministic confidence-weighted scoring behavior
  - deterministic per-detector confidence aggregation
  - markdown output includes confidence-weighted risk metric.
- Verification evidence:
  - `pytest -q tests/test_reporting.py` (3 passed)
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py` (41 passed)
  - `pytest -q` (93 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Phase 19 Hardening (Completed)

- Added per-finding confidence explainability in detector outputs:
  - `Finding` now carries `confidence_reason`.
  - `BaseDetector.finding(...)` now auto-populates deterministic rationale text, including path uncertainty context for state-driven findings.
- Improved confidence deduplication semantics:
  - dedupe now preserves the rationale that corresponds to the retained merged confidence.
- Extended report outputs for explainability:
  - JSON includes `confidence_reason` for every finding.
  - Markdown includes `Confidence` and `Confidence Rationale` lines per finding.
- Added regressions validating:
  - detector-generated path-uncertainty confidence rationale content
  - report serialization of confidence rationale
  - markdown rendering of confidence rationale.
- Verification evidence:
  - `pytest -q tests/test_detectors.py tests/test_reporting.py -k "confidence_rationale"` (2 passed)
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py` (43 passed)
  - `pytest -q` (95 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Phase 20 Hardening (Completed)

- Added confidence-aware CI gating controls to CLI analysis:
  - `--fail-on-weighted-score <int>`
  - `--fail-on-confidence-weighted-score <int>`
  - `--min-confidence <severity>=<0..1>` (repeatable per severity floor)
- Added deterministic gate evaluation and non-zero CI exit behavior:
  - gate failures now emit explicit diagnostics and exit with code `3`.
  - report generation still occurs before gate evaluation to preserve audit artifacts.
- Added CLI regressions validating:
  - confidence-weighted score gate failure behavior
  - minimum confidence floor violation behavior
  - passing behavior when configured gates are not triggered.
- Verification evidence:
  - `pytest -q tests/test_cli.py` (4 passed)
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py tests/test_cli.py` (47 passed)
  - `pytest -q` (98 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Phase 21 Hardening (Completed)

- Expanded CI gate policy controls for severity governance:
  - `--fail-on-max-severity <severity>` for global severity threshold enforcement.
  - `--fail-on-detector-severity <detector>=<severity>` (repeatable) for detector-specific severity policies.
- Added deterministic policy parsing/validation:
  - strict detector-name validation against registered detectors.
  - strict severity validation against known severity levels.
- Extended gate evaluator to produce explicit policy breach diagnostics while preserving existing score/confidence gates.
- Added CLI regressions validating:
  - max severity gate failure behavior
  - per-detector severity gate failure behavior
  - per-detector severity non-trigger pass behavior
  - invalid per-detector severity policy validation behavior.
- Verification evidence:
  - `pytest -q tests/test_cli.py` (8 passed)
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py tests/test_cli.py` (51 passed)
  - `pytest -q` (102 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Phase 22 Hardening (Completed)

- Added first-class gate evaluation artifacts to analysis reports for CI traceability:
  - JSON now includes `gate_evaluation` with:
    - `passed` boolean
    - `violations` list
    - `policies` map (active gate configuration snapshot)
  - Markdown now includes a dedicated `## Gate Evaluation` section with active policies and violations.
- Preserved deterministic CI behavior:
  - report artifacts are written before gate exit enforcement.
  - gate failures still exit with code `3`.
- Added CLI regressions validating:
  - JSON report captures failed gate evaluation details.
  - JSON report captures passing gate evaluation details.
  - Markdown report includes gate evaluation diagnostics on failure.
- Verification evidence:
  - `pytest -q tests/test_cli.py` (11 passed)
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py tests/test_cli.py` (54 passed)
  - `pytest -q` (105 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Phase 23 Hardening (Completed)

- Added count-based CI gate policies for stricter release blocking:
  - `--fail-on-total-findings <count>` (global total finding threshold)
  - `--fail-on-severity-count <severity>=<count>` (repeatable per-severity finding count thresholds)
- Added strict policy parsing/validation for severity count gates:
  - rejects unknown severities and invalid/non-positive thresholds with CLI parameter errors.
- Extended gate evaluation and artifacting:
  - new count-based policies are enforced in gate violation logic.
  - `gate_evaluation.policies` now captures total/severity-count threshold config.
  - markdown `Gate Evaluation` section now includes count-policy configuration when active.
- Added CLI regressions validating:
  - total-findings gate failure
  - severity-count gate failure
  - severity-count non-trigger pass
  - invalid severity-count policy validation.
- Verification evidence:
  - `pytest -q tests/test_cli.py` (15 passed)
  - `pytest -q tests/test_detectors.py tests/test_advanced_detectors.py tests/test_reporting.py tests/test_cli.py` (58 passed)
  - `pytest -q` (109 passed)
  - `python3 -m compileall -q src tests`
  - `PYTHONPATH=src python3 -m neo_sym.cli --help`
  - `PYTHONPATH=src python3 examples/sample_audit.py`

## Production Limits (Explicit)

- No static analyzer can guarantee detection of *all* vulnerabilities.
- Current engine models a security-relevant subset of NeoVM opcodes and syscall IDs.
- High assurance requires adding full NEF envelope decoding, full syscall map, and constraint solving via real `z3-solver` in CI.
