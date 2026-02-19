"""Tests for advanced detector behaviors."""
from __future__ import annotations

import z3

from neo_sym.detectors import ALL_DETECTORS
from neo_sym.detectors.base import Severity
from neo_sym.engine.state import ArithmeticOp, ExecutionState, ExternalCall, StorageOp, SymbolicValue
from neo_sym.nef.manifest import ContractMethod, Manifest


def _apply_high_uncertainty_constraints(state: ExecutionState, prefix: str) -> None:
    state.constraints = [
        ("eq", f"{prefix}_a", ("add", 1, 2)),
        ("branch", ("gt", f"{prefix}_b", 0), ("mul", ("add", 1, 2), ("sub", 5, 3))),
        {"phi": [f"{prefix}_c", {"left": ("mix", 1, 2, 3), "right": ("mix", 4, 5, 6)}]},
        ["path", ["a", ["b", ["c", ["d", prefix]]]]],
    ]


def test_overflow_detector_flags_unchecked_math():
    state = ExecutionState()
    state.arithmetic_ops.append(
        ArithmeticOp(
            opcode="ADD",
            offset=14,
            left=SymbolicValue(expr=z3.BitVecVal(1, 256)),
            right=SymbolicValue(expr=z3.BitVecVal(2, 256)),
            overflow_possible=True,
            checked=False,
        )
    )
    findings = ALL_DETECTORS["overflow"]().detect([state])
    assert any(f.severity == Severity.HIGH for f in findings)


def test_overflow_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.arithmetic_ops.append(
        ArithmeticOp(
            opcode="ADD",
            offset=14,
            left=SymbolicValue(expr=z3.BitVecVal(1, 256)),
            right=SymbolicValue(expr=z3.BitVecVal(2, 256)),
            overflow_possible=True,
            checked=False,
        )
    )

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "overflow")

    detector = ALL_DETECTORS["overflow"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.HIGH
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_reentrancy_not_reported_when_guarded():
    state = ExecutionState()
    state.witness_checks = [3]
    state.reentrancy_guard = True
    state.external_calls.append(ExternalCall(contract_hash=b"\x01" * 20, method="transfer", offset=8))
    state.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))
    findings = ALL_DETECTORS["reentrancy"]().detect([state])
    assert not findings


def test_reentrancy_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.external_calls.append(ExternalCall(contract_hash=b"\x01" * 20, method="transfer", offset=8))
    baseline.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "reentrant")

    detector = ALL_DETECTORS["reentrancy"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.CRITICAL
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_reentrancy_witness_gated_single_call_is_high():
    state = ExecutionState()
    state.witness_checks = [3]
    state.witness_checks_enforced = [3]
    state.external_calls.append(ExternalCall(contract_hash=b"\x01" * 20, method="transfer", offset=8))
    state.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))
    findings = ALL_DETECTORS["reentrancy"]().detect([state])

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_reentrancy_escalates_with_multiple_pre_write_calls():
    state = ExecutionState()
    state.witness_checks = [3]
    state.external_calls.extend(
        [
            ExternalCall(contract_hash=b"\x02" * 20, method="transfer", offset=8),
            ExternalCall(contract_hash=b"\x03" * 20, method="balanceOf", offset=10),
        ]
    )
    state.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=14))
    findings = ALL_DETECTORS["reentrancy"]().detect([state])

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_reentrancy_escalates_with_dynamic_call_target_before_write():
    state = ExecutionState()
    state.witness_checks = [3]
    state.external_calls.append(
        ExternalCall(
            contract_hash=None,
            method="Contract.Call:update",
            offset=8,
            target_hash_dynamic=True,
            method_dynamic=False,
        )
    )
    state.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))
    findings = ALL_DETECTORS["reentrancy"]().detect([state])

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_reentrancy_escalates_with_deep_internal_call_chain_before_write():
    state = ExecutionState()
    state.witness_checks = [3]
    state.max_call_stack_depth = 2
    state.external_calls.append(
        ExternalCall(
            contract_hash=b"\x06" * 20,
            method="transfer",
            offset=8,
        )
    )
    state.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))
    findings = ALL_DETECTORS["reentrancy"]().detect([state])

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_reentrancy_unenforced_witness_check_stays_critical():
    state = ExecutionState()
    state.witness_checks = [3]
    state.external_calls.append(ExternalCall(contract_hash=b"\x09" * 20, method="transfer", offset=8))
    state.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))
    findings = ALL_DETECTORS["reentrancy"]().detect([state])

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_reentrancy_dedupe_keeps_worst_severity_for_same_offset():
    baseline = ExecutionState()
    baseline.witness_checks = [3]
    baseline.external_calls.append(ExternalCall(contract_hash=b"\x07" * 20, method="transfer", offset=8))
    baseline.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))

    amplified = ExecutionState()
    amplified.witness_checks = [3]
    amplified.external_calls.append(
        ExternalCall(
            contract_hash=None,
            method="Contract.Call:transfer",
            offset=8,
            target_hash_dynamic=True,
        )
    )
    amplified.storage_ops.append(StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"x"), offset=12))

    findings = ALL_DETECTORS["reentrancy"]().detect([baseline, amplified])

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_dos_detector_flags_deep_internal_call_chain():
    state = ExecutionState()
    state.max_call_stack_depth = 8
    findings = ALL_DETECTORS["dos"]().detect([state])

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Recursive" in findings[0].title


def test_dos_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.max_call_stack_depth = 8

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "dos")

    detector = ALL_DETECTORS["dos"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.MEDIUM
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_upgradeability_detects_update_without_auth():
    manifest = Manifest(name="Upgradeable")
    manifest.abi_methods = [ContractMethod(name="update", offset=100)]
    state = ExecutionState(entry_offset=100)
    state.external_calls.append(ExternalCall(contract_hash=b"\x00" * 20, method="ContractManagement.Update", offset=102))
    findings = ALL_DETECTORS["upgradeability"]().detect([state], manifest)
    assert len(findings) == 1


def test_upgradeability_confidence_downgraded_for_symbolic_path_uncertainty():
    manifest = Manifest(name="Upgradeable")
    manifest.abi_methods = [ContractMethod(name="update", offset=100)]

    baseline = ExecutionState(entry_offset=100)
    baseline.external_calls.append(
        ExternalCall(contract_hash=b"\x00" * 20, method="ContractManagement.Update", offset=102)
    )

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "upgrade")

    detector = ALL_DETECTORS["upgradeability"]()
    baseline_finding = detector.detect([baseline], manifest)[0]
    uncertain_finding = detector.detect([uncertain], manifest)[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.CRITICAL
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_timestamp_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.time_accesses = [12]

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "timestamp")

    detector = ALL_DETECTORS["timestamp"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.LOW
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_randomness_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.randomness_accesses = [21]

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "randomness")

    detector = ALL_DETECTORS["randomness"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.MEDIUM
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_gas_exhaustion_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.gas_cost = 75_000

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "gas")

    detector = ALL_DETECTORS["gas_exhaustion"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.MEDIUM
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_storage_collision_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.storage_ops.append(StorageOp("put", SymbolicValue(concrete=b"vault"), offset=30))

    uncertain = ExecutionState()
    uncertain.storage_ops.append(StorageOp("put", SymbolicValue(concrete=b"vault:user"), offset=42))
    _apply_high_uncertainty_constraints(uncertain, "storage")

    detector = ALL_DETECTORS["storage_collision"]()
    baseline_finding = detector.detect([baseline, ExecutionState(storage_ops=[StorageOp("put", SymbolicValue(concrete=b"vault:user"), offset=42)])])[0]
    uncertain_finding = detector.detect([baseline, uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.MEDIUM
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_dynamic_call_target_detector_flags_dynamic_contract_hash():
    state = ExecutionState()
    state.external_calls.append(
        ExternalCall(
            contract_hash=None,
            method="Contract.Call:update",
            offset=42,
            target_hash_dynamic=True,
            method_dynamic=False,
        )
    )
    findings = ALL_DETECTORS["dynamic_call_target"]().detect([state])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_dynamic_call_target_detector_flags_hash_and_method_fully_dynamic():
    state = ExecutionState()
    state.external_calls.append(
        ExternalCall(
            contract_hash=None,
            method="Contract.Call:method_arg",
            offset=55,
            target_hash_dynamic=True,
            method_dynamic=True,
        )
    )
    findings = ALL_DETECTORS["dynamic_call_target"]().detect([state])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_dynamic_call_target_detector_flags_dynamic_method_only():
    state = ExecutionState()
    state.external_calls.append(
        ExternalCall(
            contract_hash=b"\x01" * 20,
            method="Contract.Call:selector_arg",
            offset=61,
            target_hash_dynamic=False,
            method_dynamic=True,
        )
    )
    findings = ALL_DETECTORS["dynamic_call_target"]().detect([state])
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_dynamic_call_target_detector_ignores_static_call_target():
    state = ExecutionState()
    state.external_calls.append(
        ExternalCall(
            contract_hash=b"\x02" * 20,
            method="Contract.Call:update",
            offset=72,
            target_hash_dynamic=False,
            method_dynamic=False,
        )
    )
    findings = ALL_DETECTORS["dynamic_call_target"]().detect([state])
    assert not findings


def test_dangerous_call_flags_detector_flags_all_flags():
    state = ExecutionState()
    state.external_calls.append(
        ExternalCall(
            contract_hash=b"\x03" * 20,
            method="Contract.Call:update",
            offset=80,
            call_flags=0x0F,
            call_flags_dynamic=False,
        )
    )
    findings = ALL_DETECTORS["dangerous_call_flags"]().detect([state])
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_dangerous_call_flags_detector_flags_dynamic_flags():
    state = ExecutionState()
    state.external_calls.append(
        ExternalCall(
            contract_hash=b"\x04" * 20,
            method="Contract.Call:transfer",
            offset=81,
            call_flags=None,
            call_flags_dynamic=True,
        )
    )
    findings = ALL_DETECTORS["dangerous_call_flags"]().detect([state])
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_dangerous_call_flags_detector_ignores_restricted_flags():
    state = ExecutionState()
    state.external_calls.append(
        ExternalCall(
            contract_hash=b"\x05" * 20,
            method="Contract.Call:transfer",
            offset=82,
            call_flags=0x01,
            call_flags_dynamic=False,
        )
    )
    findings = ALL_DETECTORS["dangerous_call_flags"]().detect([state])
    assert not findings
