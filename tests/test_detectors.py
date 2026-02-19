"""Tests for security detectors."""
import struct

from neo_sym.engine.state import ExecutionState, SymbolicValue, StorageOp, ExternalCall
from neo_sym.engine.symbolic import SymbolicEngine
from neo_sym.detectors import ALL_DETECTORS
from neo_sym.detectors.base import Severity
from neo_sym.nef.parser import MethodToken, NefFile, disassemble
from neo_sym.nef.opcodes import OpCode
from neo_sym.nef.syscalls import SYSCALLS_BY_NAME
from neo_sym.nef.manifest import Manifest, ContractMethod, ContractEvent
import z3


def _apply_high_uncertainty_constraints(state: ExecutionState, prefix: str) -> None:
    state.constraints = [
        ("eq", f"{prefix}_a", ("add", 1, 2)),
        ("branch", ("gt", f"{prefix}_b", 0), ("mul", ("add", 1, 2), ("sub", 5, 3))),
        {"phi": [f"{prefix}_c", {"left": ("mix", 1, 2, 3), "right": ("mix", 4, 5, 6)}]},
        ["path", ["a", ["b", ["c", ["d", prefix]]]]],
    ]


def _state_with_call_then_write() -> ExecutionState:
    s = ExecutionState()
    s.external_calls = [ExternalCall(contract_hash=b"\x00" * 20, method="transfer", offset=10)]
    s.storage_ops = [StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256), concrete=b"key"), offset=20)]
    return s


def test_reentrancy():
    det = ALL_DETECTORS["reentrancy"]()
    findings = det.detect([_state_with_call_then_write()])
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_access_control_missing():
    s = ExecutionState()
    s.storage_ops = [StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256)), offset=5)]
    det = ALL_DETECTORS["access_control"]()
    findings = det.detect([s])
    assert any("Access Control" in f.title for f in findings)


def test_access_control_present():
    s = ExecutionState()
    s.storage_ops = [StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256)), offset=5)]
    s.witness_checks = [2]
    s.witness_checks_enforced = [2]
    det = ALL_DETECTORS["access_control"]()
    findings = det.detect([s])
    assert not findings


def test_access_control_unenforced_witness_check():
    s = ExecutionState()
    s.storage_ops = [StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256)), offset=5)]
    s.witness_checks = [2]
    det = ALL_DETECTORS["access_control"]()
    findings = det.detect([s])
    assert any("Unenforced Authorization" in f.title for f in findings)


def test_access_control_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.storage_ops = [StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256)), offset=5)]

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "auth")

    detector = ALL_DETECTORS["access_control"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.HIGH
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_access_control_confidence_rationale_includes_path_uncertainty_context():
    state = ExecutionState()
    state.storage_ops = [StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256)), offset=5)]
    _apply_high_uncertainty_constraints(state, "auth_reason")

    finding = ALL_DETECTORS["access_control"]().detect([state])[0]

    assert finding.confidence_reason is not None
    assert "path uncertainty" in finding.confidence_reason.lower()
    assert "constraints" in finding.confidence_reason.lower()


def test_access_control_handles_unknown_offsets():
    s = ExecutionState()
    s.storage_ops = [StorageOp("put", SymbolicValue(expr=z3.BitVecVal(1, 256)), offset=-1)]
    det = ALL_DETECTORS["access_control"]()
    findings = det.detect([s])
    assert len(findings) == 1
    assert findings[0].offset == -1


def test_unchecked_return():
    s = ExecutionState()
    s.external_calls = [ExternalCall(b"\x00" * 20, "test", offset=10, return_checked=False)]
    det = ALL_DETECTORS["unchecked_return"]()
    findings = det.detect([s])
    assert len(findings) == 1


def test_unchecked_return_confidence_downgraded_for_symbolic_path_uncertainty():
    baseline = ExecutionState()
    baseline.external_calls = [ExternalCall(b"\x00" * 20, "transfer", offset=10, return_checked=False)]

    uncertain = baseline.clone()
    _apply_high_uncertainty_constraints(uncertain, "unchecked")

    detector = ALL_DETECTORS["unchecked_return"]()
    baseline_finding = detector.detect([baseline])[0]
    uncertain_finding = detector.detect([uncertain])[0]

    assert baseline_finding.severity == uncertain_finding.severity == Severity.MEDIUM
    assert uncertain_finding.confidence < baseline_finding.confidence


def test_nep17_missing_methods():
    m = Manifest(name="test", supported_standards=["NEP-17"])
    m.abi_methods = [ContractMethod("symbol", 0), ContractMethod("decimals", 4)]
    m.abi_events = [ContractEvent("Transfer")]
    det = ALL_DETECTORS["nep17"]()
    findings = det.detect([], m)
    assert any("Missing NEP-17" in f.title for f in findings)


def test_timestamp():
    s = ExecutionState()
    s.time_accesses = [10]
    det = ALL_DETECTORS["timestamp"]()
    findings = det.detect([s])
    assert len(findings) == 1


def test_access_control_enforced_by_comparison_branch_from_engine():
    syscall_id = SYSCALLS_BY_NAME["System.Runtime.CheckWitness"].syscall_id
    script = bytes([OpCode.PUSH0, OpCode.SYSCALL]) + struct.pack("<I", syscall_id) + bytes(
        [
            OpCode.PUSHT,
            OpCode.JMPEQ,
            0x06,  # branch to PUSH0/RET path
            OpCode.CALLT,
            0x00,
            0x00,
            OpCode.RET,
            OpCode.PUSH0,
            OpCode.RET,
        ]
    )
    nef = NefFile(
        script=script,
        instructions=disassemble(script),
        tokens=[
            MethodToken(
                hash=b"\x22" * 20,
                method="transfer",
                parameters_count=0,
                has_return_value=True,
                call_flags=0x0F,
            )
        ],
    )
    states = SymbolicEngine(nef).run()
    findings = ALL_DETECTORS["access_control"]().detect(states)

    assert not findings


def test_unchecked_return_not_reported_when_result_controls_branch():
    script = bytes(
        [
            OpCode.CALLT,
            0x00,
            0x00,
            OpCode.JMPIF,
            0x04,
            OpCode.PUSH0,
            OpCode.RET,
            OpCode.PUSH1,
            OpCode.RET,
        ]
    )
    nef = NefFile(
        script=script,
        instructions=disassemble(script),
        tokens=[
            MethodToken(
                hash=b"\x55" * 20,
                method="transfer",
                parameters_count=0,
                has_return_value=True,
                call_flags=0x0F,
            )
        ],
    )
    states = SymbolicEngine(nef).run()
    findings = ALL_DETECTORS["unchecked_return"]().detect(states)

    assert not findings


def test_dangerous_call_flags_detected_from_engine_states():
    syscall_id = SYSCALLS_BY_NAME["System.Contract.Call"].syscall_id
    method = b"transfer"
    contract_hash = bytes(range(20))
    script = b"".join(
        [
            bytes([OpCode.PUSH0]),  # args
            bytes([OpCode.PUSHINT8, 0x0F]),  # CallFlags.All
            bytes([OpCode.PUSHDATA1, len(method)]),
            method,
            bytes([OpCode.PUSHDATA1, len(contract_hash)]),
            contract_hash,
            bytes([OpCode.SYSCALL]),
            struct.pack("<I", syscall_id),
            bytes([OpCode.RET]),
        ]
    )
    states = SymbolicEngine(NefFile(script=script, instructions=disassemble(script))).run()
    findings = ALL_DETECTORS["dangerous_call_flags"]().detect(states)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
