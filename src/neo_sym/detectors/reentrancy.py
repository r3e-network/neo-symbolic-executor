"""Reentrancy detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class ReentrancyDetector(BaseDetector):
    name = "reentrancy"
    description = "Detects external-call-before-state-update patterns"
    default_confidence = 0.9

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            if not state.external_calls:
                continue

            first_call = min(state.external_calls, key=lambda c: c.offset if c.offset >= 0 else 10**9)
            if first_call.offset < 0:
                continue
            writes_after_call = [
                op
                for op in state.storage_ops
                if op.op_type == "put" and op.offset >= 0 and op.offset > first_call.offset
            ]
            if not writes_after_call:
                continue
            if state.reentrancy_guard:
                continue

            first_write_offset = min(op.offset for op in writes_after_call)
            pre_write_calls = [
                call
                for call in state.external_calls
                if call.offset >= 0 and call.offset < first_write_offset
            ]
            if not pre_write_calls:
                pre_write_calls = list(state.external_calls)

            amplification_signals: list[str] = []
            if len(pre_write_calls) > 1:
                amplification_signals.append("multiple external calls occur before the first state write")
            if any(call.target_hash_dynamic or call.method_dynamic for call in pre_write_calls):
                amplification_signals.append("external call targets are dynamically selected at runtime")
            if any(
                call.call_flags_dynamic
                or (isinstance(call.call_flags, int) and (call.call_flags & CALL_FLAGS_ALL) == CALL_FLAGS_ALL)
                for call in pre_write_calls
            ):
                amplification_signals.append("external calls use dynamic or over-privileged call flags")
            if state.max_call_stack_depth >= 2:
                amplification_signals.append("execution reaches deep internal call-chain depth before state effects")

            has_effective_auth = bool(state.witness_checks_enforced)
            severity = Severity.CRITICAL if not has_effective_auth else Severity.HIGH
            if severity == Severity.HIGH and amplification_signals:
                severity = Severity.CRITICAL

            amplification_suffix = ""
            if amplification_signals:
                amplification_suffix = " Risk amplifiers detected: " + "; ".join(amplification_signals) + "."

            findings.append(
                self.finding(
                    title="Potential Reentrancy",
                    severity=severity,
                    offset=first_call.offset,
                    description=(
                        "External call executes before storage write. If the callee re-enters, "
                        "contract state may be manipulated before completion."
                        f"{amplification_suffix}"
                    ),
                    recommendation=(
                        "Apply checks-effects-interactions ordering and explicit reentrancy lock "
                        "for methods performing external calls."
                    ),
                    state=state,
                    tags=("SWC-107", "reentrancy", "amplified-risk" if amplification_signals else "baseline-risk"),
                )
            )
        return self.dedupe_findings(findings)
