"""Access-control detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class AccessControlDetector(BaseDetector):
    name = "access_control"
    description = "Detects sensitive operations without explicit authorization checks"
    default_confidence = 0.85

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            sensitive_offsets = [op.offset for op in state.storage_ops if op.op_type == "put"]
            sensitive_offsets.extend(call.offset for call in state.external_calls if call.method)
            if not sensitive_offsets:
                continue
            known_sensitive_offsets = [off for off in sensitive_offsets if off >= 0]
            first_sensitive = min(known_sensitive_offsets) if known_sensitive_offsets else -1

            if not state.witness_checks:
                findings.append(
                    self.finding(
                        title="Missing Access Control",
                        severity=Severity.HIGH,
                        offset=first_sensitive,
                        description="Sensitive operations execute without Runtime.CheckWitness or equivalent guard.",
                        recommendation="Enforce authorization for state-changing and privileged methods.",
                        state=state,
                        tags=("authorization",),
                    )
                )
                continue

            known_enforced_offsets = [off for off in state.witness_checks_enforced if off >= 0]
            if not known_enforced_offsets:
                findings.append(
                    self.finding(
                        title="Unenforced Authorization Check",
                        severity=Severity.HIGH,
                        offset=min(state.witness_checks),
                        description=(
                            "Runtime.CheckWitness is invoked but its result is not used in control flow "
                            "or assertion before sensitive operations."
                        ),
                        recommendation="Require witness result via ASSERT/JMP guard before privileged behavior.",
                        state=state,
                        tags=("authorization", "fail-open"),
                    )
                )
                continue

            first_enforced = min(known_enforced_offsets)
            if first_sensitive >= 0 and first_enforced > first_sensitive:
                findings.append(
                    self.finding(
                        title="Late Authorization Check",
                        severity=Severity.MEDIUM,
                        offset=first_enforced,
                        description="Authorization check occurs after at least one sensitive operation.",
                        recommendation="Run Runtime.CheckWitness before state changes or external calls.",
                        state=state,
                        tags=("authorization", "execution-order"),
                    )
                )

        return self.dedupe_findings(findings)
