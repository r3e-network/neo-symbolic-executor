"""GAS exhaustion detector."""
from __future__ import annotations

__all__ = ["GasExhaustionDetector"]

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class GasExhaustionDetector(BaseDetector):
    name = "gas_exhaustion"
    description = "Detects high-gas execution paths"
    _GAS_THRESHOLD = 50_000

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            if state.gas_cost <= self._GAS_THRESHOLD:
                continue
            findings.append(
                self.finding(
                    title="High GAS Consumption Path",
                    severity=Severity.MEDIUM,
                    description=f"Execution path consumes approximately {state.gas_cost} gas units.",
                    recommendation="Reduce expensive syscalls/loops and split heavy workflows.",
                    state=state,
                    tags=("gas", "dos"),
                )
            )
        return self.dedupe_findings(findings)
