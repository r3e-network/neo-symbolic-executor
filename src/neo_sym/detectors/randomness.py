"""Predictable randomness detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class RandomnessDetector(BaseDetector):
    name = "randomness"
    description = "Detects use of predictable random sources"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            stack_names = {sv.name for sv in state.stack if sv and sv.name}
            if state.time_accesses and "timestamp" in stack_names:
                findings.append(
                    self.finding(
                        title="Predictable Randomness",
                        severity=Severity.HIGH,
                        offset=state.time_accesses[0],
                        description="Timestamp-derived value appears to influence randomness.",
                        recommendation="Use commit-reveal or verifiable randomness source.",
                        state=state,
                        tags=("randomness", "timestamp"),
                    )
                )
            elif state.randomness_accesses:
                findings.append(
                    self.finding(
                        title="On-chain Randomness Reliance",
                        severity=Severity.MEDIUM,
                        offset=state.randomness_accesses[0],
                        description="Contract uses runtime randomness primitive directly.",
                        recommendation="Harden with anti-manipulation logic and delayed settlement where possible.",
                        state=state,
                        tags=("randomness",),
                    )
                )
        return self.dedupe_findings(findings)
