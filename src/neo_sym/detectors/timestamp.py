"""Timestamp dependence detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class TimestampDetector(BaseDetector):
    name = "timestamp"
    description = "Detects unsafe timestamp usage"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            if not state.time_accesses:
                continue
            findings.append(
                self.finding(
                    title="Timestamp Dependence",
                    severity=Severity.LOW,
                    offset=state.time_accesses[0],
                    description=f"Runtime.GetTime observed at {len(state.time_accesses)} location(s).",
                    recommendation="Do not rely on timestamp for critical authorization or randomness logic.",
                    state=state,
                    tags=("timestamp",),
                )
            )
        return self.dedupe_findings(findings)
