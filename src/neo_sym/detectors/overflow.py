"""Arithmetic overflow/underflow detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class OverflowDetector(BaseDetector):
    name = "overflow"
    description = "Detects unchecked arithmetic with overflow/underflow risk"
    default_confidence = 0.8

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            for op in state.arithmetic_ops:
                if not op.overflow_possible or op.checked:
                    continue
                findings.append(
                    self.finding(
                        title="Unchecked Arithmetic Operation",
                        severity=Severity.HIGH,
                        offset=op.offset,
                        description=f"Operation {op.opcode} may overflow or underflow without runtime guard.",
                        recommendation="Validate arithmetic bounds or assert invariants before state updates.",
                        state=state,
                        tags=("SWC-101", "integer-overflow"),
                    )
                )
        return self.dedupe_findings(findings)
