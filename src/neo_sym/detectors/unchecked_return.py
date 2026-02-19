"""Unchecked external call return detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class UncheckedReturnDetector(BaseDetector):
    name = "unchecked_return"
    description = "Detects ignored external call results"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            for call in state.external_calls:
                if call.return_checked:
                    continue
                findings.append(
                    self.finding(
                        title="Unchecked External Call Return Value",
                        severity=Severity.MEDIUM,
                        offset=call.offset,
                        description=f"Result of external call '{call.method}' is not validated before continuing.",
                        recommendation="Check return values and revert/abort on failure.",
                        state=state,
                        tags=("external-call", "error-handling"),
                    )
                )
        return self.dedupe_findings(findings)
