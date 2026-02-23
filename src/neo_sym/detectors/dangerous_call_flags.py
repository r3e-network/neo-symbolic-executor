"""Dangerous external call flags detector."""
from __future__ import annotations

__all__ = ["DangerousCallFlagsDetector"]

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from ..nef.parser import CALL_FLAGS_ALL
from .base import BaseDetector, Finding, Severity


class DangerousCallFlagsDetector(BaseDetector):
    name = "dangerous_call_flags"
    description = "Detects dynamic or over-privileged external call flags"
    default_confidence = 0.85

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            for call in state.external_calls:
                if call.call_flags_dynamic:
                    findings.append(
                        self.finding(
                            title="Dynamic External Call Flags",
                            severity=Severity.MEDIUM,
                            offset=call.offset,
                            description=(
                                "External call flags are determined dynamically at runtime, increasing dispatch risk."
                            ),
                            recommendation=(
                                "Use fixed call flags and validate allowed capabilities before external invocations."
                            ),
                            state=state,
                            tags=("external-call", "call-flags"),
                        )
                    )
                    continue

                if isinstance(call.call_flags, int) and (call.call_flags & CALL_FLAGS_ALL) == CALL_FLAGS_ALL:
                    findings.append(
                        self.finding(
                            title="Over-Privileged External Call Flags",
                            severity=Severity.HIGH,
                            offset=call.offset,
                            description="External call uses CallFlags.All (0x0F), enabling full callee capabilities.",
                            recommendation=(
                                "Reduce call flags to the minimum required permissions (least privilege)."
                            ),
                            state=state,
                            tags=("external-call", "least-privilege", "call-flags"),
                        )
                    )

        return self.dedupe_findings(findings)
