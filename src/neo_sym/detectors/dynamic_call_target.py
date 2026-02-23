"""Dynamic external call target detector."""
from __future__ import annotations

__all__ = ["DynamicCallTargetDetector"]

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class DynamicCallTargetDetector(BaseDetector):
    name = "dynamic_call_target"
    description = "Detects unconstrained System.Contract.Call targets"
    default_confidence = 0.9

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            for call in state.external_calls:
                if not call.method.startswith("Contract.Call:"):
                    continue
                if not call.target_hash_dynamic and not call.method_dynamic:
                    continue

                if call.target_hash_dynamic and call.method_dynamic:
                    findings.append(
                        self.finding(
                            title="Fully Dynamic External Call Target",
                            severity=Severity.CRITICAL,
                            offset=call.offset,
                            description=(
                                "System.Contract.Call uses both dynamic contract hash and dynamic method name."
                            ),
                            recommendation=(
                                "Restrict call targets to a vetted allowlist and validate method selectors "
                                "before dispatch."
                            ),
                            state=state,
                            tags=("external-call", "dynamic-dispatch", "call-injection"),
                        )
                    )
                    continue

                if call.target_hash_dynamic:
                    findings.append(
                        self.finding(
                            title="Dynamic External Contract Target",
                            severity=Severity.HIGH,
                            offset=call.offset,
                            description=(
                                "System.Contract.Call receives a non-concrete contract hash at runtime."
                            ),
                            recommendation=(
                                "Validate contract hashes against explicit allowlists before performing external calls."
                            ),
                            state=state,
                            tags=("external-call", "dynamic-dispatch"),
                        )
                    )
                    continue

                findings.append(
                    self.finding(
                        title="Dynamic External Method Target",
                        severity=Severity.MEDIUM,
                        offset=call.offset,
                        description="System.Contract.Call selects method name dynamically at runtime.",
                        recommendation=(
                            "Restrict invoked methods to a small approved set and reject unknown selectors."
                        ),
                        state=state,
                        tags=("external-call", "dynamic-dispatch"),
                    )
                )

        return self.dedupe_findings(findings)
