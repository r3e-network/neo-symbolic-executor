"""Admin centralization detector."""
from __future__ import annotations

__all__ = ["AdminCentralizationDetector"]

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class AdminCentralizationDetector(BaseDetector):
    name = "admin_centralization"
    description = "Detects single-admin risks and missing timelock"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            enforced = state.witness_checks_enforced
            if len(enforced) != 1:
                continue
            has_privileged_actions = any(op.op_type == "put" for op in state.storage_ops) or state.external_calls
            if not has_privileged_actions:
                continue
            findings.append(
                self.finding(
                    title="Single Admin Control",
                    severity=Severity.MEDIUM,
                    offset=enforced[0],
                    description="Critical operations are gated by a single enforced witness check.",
                    recommendation="Use multisig governance and optional timelock for sensitive methods.",
                    state=state,
                    tags=("governance", "centralization"),
                )
            )
        return self.dedupe_findings(findings)
