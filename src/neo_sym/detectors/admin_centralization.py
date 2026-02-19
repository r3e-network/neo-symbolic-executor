"""Admin centralization detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class AdminCentralizationDetector(BaseDetector):
    name = "admin_centralization"
    description = "Detects single-admin risks and missing timelock"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            if len(state.witness_checks) != 1:
                continue
            has_privileged_actions = any(op.op_type == "put" for op in state.storage_ops) or bool(state.external_calls)
            if not has_privileged_actions:
                continue
            findings.append(
                self.finding(
                    title="Single Admin Control",
                    severity=Severity.MEDIUM,
                    offset=state.witness_checks[0],
                    description="Critical operations are gated by a single witness check.",
                    recommendation="Use multisig governance and optional timelock for sensitive methods.",
                    tags=("governance", "centralization"),
                )
            )
        return self.dedupe_findings(findings)
