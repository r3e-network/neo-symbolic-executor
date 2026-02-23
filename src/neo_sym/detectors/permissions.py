"""Manifest permission detector."""
from __future__ import annotations

__all__ = ["ManifestPermissionDetector"]

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class ManifestPermissionDetector(BaseDetector):
    name = "manifest_permissions"
    description = "Detects wildcard manifest permissions"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        if manifest is None:
            return []
        findings: list[Finding] = []
        for perm in manifest.permissions:
            if perm.contract == "*" and "*" in perm.methods:
                findings.append(
                    self.finding(
                        title="Overly Broad Manifest Permissions",
                        severity=Severity.MEDIUM,
                        description=(
                            "Manifest allows unrestricted contract/method calls, expanding the callable trust surface."
                        ),
                        recommendation="Restrict manifest permissions to explicit contract hashes and method names.",
                        tags=("manifest", "least-privilege"),
                    )
                )
        return self.dedupe_findings(findings)
