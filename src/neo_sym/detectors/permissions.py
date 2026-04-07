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
            is_wildcard_contract = perm.contract == "*"
            is_wildcard_methods = "*" in perm.methods
            if is_wildcard_contract and is_wildcard_methods:
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
            elif is_wildcard_contract and perm.methods:
                findings.append(
                    self.finding(
                        title="Wildcard Contract Permission",
                        severity=Severity.LOW,
                        description=(
                            f"Manifest allows calling methods {perm.methods} on any contract."
                        ),
                        recommendation="Restrict permissions to specific contract hashes.",
                        tags=("manifest", "least-privilege"),
                    )
                )
            elif is_wildcard_methods:
                findings.append(
                    self.finding(
                        title="Wildcard Method Permission",
                        severity=Severity.LOW,
                        description=(
                            f"Manifest allows calling any method on contract '{perm.contract}'."
                        ),
                        recommendation="Restrict permissions to specific method names.",
                        tags=("manifest", "least-privilege"),
                    )
                )
        return self.dedupe_findings(findings)
