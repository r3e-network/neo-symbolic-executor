"""Upgradeability and destroy-path hardening detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class UpgradeabilityDetector(BaseDetector):
    name = "upgradeability"
    description = "Detects insecure update/destroy flows"
    default_confidence = 0.85

    _SENSITIVE_METHOD_NAMES = {"update", "destroy", "_deploy"}

    @classmethod
    def _is_sensitive_external_method(cls, method_name: str) -> bool:
        lowered = method_name.lower()
        if "contractmanagement.update" in lowered:
            return True
        if "destroy" in lowered:
            return True
        if ":" in lowered:
            target_method = lowered.split(":")[-1]
            if target_method in cls._SENSITIVE_METHOD_NAMES:
                return True
        return False

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        sensitive_entries: set[int] = set()

        if manifest is not None:
            for method in manifest.abi_methods:
                if method.name.lower() in self._SENSITIVE_METHOD_NAMES:
                    sensitive_entries.add(method.offset)

        for state in states:
            has_upgrade_call = any(self._is_sensitive_external_method(call.method) for call in state.external_calls)
            is_sensitive_entry = state.entry_offset in sensitive_entries
            if not (has_upgrade_call or is_sensitive_entry):
                continue
            if state.witness_checks:
                continue

            findings.append(
                self.finding(
                    title="Insecure Upgradeability Path",
                    severity=Severity.CRITICAL if has_upgrade_call else Severity.HIGH,
                    offset=state.entry_offset if state.entry_offset >= 0 else -1,
                    description=(
                        "Contract exposes upgrade/destroy behavior without strong authorization checks."
                    ),
                    recommendation=(
                        "Protect update/destroy methods using strict witness checks and preferably multisig governance."
                    ),
                    state=state,
                    tags=("upgradeability", "authorization"),
                )
            )

        return self.dedupe_findings(findings)
