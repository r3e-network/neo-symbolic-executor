"""NEP-17 compliance detector."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity

NEP17_METHODS = {"symbol", "decimals", "totalSupply", "balanceOf", "transfer"}
NEP17_EVENTS = {"Transfer"}


class NEP17Detector(BaseDetector):
    name = "nep17"
    description = "Checks NEP-17 interface completeness"
    default_confidence = 0.95

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        if manifest is None:
            findings.append(
                self.finding(
                    title="No Manifest",
                    severity=Severity.INFO,
                    description="Cannot verify NEP-17 compliance without a manifest.",
                    recommendation="Provide contract manifest when running analysis.",
                    tags=("standard-compliance",),
                )
            )
            return findings

        if "NEP-17" not in manifest.supported_standards:
            return findings

        declared = {m.name for m in manifest.abi_methods}
        missing = NEP17_METHODS - declared
        if missing:
            findings.append(
                self.finding(
                    title="Missing NEP-17 Methods",
                    severity=Severity.HIGH,
                    description=f"Missing required NEP-17 methods: {', '.join(sorted(missing))}",
                    recommendation="Implement the full NEP-17 ABI surface.",
                    tags=("NEP-17",),
                )
            )

        events = {e.name for e in manifest.abi_events}
        if not NEP17_EVENTS.issubset(events):
            findings.append(
                self.finding(
                    title="Missing NEP-17 Transfer Event",
                    severity=Severity.HIGH,
                    description="Manifest does not declare required Transfer event.",
                    recommendation="Add Transfer event with expected parameter schema.",
                    tags=("NEP-17",),
                )
            )

        transfer = next((m for m in manifest.abi_methods if m.name == "transfer"), None)
        if transfer and len(transfer.parameters) != 4:
            findings.append(
                self.finding(
                    title="Invalid transfer Signature",
                    severity=Severity.HIGH,
                    offset=transfer.offset,
                    description=f"transfer requires 4 parameters, found {len(transfer.parameters)}.",
                    recommendation="Use transfer(from, to, amount, data).",
                    tags=("NEP-17",),
                )
            )

        return self.dedupe_findings(findings)
