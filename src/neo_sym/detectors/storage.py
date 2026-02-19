"""Storage collision detector - key prefix conflicts."""
from __future__ import annotations

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class StorageCollisionDetector(BaseDetector):
    name = "storage_collision"
    description = "Detects potential storage key prefix collisions"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        all_keys: list[tuple[int, bytes | str | int, ExecutionState]] = []
        for state in states:
            for op in state.storage_ops:
                if op.op_type == "put" and op.key.concrete is not None:
                    all_keys.append((op.offset, op.key.concrete, state))

        concrete_keys = [
            (off, k if isinstance(k, bytes) else str(k).encode("utf-8"), state)
            for off, k, state in all_keys
        ]
        for i, (off1, k1, source_state) in enumerate(concrete_keys):
            for off2, k2, other_state in concrete_keys[i + 1 :]:
                if k1 != k2 and (k1.startswith(k2) or k2.startswith(k1)):
                    pair_confidence = min(
                        self.calibrated_confidence(source_state),
                        self.calibrated_confidence(other_state),
                    )
                    findings.append(
                        self.finding(
                            title="Storage Key Prefix Collision",
                            severity=Severity.MEDIUM,
                            offset=off1,
                            description=f"Storage keys at offsets {off1} and {off2} overlap by prefix.",
                            recommendation="Use fixed-length namespace prefixes per storage domain.",
                            confidence=pair_confidence,
                            tags=("storage", "collision"),
                        )
                    )
        return self.dedupe_findings(findings)
