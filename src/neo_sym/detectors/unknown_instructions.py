"""Detector for unmodelled opcodes and syscalls."""
from __future__ import annotations

__all__ = ["UnknownInstructionsDetector"]

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class UnknownInstructionsDetector(BaseDetector):
    name = "unknown_instructions"
    description = "Reports opcodes and syscalls not fully modelled by the engine"

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []

        for state in states:
            for offset in state.unknown_opcodes:
                findings.append(
                    self.finding(
                        title="Unmodelled Opcode",
                        severity=Severity.INFO,
                        offset=offset,
                        description=(
                            f"Opcode at offset 0x{offset:04X} is not fully modelled;"
                            " analysis may be incomplete."
                        ),
                        recommendation="Review the instruction manually to assess its impact on security properties.",
                        state=state,
                        tags=("coverage",),
                    )
                )
            for offset, name in state.unknown_syscalls:
                findings.append(
                    self.finding(
                        title=f"Unmodelled Syscall: {name}",
                        severity=Severity.INFO,
                        offset=offset,
                        description=f"Syscall '{name}' at offset 0x{offset:04X} is not fully modelled.",
                        recommendation="Verify that the unmodelled syscall does not affect security-critical state.",
                        state=state,
                        tags=("coverage",),
                    )
                )

        return self.dedupe_findings(findings)
