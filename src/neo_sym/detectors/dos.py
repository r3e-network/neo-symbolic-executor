"""DoS detector - unbounded loops and excessive storage operations."""
from __future__ import annotations

__all__ = ["DoSDetector"]

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest
from .base import BaseDetector, Finding, Severity


class DoSDetector(BaseDetector):
    name = "dos"
    description = "Detects potential denial-of-service vectors"
    _RECURSION_DEPTH_THRESHOLD = 8
    _MAX_DEPTH_THRESHOLD = 96
    _EXCESSIVE_WRITES_THRESHOLD = 32

    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        findings: list[Finding] = []
        for state in states:
            has_loops = bool(state.loops_detected)
            if state.depth > self._MAX_DEPTH_THRESHOLD or has_loops:
                desc = f"Execution path depth={state.depth}"
                if has_loops:
                    desc += " with loop back-edges detected."
                else:
                    desc += " exceeds depth threshold."
                findings.append(
                    self.finding(
                        title="Potential Unbounded Loop",
                        severity=Severity.MEDIUM,
                        offset=self.first_positive_offset(state.loops_detected),
                        description=desc,
                        recommendation="Add bounded iteration checks and short-circuit exit conditions.",
                        state=state,
                        tags=("dos", "loop"),
                    )
                )

            if state.max_call_stack_depth >= self._RECURSION_DEPTH_THRESHOLD:
                findings.append(
                    self.finding(
                        title="Potential Recursive Call Exhaustion",
                        severity=Severity.MEDIUM,
                        description=(
                            f"Execution reached internal call depth {state.max_call_stack_depth}, "
                            "which may lead to stack/resource exhaustion under adversarial inputs."
                        ),
                        recommendation="Bound recursion depth and prefer iterative state-machine patterns.",
                        state=state,
                        tags=("dos", "recursion"),
                    )
                )

            storage_writes = sum(1 for op in state.storage_ops if op.op_type == "put")
            if storage_writes > self._EXCESSIVE_WRITES_THRESHOLD:
                findings.append(
                    self.finding(
                        title="Excessive Storage Writes",
                        severity=Severity.MEDIUM,
                        description=f"Path performs {storage_writes} storage writes.",
                        recommendation="Cap per-invocation writes or split operations across transactions.",
                        state=state,
                        tags=("dos", "storage"),
                    )
                )
        return self.dedupe_findings(findings)
