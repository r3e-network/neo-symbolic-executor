"""Base detector definitions."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(slots=True, frozen=True)
class Finding:
    detector: str
    title: str
    severity: Severity
    description: str
    offset: int = -1
    recommendation: str | None = None
    confidence: float = 0.7
    confidence_reason: str | None = None
    tags: tuple[str, ...] = field(default_factory=tuple)


class BaseDetector(ABC):
    name = "base"
    description = "base detector"
    default_confidence = 0.7

    @abstractmethod
    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]:
        raise NotImplementedError

    def finding(
        self,
        *,
        title: str,
        severity: Severity,
        description: str,
        offset: int = -1,
        recommendation: str | None = None,
        confidence: float | None = None,
        confidence_reason: str | None = None,
        tags: Iterable[str] = (),
        state: ExecutionState | None = None,
    ) -> Finding:
        resolved_confidence = self.default_confidence if confidence is None else confidence
        resolved_confidence_reason = confidence_reason
        if state is not None:
            base_confidence = resolved_confidence
            uncertainty_score = self.path_uncertainty_score(state)
            resolved_confidence = self.calibrated_confidence(
                state,
                base_confidence=base_confidence,
                uncertainty_score=uncertainty_score,
            )
            if resolved_confidence_reason is None:
                resolved_confidence_reason = self._calibrated_confidence_reason(
                    state,
                    base_confidence=base_confidence,
                    calibrated_confidence=resolved_confidence,
                    uncertainty_score=uncertainty_score,
                )
        elif resolved_confidence_reason is None:
            resolved_confidence_reason = (
                f"Static confidence baseline {resolved_confidence:.3f}; no execution-path uncertainty context."
            )
        return Finding(
            detector=self.name,
            title=title,
            severity=severity,
            description=description,
            offset=offset,
            recommendation=recommendation,
            confidence=resolved_confidence,
            confidence_reason=resolved_confidence_reason,
            tags=tuple(tags),
        )

    def _calibrated_confidence_reason(
        self,
        state: ExecutionState,
        *,
        base_confidence: float,
        calibrated_confidence: float,
        uncertainty_score: float,
    ) -> str:
        constraint_count = len(state.constraints)
        if constraint_count == 0:
            return (
                f"Path uncertainty calibration retained baseline confidence {calibrated_confidence:.3f}; "
                "no symbolic constraints were observed."
            )

        complexities = [self._constraint_complexity(constraint) for constraint in state.constraints]
        avg_complexity = sum(complexities) / len(complexities)
        peak_complexity = max(complexities)
        penalty = max(0.0, base_confidence - calibrated_confidence)
        return (
            f"Path uncertainty calibration applied: constraints={constraint_count}, "
            f"avg_complexity={avg_complexity:.2f}, peak_complexity={peak_complexity}, "
            f"uncertainty={uncertainty_score:.3f}, penalty={penalty:.3f}, "
            f"confidence {base_confidence:.3f}->{calibrated_confidence:.3f}."
        )

    @classmethod
    def _iter_constraint_children(cls, constraint: Any) -> tuple[Any, ...]:
        if constraint is None:
            return ()
        if isinstance(constraint, dict):
            return tuple(constraint.values())
        if isinstance(constraint, (list, tuple, set, frozenset)):
            return tuple(constraint)
        if isinstance(constraint, (str, bytes, bytearray, int, float, bool)):
            return ()

        children_attr = getattr(constraint, "children", None)
        if callable(children_attr):
            try:
                children = tuple(children_attr())
                if children:
                    return children
            except Exception:
                pass

        args_attr = getattr(constraint, "args", None)
        if isinstance(args_attr, tuple) and args_attr:
            return args_attr
        if isinstance(args_attr, list) and args_attr:
            return tuple(args_attr)

        num_args = getattr(constraint, "num_args", None)
        arg_at = getattr(constraint, "arg", None)
        if callable(num_args) and callable(arg_at):
            try:
                count = int(num_args())
            except Exception:
                count = 0
            if count > 0:
                extracted: list[Any] = []
                for idx in range(count):
                    try:
                        extracted.append(arg_at(idx))
                    except Exception:
                        break
                if extracted:
                    return tuple(extracted)

        return ()

    @classmethod
    def _constraint_complexity(cls, constraint: Any) -> int:
        seen_ids: set[int] = set()
        stack: list[tuple[Any, int]] = [(constraint, 1)]
        nodes = 0
        max_depth = 1

        while stack:
            current, depth = stack.pop()
            obj_id = id(current)
            if obj_id in seen_ids:
                continue
            seen_ids.add(obj_id)

            nodes += 1
            max_depth = max(max_depth, depth)
            for child in cls._iter_constraint_children(current):
                stack.append((child, depth + 1))

        # Fallback uplift for opaque leaf objects whose structure is not introspectable.
        if nodes <= 1:
            text_len = len(repr(constraint))
            nodes += min(4, max(0, text_len - 32) // 32)

        return nodes + max_depth - 1

    def path_uncertainty_score(self, state: ExecutionState) -> float:
        constraints = state.constraints
        if not constraints:
            return 0.0

        complexities = [self._constraint_complexity(constraint) for constraint in constraints]
        count_factor = min(1.0, len(constraints) / 6.0)
        average_complexity = sum(complexities) / len(complexities)
        average_factor = min(1.0, average_complexity / 12.0)
        peak_factor = min(1.0, max(complexities) / 24.0)

        score = (0.5 * count_factor) + (0.35 * average_factor) + (0.15 * peak_factor)
        return max(0.0, min(1.0, score))

    def calibrated_confidence(
        self,
        state: ExecutionState,
        *,
        base_confidence: float | None = None,
        minimum_confidence: float = 0.45,
        uncertainty_score: float | None = None,
    ) -> float:
        baseline = self.default_confidence if base_confidence is None else base_confidence
        uncertainty = self.path_uncertainty_score(state) if uncertainty_score is None else uncertainty_score
        penalty = 0.25 * uncertainty
        adjusted = baseline - penalty
        bounded = max(minimum_confidence, min(0.99, adjusted))
        return round(bounded, 3)

    @staticmethod
    def dedupe_findings(findings: list[Finding]) -> list[Finding]:
        unique_by_key: dict[tuple[str, str, int], Finding] = {}
        for finding in findings:
            key = (finding.detector, finding.title, finding.offset)
            existing = unique_by_key.get(key)
            if existing is None:
                unique_by_key[key] = finding
                continue

            # Lower SEVERITY_RANK value = more severe
            existing_rank = SEVERITY_RANK[existing.severity]
            incoming_rank = SEVERITY_RANK[finding.severity]

            chosen = existing
            if incoming_rank < existing_rank:
                chosen = finding
            elif incoming_rank == existing_rank and finding.confidence > existing.confidence:
                chosen = finding

            merged_tags = tuple(dict.fromkeys((*existing.tags, *finding.tags)))

            confidence_source = existing
            if finding.confidence > existing.confidence:
                confidence_source = finding
            elif finding.confidence == existing.confidence:
                if finding.confidence_reason and not existing.confidence_reason:
                    confidence_source = finding

            merged_confidence = confidence_source.confidence
            merged_confidence_reason = confidence_source.confidence_reason
            if (
                chosen.tags != merged_tags
                or chosen.confidence != merged_confidence
                or chosen.confidence_reason != merged_confidence_reason
            ):
                chosen = Finding(
                    detector=chosen.detector,
                    title=chosen.title,
                    severity=chosen.severity,
                    description=chosen.description,
                    offset=chosen.offset,
                    recommendation=chosen.recommendation,
                    confidence=merged_confidence,
                    confidence_reason=merged_confidence_reason,
                    tags=merged_tags,
                )

            unique_by_key[key] = chosen

        return list(unique_by_key.values())
