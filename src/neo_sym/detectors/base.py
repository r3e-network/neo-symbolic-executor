"""Base detector definitions."""
from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..engine.state import ExecutionState
from ..nef.manifest import Manifest

__all__ = ["SEVERITY_RANK", "BaseDetector", "Finding", "Severity"]


class Severity(StrEnum):
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

    _COUNT_CEILING = 6.0
    _AVG_COMPLEXITY_CEILING = 12.0
    _PEAK_COMPLEXITY_CEILING = 24.0
    _COUNT_WEIGHT = 0.5
    _AVG_WEIGHT = 0.35
    _PEAK_WEIGHT = 0.15

    _UNCERTAINTY_PENALTY_FACTOR = 0.25
    _MIN_CONFIDENCE = 0.45
    _MAX_CONFIDENCE = 0.99

    _OPAQUE_REPR_CHUNK = 32
    _OPAQUE_MAX_UPLIFT = 4

    @abstractmethod
    def detect(self, states: list[ExecutionState], manifest: Manifest | None = None) -> list[Finding]: ...

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
        """Create a Finding with optional path-uncertainty calibration from *state*."""
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
        if not constraint_count:
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
            except (TypeError, AttributeError):
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
            except (TypeError, ValueError):
                count = 0
            if count > 0:
                extracted: list[Any] = []
                for idx in range(count):
                    try:
                        extracted.append(arg_at(idx))
                    except (TypeError, ValueError, IndexError):
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
            nodes += min(cls._OPAQUE_MAX_UPLIFT, max(0, text_len - cls._OPAQUE_REPR_CHUNK) // cls._OPAQUE_REPR_CHUNK)

        return nodes + max_depth - 1

    def path_uncertainty_score(self, state: ExecutionState) -> float:
        """Return a 0.0–1.0 score reflecting symbolic-path uncertainty from constraints."""
        constraints = state.constraints
        if not constraints:
            return 0.0

        complexities = [self._constraint_complexity(constraint) for constraint in constraints]
        count_factor = min(1.0, len(constraints) / self._COUNT_CEILING)
        average_complexity = sum(complexities) / len(complexities)
        average_factor = min(1.0, average_complexity / self._AVG_COMPLEXITY_CEILING)
        peak_factor = min(1.0, max(complexities) / self._PEAK_COMPLEXITY_CEILING)

        score = (
            self._COUNT_WEIGHT * count_factor
            + self._AVG_WEIGHT * average_factor
            + self._PEAK_WEIGHT * peak_factor
        )
        return max(0.0, min(1.0, score))

    def calibrated_confidence(
        self,
        state: ExecutionState,
        *,
        base_confidence: float | None = None,
        minimum_confidence: float | None = None,
        uncertainty_score: float | None = None,
    ) -> float:
        """Return *base_confidence* penalised by path uncertainty, clamped to valid range."""
        baseline = self.default_confidence if base_confidence is None else base_confidence
        uncertainty = self.path_uncertainty_score(state) if uncertainty_score is None else uncertainty_score
        min_conf = self._MIN_CONFIDENCE if minimum_confidence is None else minimum_confidence
        penalty = self._UNCERTAINTY_PENALTY_FACTOR * uncertainty
        adjusted = baseline - penalty
        bounded = max(min_conf, min(self._MAX_CONFIDENCE, adjusted))
        return round(bounded, 3)

    @staticmethod
    def first_positive_offset(offsets: list[int] | tuple[int, ...]) -> int:
        """Return the smallest non-negative offset, or -1 if none."""
        return min((o for o in offsets if o >= 0), default=-1)

    @staticmethod
    def dedupe_findings(findings: list[Finding]) -> list[Finding]:
        """Deduplicate findings by (detector, title, offset), keeping the most severe."""
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
            is_more_severe = incoming_rank < existing_rank
            is_higher_confidence = incoming_rank == existing_rank and finding.confidence > existing.confidence
            if is_more_severe or is_higher_confidence:
                chosen = finding

            merged_tags = tuple(dict.fromkeys((*existing.tags, *finding.tags)))

            confidence_source = existing
            if finding.confidence > existing.confidence or (
                finding.confidence == existing.confidence
                and finding.confidence_reason
                and not existing.confidence_reason
            ):
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
