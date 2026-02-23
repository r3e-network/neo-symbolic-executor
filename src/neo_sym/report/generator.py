"""Report generator - JSON and Markdown output."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from ..detectors.base import SEVERITY_RANK, Finding, Severity

__all__ = ["ReportGenerator"]


class ReportGenerator:
    _SEVERITY_WEIGHTS: dict[Severity, int] = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 40,
        Severity.MEDIUM: 10,
        Severity.LOW: 3,
        Severity.INFO: 1,
    }

    def __init__(self, contract_name: str = "unknown") -> None:
        self.contract_name = contract_name

    def _sorted_findings(self, findings: list[Finding]) -> list[Finding]:
        return sorted(
            findings,
            key=lambda finding: (
                SEVERITY_RANK.get(finding.severity, 99),
                finding.offset if finding.offset >= 0 else 1_000_000,
                finding.detector,
                finding.title,
            ),
        )

    @classmethod
    def _severity_weight(cls, severity: Severity) -> int:
        return cls._SEVERITY_WEIGHTS.get(severity, 0)

    def _risk_profile(self, findings: list[Finding]) -> dict[str, Any]:
        if not findings:
            return {
                "overall_max_severity": Severity.INFO.value,
                "detector_max_severity": {},
                "weighted_score": 0,
                "confidence_weighted_score": 0,
                "detector_average_confidence": {},
            }

        overall = min((f.severity for f in findings), key=lambda s: SEVERITY_RANK[s])

        # Single-pass per-detector accumulation
        det_stats: dict[str, list[Any]] = {}  # {name: [max_severity, conf_sum, count]}
        for f in findings:
            s = det_stats.get(f.detector)
            if s is None:
                det_stats[f.detector] = [f.severity, f.confidence, 1]
            else:
                if SEVERITY_RANK[f.severity] < SEVERITY_RANK[s[0]]:
                    s[0] = f.severity
                s[1] += f.confidence
                s[2] += 1

        det_sorted = sorted(det_stats.items())
        return {
            "overall_max_severity": overall.value,
            "detector_max_severity": {d: s[0].value for d, s in det_sorted},
            "weighted_score": sum(self._severity_weight(f.severity) for f in findings),
            "confidence_weighted_score": int(round(sum(
                self._severity_weight(f.severity) * max(0.0, min(1.0, f.confidence))
                for f in findings
            ))),
            "detector_average_confidence": {
                d: round(s[1] / s[2], 3) for d, s in det_sorted
            },
        }

    @staticmethod
    def _finding_to_dict(f: Finding) -> dict[str, Any]:
        return {
            "detector": f.detector,
            "title": f.title,
            "severity": f.severity.value,
            "description": f.description,
            "offset": f.offset,
            "recommendation": f.recommendation,
            "confidence": f.confidence,
            "confidence_reason": f.confidence_reason,
            "tags": list(f.tags),
        }

    def to_dict(self, findings: list[Finding]) -> dict[str, Any]:
        """Serialize findings into a structured report dictionary."""
        sorted_findings = self._sorted_findings(findings)
        by_sev = {s.value: 0 for s in Severity}
        for f in sorted_findings:
            by_sev[f.severity.value] += 1
        return {
            "contract": self.contract_name,
            "timestamp": datetime.now(UTC).isoformat(),
            "summary": by_sev,
            "risk_profile": self._risk_profile(sorted_findings),
            "total": len(sorted_findings),
            "findings": [self._finding_to_dict(f) for f in sorted_findings],
        }

    def to_json(self, findings: list[Finding]) -> str:
        """Return the report as a pretty-printed JSON string."""
        return json.dumps(self.to_dict(findings), indent=2)

    @staticmethod
    def _markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
        sep = "|".join("-" * max(len(h), 3) for h in headers)
        lines = [
            "| " + " | ".join(headers) + " |",
            "|" + sep + "|",
        ]
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
        return lines

    def to_markdown(self, findings: list[Finding]) -> str:
        """Render the report as a Markdown document."""
        d = self.to_dict(findings)
        lines = [
            f"# Security Audit Report: {self.contract_name}",
            f"\nGenerated: {d['timestamp']}\n",
            "## Summary\n",
        ]
        lines.extend(self._markdown_table(
            ["Severity", "Count"],
            [[sev.value.capitalize(), str(d["summary"][sev.value])] for sev in Severity],
        ))
        lines.append(f"\n**Total findings: {d['total']}**\n")
        lines.append("## Risk Profile\n")
        risk = d["risk_profile"]
        lines.append(f"- **Overall Max Severity:** {risk['overall_max_severity'].capitalize()}")
        lines.append(f"- **Weighted Score:** {risk['weighted_score']}")
        lines.append(f"- **Confidence-Weighted Score:** {risk['confidence_weighted_score']}")
        lines.append("")
        if risk["detector_max_severity"]:
            lines.extend(self._markdown_table(
                ["Detector", "Max Severity"],
                [[det, sev.capitalize()] for det, sev in risk["detector_max_severity"].items()],
            ))
            lines.append("")
        lines.append("## Findings\n")
        for i, f in enumerate(d["findings"], 1):
            lines.append(f"### {i}. {f['title']}")
            lines.append(f"\n- **Severity:** {f['severity'].capitalize()}")
            lines.append(f"- **Detector:** {f['detector']}")
            if f["offset"] >= 0:
                lines.append(f"- **Offset:** 0x{f['offset']:04X}")
            lines.append(f"- **Confidence:** {f['confidence']:.3f}")
            if f["confidence_reason"]:
                lines.append(f"- **Confidence Rationale:** {f['confidence_reason']}")
            lines.append(f"- **Description:** {f['description']}")
            if f["recommendation"]:
                lines.append(f"- **Recommendation:** {f['recommendation']}")
            if f["tags"]:
                lines.append(f"- **Tags:** {', '.join(f['tags'])}")
            lines.append("")
        return "\n".join(lines)
