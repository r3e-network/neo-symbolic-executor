"""Report generator - JSON and Markdown output."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from ..detectors.base import SEVERITY_RANK, Finding, Severity


class ReportGenerator:
    def __init__(self, contract_name: str = "unknown") -> None:
        self.contract_name = contract_name

    @staticmethod
    def _severity_rank(severity: Severity) -> int:
        return SEVERITY_RANK.get(severity, 99)

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

    @staticmethod
    def _severity_weight(severity: Severity) -> int:
        weights = {
            Severity.CRITICAL: 100,
            Severity.HIGH: 40,
            Severity.MEDIUM: 10,
            Severity.LOW: 3,
            Severity.INFO: 1,
        }
        return weights.get(severity, 0)

    def _risk_profile(self, findings: list[Finding]) -> dict:
        if not findings:
            return {
                "overall_max_severity": Severity.INFO.value,
                "detector_max_severity": {},
                "weighted_score": 0,
                "confidence_weighted_score": 0,
                "detector_average_confidence": {},
            }

        overall = min((f.severity for f in findings), key=self._severity_rank)
        detector_max: dict[str, Severity] = {}
        detector_conf_sum: dict[str, float] = {}
        detector_conf_count: dict[str, int] = {}
        for finding in findings:
            prev = detector_max.get(finding.detector)
            if prev is None or self._severity_rank(finding.severity) < self._severity_rank(prev):
                detector_max[finding.detector] = finding.severity

            detector_conf_sum[finding.detector] = detector_conf_sum.get(finding.detector, 0.0) + finding.confidence
            detector_conf_count[finding.detector] = detector_conf_count.get(finding.detector, 0) + 1

        detector_max_serialized = {
            detector: detector_max[detector].value
            for detector in sorted(detector_max.keys())
        }

        detector_average_confidence = {
            detector: round(detector_conf_sum[detector] / detector_conf_count[detector], 3)
            for detector in sorted(detector_conf_sum.keys())
        }

        weighted_score = sum(self._severity_weight(f.severity) for f in findings)
        confidence_weighted_score = int(
            round(
                sum(
                    self._severity_weight(f.severity) * max(0.0, min(1.0, f.confidence))
                    for f in findings
                )
            )
        )
        return {
            "overall_max_severity": overall.value,
            "detector_max_severity": detector_max_serialized,
            "weighted_score": weighted_score,
            "confidence_weighted_score": confidence_weighted_score,
            "detector_average_confidence": detector_average_confidence,
        }

    def to_dict(self, findings: list[Finding]) -> dict:
        sorted_findings = self._sorted_findings(findings)
        by_sev = {s.value: 0 for s in Severity}
        for f in sorted_findings:
            by_sev[f.severity.value] += 1
        return {
            "contract": self.contract_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": by_sev,
            "risk_profile": self._risk_profile(sorted_findings),
            "total": len(sorted_findings),
            "findings": [
                {"detector": f.detector, "title": f.title, "severity": f.severity.value,
                 "description": f.description, "offset": f.offset,
                 "recommendation": f.recommendation, "confidence": f.confidence,
                 "confidence_reason": f.confidence_reason,
                 "tags": list(f.tags)}
                for f in sorted_findings
            ],
        }

    def to_json(self, findings: list[Finding]) -> str:
        return json.dumps(self.to_dict(findings), indent=2)

    def to_markdown(self, findings: list[Finding]) -> str:
        d = self.to_dict(findings)
        lines = [
            f"# Security Audit Report: {self.contract_name}",
            f"\nGenerated: {d['timestamp']}\n",
            "## Summary\n",
            "| Severity | Count |\n|----------|-------|",
        ]
        for sev in Severity:
            lines.append(f"| {sev.value.capitalize()} | {d['summary'][sev.value]} |")
        lines.append(f"\n**Total findings: {d['total']}**\n")
        lines.append("## Risk Profile\n")
        risk = d["risk_profile"]
        lines.append(f"- **Overall Max Severity:** {risk['overall_max_severity'].capitalize()}")
        lines.append(f"- **Weighted Score:** {risk['weighted_score']}")
        lines.append(f"- **Confidence-Weighted Score:** {risk['confidence_weighted_score']}")
        lines.append("")
        if risk["detector_max_severity"]:
            lines.append("| Detector | Max Severity |")
            lines.append("|----------|--------------|")
            for detector, severity in risk["detector_max_severity"].items():
                lines.append(f"| {detector} | {severity.capitalize()} |")
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
