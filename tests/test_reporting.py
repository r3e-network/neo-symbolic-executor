"""Tests for report output consistency."""
from __future__ import annotations

from neo_sym.detectors.base import Finding, Severity
from neo_sym.report.generator import ReportGenerator


def test_report_summary_counts():
    findings = [
        Finding(detector="d1", title="f1", severity=Severity.HIGH, description="x"),
        Finding(detector="d2", title="f2", severity=Severity.MEDIUM, description="y"),
        Finding(detector="d3", title="f3", severity=Severity.HIGH, description="z"),
    ]

    report = ReportGenerator("Contract").to_dict(findings)
    assert report["contract"] == "Contract"
    assert report["summary"]["high"] == 2
    assert report["summary"]["medium"] == 1
    assert report["total"] == 3


def test_report_risk_profile_aggregates_worst_case():
    findings = [
        Finding(detector="reentrancy", title="r1", severity=Severity.HIGH, description="x", confidence=0.5),
        Finding(detector="reentrancy", title="r2", severity=Severity.CRITICAL, description="y", confidence=0.75),
        Finding(detector="dos", title="d1", severity=Severity.MEDIUM, description="z", confidence=0.2),
    ]

    report = ReportGenerator("Contract").to_dict(findings)
    risk = report["risk_profile"]

    assert risk["overall_max_severity"] == "critical"
    assert risk["detector_max_severity"]["reentrancy"] == "critical"
    assert risk["detector_max_severity"]["dos"] == "medium"
    assert risk["weighted_score"] == 150
    assert risk["confidence_weighted_score"] == 97
    assert risk["detector_average_confidence"]["reentrancy"] == 0.625
    assert risk["detector_average_confidence"]["dos"] == 0.2


def test_markdown_includes_risk_profile_section():
    findings = [
        Finding(
            detector="reentrancy",
            title="r1",
            severity=Severity.CRITICAL,
            description="x",
            confidence=0.8,
            confidence_reason="Path uncertainty calibration applied.",
        ),
    ]

    markdown = ReportGenerator("Contract").to_markdown(findings)
    assert "## Risk Profile" in markdown
    assert "Overall Max Severity" in markdown
    assert "Confidence-Weighted Score" in markdown
    assert "Confidence Rationale" in markdown


def test_report_serializes_finding_confidence_rationale():
    findings = [
        Finding(
            detector="access_control",
            title="Missing Access Control",
            severity=Severity.HIGH,
            description="x",
            confidence=0.71,
            confidence_reason="Calibrated from path uncertainty with 4 constraints.",
        ),
    ]

    report = ReportGenerator("Contract").to_dict(findings)
    assert report["findings"][0]["confidence"] == 0.71
    assert report["findings"][0]["confidence_reason"] == "Calibrated from path uncertainty with 4 constraints."
