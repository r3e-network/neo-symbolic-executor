"""CLI behavior tests."""
from __future__ import annotations

import json

from click.testing import CliRunner

from neo_sym.cli import main
from neo_sym import __version__
from neo_sym.nef.opcodes import OpCode


def _overflow_prone_script() -> bytes:
    return bytes(
        [
            OpCode.INITSLOT, 0x01, 0x01,
            OpCode.LDARG0,
            OpCode.STLOC0,
            OpCode.LDLOC0,
            OpCode.PUSH1,
            OpCode.ADD,
            OpCode.RET,
        ]
    )


def test_cli_falls_back_to_entry_zero_when_manifest_has_no_methods(tmp_path):
    nef_path = tmp_path / "contract.nef"
    manifest_path = tmp_path / "manifest.json"

    nef_path.write_bytes(bytes([OpCode.PUSH1, OpCode.RET]))
    manifest_path.write_text(
        json.dumps(
            {
                "name": "NoAbiContract",
                "supportedstandards": [],
                "abi": {"methods": [], "events": []},
            }
        )
    )

    runner = CliRunner()
    result = runner.invoke(main, ["analyze", str(nef_path), "--manifest", str(manifest_path), "--format", "json"])

    assert result.exit_code == 0
    assert "Explored 1 execution paths" in result.output


def test_cli_reports_package_version():
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_cli_fails_when_confidence_weighted_score_gate_is_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-confidence-weighted-score",
            "30",
        ],
    )

    assert result.exit_code == 3
    assert "Confidence-weighted score gate failed" in result.output


def test_cli_fails_when_min_confidence_floor_is_violated(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--min-confidence",
            "high=0.90",
        ],
    )

    assert result.exit_code == 3
    assert "Minimum confidence floor violated" in result.output


def test_cli_passes_when_confidence_gates_are_not_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-confidence-weighted-score",
            "40",
            "--min-confidence",
            "high=0.70",
        ],
    )

    assert result.exit_code == 0


def test_cli_fails_when_max_severity_gate_is_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-max-severity",
            "medium",
        ],
    )

    assert result.exit_code == 3
    assert "Max severity gate failed" in result.output


def test_cli_fails_when_detector_severity_gate_is_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-detector-severity",
            "overflow=high",
        ],
    )

    assert result.exit_code == 3
    assert "Detector severity gate failed" in result.output


def test_cli_passes_when_detector_severity_gate_not_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-detector-severity",
            "overflow=critical",
        ],
    )

    assert result.exit_code == 0


def test_cli_fails_for_invalid_detector_severity_policy(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-detector-severity",
            "unknown_detector=high",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid detector" in result.output


def test_cli_writes_gate_evaluation_to_json_report_on_failure(tmp_path):
    nef_path = tmp_path / "contract.nef"
    report_path = tmp_path / "report.json"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--output",
            str(report_path),
            "--detectors",
            "overflow,nep17",
            "--fail-on-confidence-weighted-score",
            "30",
        ],
    )

    assert result.exit_code == 3
    report = json.loads(report_path.read_text())
    gates = report["gate_evaluation"]
    assert gates["passed"] is False
    assert len(gates["violations"]) >= 1
    assert "Confidence-weighted score gate failed" in gates["violations"][0]
    assert gates["policies"]["fail_on_confidence_weighted_score"] == 30


def test_cli_writes_gate_evaluation_to_json_report_on_success(tmp_path):
    nef_path = tmp_path / "contract.nef"
    report_path = tmp_path / "report.json"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--output",
            str(report_path),
            "--detectors",
            "overflow,nep17",
            "--fail-on-confidence-weighted-score",
            "40",
            "--min-confidence",
            "high=0.70",
        ],
    )

    assert result.exit_code == 0
    report = json.loads(report_path.read_text())
    gates = report["gate_evaluation"]
    assert gates["passed"] is True
    assert gates["violations"] == []
    assert gates["policies"]["fail_on_confidence_weighted_score"] == 40
    assert gates["policies"]["min_confidence"] == {"high": 0.7}


def test_cli_markdown_report_includes_gate_evaluation_section(tmp_path):
    nef_path = tmp_path / "contract.nef"
    report_path = tmp_path / "report.md"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "markdown",
            "--output",
            str(report_path),
            "--detectors",
            "overflow,nep17",
            "--fail-on-confidence-weighted-score",
            "30",
        ],
    )

    assert result.exit_code == 3
    markdown = report_path.read_text()
    assert "## Gate Evaluation" in markdown
    assert "### Violations" in markdown
    assert "Confidence-weighted score gate failed" in markdown


def test_cli_fails_when_total_findings_gate_is_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-total-findings",
            "2",
        ],
    )

    assert result.exit_code == 3
    assert "Total findings gate failed" in result.output


def test_cli_fails_when_severity_count_gate_is_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-severity-count",
            "high=1",
        ],
    )

    assert result.exit_code == 3
    assert "Severity count gate failed" in result.output


def test_cli_passes_when_severity_count_gate_not_triggered(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-severity-count",
            "critical=1",
        ],
    )

    assert result.exit_code == 0


def test_cli_fails_for_invalid_severity_count_policy(tmp_path):
    nef_path = tmp_path / "contract.nef"
    nef_path.write_bytes(_overflow_prone_script())

    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "analyze",
            str(nef_path),
            "--format",
            "json",
            "--detectors",
            "overflow,nep17",
            "--fail-on-severity-count",
            "unknown=1",
        ],
    )

    assert result.exit_code == 2
    assert "Invalid severity" in result.output
