"""CLI entry point for neo-sym."""

from __future__ import annotations

import json
import sys
from collections.abc import Iterable
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .detectors import ALL_DETECTORS, Severity
from .detectors.base import SEVERITY_RANK
from .engine.symbolic import SymbolicEngine
from .nef.manifest import parse_manifest
from .nef.parser import parse_nef
from .report.generator import ReportGenerator

console = Console()

_SEVERITY_RANK_BY_NAME: dict[str, int] = {s.value: r for s, r in SEVERITY_RANK.items()}


def _parse_min_confidence_specs(specs: Iterable[str]) -> dict[str, float]:
    floors: dict[str, float] = {}
    valid_severities = {severity.value for severity in Severity}
    for raw_spec in specs:
        if "=" not in raw_spec:
            raise click.BadParameter(
                f"Invalid --min-confidence value '{raw_spec}'. Expected format '<severity>=<0..1>'."
            )
        severity_text, floor_text = raw_spec.split("=", 1)
        severity_name = severity_text.strip().lower()
        if severity_name not in valid_severities:
            allowed = ", ".join(sorted(valid_severities))
            raise click.BadParameter(f"Invalid severity '{severity_name}' in --min-confidence. Allowed: {allowed}.")
        try:
            floor = float(floor_text.strip())
        except ValueError as exc:
            raise click.BadParameter(f"Invalid confidence floor '{floor_text}' in --min-confidence.") from exc
        if floor < 0.0 or floor > 1.0:
            raise click.BadParameter(f"Confidence floor for severity '{severity_name}' must be between 0 and 1.")
        floors[severity_name] = floor
    return floors


def _severity_rank_value(severity_name: str) -> int:
    return _SEVERITY_RANK_BY_NAME.get(severity_name.lower(), 99)


def _parse_detector_severity_specs(specs: Iterable[str]) -> dict[str, str]:
    policies: dict[str, str] = {}
    valid_severities = {severity.value for severity in Severity}
    for raw_spec in specs:
        if "=" not in raw_spec:
            raise click.BadParameter(
                f"Invalid --fail-on-detector-severity value '{raw_spec}'. Expected format '<detector>=<severity>'."
            )
        detector_text, severity_text = raw_spec.split("=", 1)
        detector_name = detector_text.strip()
        severity_name = severity_text.strip().lower()
        if detector_name not in ALL_DETECTORS:
            allowed_detectors = ", ".join(sorted(ALL_DETECTORS.keys()))
            raise click.BadParameter(
                f"Invalid detector '{detector_name}' in --fail-on-detector-severity. Allowed: {allowed_detectors}."
            )
        if severity_name not in valid_severities:
            allowed_severities = ", ".join(sorted(valid_severities))
            raise click.BadParameter(
                f"Invalid severity '{severity_name}' in --fail-on-detector-severity. Allowed: {allowed_severities}."
            )
        policies[detector_name] = severity_name
    return policies


def _parse_severity_count_specs(specs: Iterable[str]) -> dict[str, int]:
    policies: dict[str, int] = {}
    valid_severities = {severity.value for severity in Severity}
    for raw_spec in specs:
        if "=" not in raw_spec:
            raise click.BadParameter(
                f"Invalid --fail-on-severity-count value '{raw_spec}'. Expected format '<severity>=<count>'."
            )
        severity_text, count_text = raw_spec.split("=", 1)
        severity_name = severity_text.strip().lower()
        if severity_name not in valid_severities:
            allowed_severities = ", ".join(sorted(valid_severities))
            raise click.BadParameter(
                f"Invalid severity '{severity_name}' in --fail-on-severity-count. Allowed: {allowed_severities}."
            )
        try:
            count_threshold = int(count_text.strip())
        except ValueError as exc:
            raise click.BadParameter(f"Invalid count threshold '{count_text}' in --fail-on-severity-count.") from exc
        if count_threshold < 1:
            raise click.BadParameter(f"Count threshold for severity '{severity_name}' must be >= 1.")
        policies[severity_name] = count_threshold
    return policies


def _collect_gate_violations(
    *,
    findings,
    risk_profile: dict,
    fail_on_max_severity: str | None,
    fail_on_total_findings: int | None,
    fail_on_weighted_score: int | None,
    fail_on_confidence_weighted_score: int | None,
    min_confidence_floors: dict[str, float],
    severity_count_policies: dict[str, int],
    detector_severity_policies: dict[str, str],
) -> list[str]:
    violations: list[str] = []

    total_findings = len(findings)
    overall_max_severity = str(risk_profile.get("overall_max_severity", Severity.INFO.value))
    weighted_score = int(risk_profile.get("weighted_score", 0))
    confidence_weighted_score = int(risk_profile.get("confidence_weighted_score", 0))
    detector_max_severity = risk_profile.get("detector_max_severity", {})

    if fail_on_total_findings is not None and total_findings >= fail_on_total_findings:
        violations.append(f"Total findings gate failed: {total_findings} >= threshold {fail_on_total_findings}.")

    if fail_on_max_severity is not None and _severity_rank_value(overall_max_severity) <= _severity_rank_value(
        fail_on_max_severity
    ):
        violations.append(f"Max severity gate failed: {overall_max_severity} >= threshold {fail_on_max_severity}.")

    if fail_on_weighted_score is not None and weighted_score >= fail_on_weighted_score:
        violations.append(f"Weighted score gate failed: {weighted_score} >= threshold {fail_on_weighted_score}.")
    if fail_on_confidence_weighted_score is not None and confidence_weighted_score >= fail_on_confidence_weighted_score:
        violations.append(
            "Confidence-weighted score gate failed: "
            f"{confidence_weighted_score} >= threshold {fail_on_confidence_weighted_score}."
        )

    for severity_name, floor in sorted(min_confidence_floors.items()):
        below_floor = [
            finding for finding in findings if finding.severity.value == severity_name and finding.confidence < floor
        ]
        if not below_floor:
            continue
        sample = ", ".join(
            f"{finding.detector}:{finding.title}@{finding.confidence:.3f}" for finding in below_floor[:3]
        )
        suffix = "..." if len(below_floor) > 3 else ""
        violations.append(
            f"Minimum confidence floor violated for severity '{severity_name}': "
            f"{len(below_floor)} finding(s) below {floor:.3f} ({sample}{suffix})."
        )

    for severity_name, threshold_count in sorted(severity_count_policies.items()):
        matching_count = sum(1 for finding in findings if finding.severity.value == severity_name)
        if matching_count >= threshold_count:
            violations.append(
                f"Severity count gate failed for '{severity_name}': {matching_count} >= threshold {threshold_count}."
            )

    for detector_name, threshold_severity in sorted(detector_severity_policies.items()):
        detector_actual_severity = detector_max_severity.get(detector_name)
        if detector_actual_severity is None:
            continue
        if _severity_rank_value(detector_actual_severity) <= _severity_rank_value(threshold_severity):
            violations.append(
                "Detector severity gate failed: "
                f"{detector_name} severity {detector_actual_severity} >= threshold {threshold_severity}."
            )

    return violations


def _render_gate_evaluation_markdown(gate_evaluation: dict) -> str:
    lines = [
        "## Gate Evaluation",
        "",
        f"- **Passed:** {'Yes' if gate_evaluation['passed'] else 'No'}",
    ]
    policies = gate_evaluation.get("policies", {})
    configured_policy_lines: list[str] = []
    for key in (
        "fail_on_total_findings",
        "fail_on_max_severity",
        "fail_on_weighted_score",
        "fail_on_confidence_weighted_score",
        "min_confidence",
        "fail_on_severity_count",
        "fail_on_detector_severity",
    ):
        value = policies.get(key)
        if value in (None, {}, ()):
            continue
        configured_policy_lines.append(f"- `{key}`: {value}")
    if configured_policy_lines:
        lines.append("")
        lines.append("### Active Policies")
        lines.append("")
        lines.extend(configured_policy_lines)
    lines.append("")
    lines.append("### Violations")
    lines.append("")
    violations = gate_evaluation.get("violations", [])
    if violations:
        for violation in violations:
            lines.append(f"- {violation}")
    else:
        lines.append("- none")
    return "\n".join(lines)


@click.group()
@click.version_option(version=__version__)
def main() -> None:
    """Neo N3 Smart Contract Symbolic Execution Security Analyzer."""


@main.command()
@click.argument("nef_file", type=click.Path(exists=True))
@click.option("--manifest", "-m", type=click.Path(exists=True), help="Manifest JSON file")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option("--format", "fmt", type=click.Choice(["json", "markdown"]), default="markdown")
@click.option("--detectors", "-d", type=str, default=None, help="Comma-separated detector names")
@click.option("--max-paths", type=int, default=256, help="Max execution paths")
@click.option("--max-depth", type=int, default=128, help="Max call depth")
@click.option(
    "--fail-on-total-findings",
    type=int,
    default=None,
    help="Exit with code 3 if total findings count is greater than or equal to this threshold.",
)
@click.option(
    "--fail-on-max-severity",
    type=click.Choice([severity.value for severity in Severity], case_sensitive=False),
    default=None,
    help=("Exit with code 3 if overall max severity is greater than or equal to this severity threshold."),
)
@click.option(
    "--fail-on-weighted-score",
    type=int,
    default=None,
    help="Exit with code 3 if weighted risk score is greater than or equal to this threshold.",
)
@click.option(
    "--fail-on-confidence-weighted-score",
    type=int,
    default=None,
    help=("Exit with code 3 if confidence-weighted risk score is greater than or equal to this threshold."),
)
@click.option(
    "--min-confidence",
    "min_confidence_specs",
    multiple=True,
    help=("Minimum confidence floor in the form <severity>=<0..1> (e.g. high=0.80). Can be repeated."),
)
@click.option(
    "--fail-on-severity-count",
    "severity_count_specs",
    multiple=True,
    help=("Fail gate in the form <severity>=<count> (e.g. high=2). Can be repeated."),
)
@click.option(
    "--fail-on-detector-severity",
    "detector_severity_specs",
    multiple=True,
    help=("Fail gate in the form <detector>=<severity> (e.g. reentrancy=high). Can be repeated."),
)
def analyze(
    nef_file: str,
    manifest: str | None,
    output: str | None,
    fmt: str,
    detectors: str | None,
    max_paths: int,
    max_depth: int,
    fail_on_total_findings: int | None,
    fail_on_max_severity: str | None,
    fail_on_weighted_score: int | None,
    fail_on_confidence_weighted_score: int | None,
    min_confidence_specs: tuple[str, ...],
    severity_count_specs: tuple[str, ...],
    detector_severity_specs: tuple[str, ...],
) -> None:
    """Analyze a NEF contract file for security issues."""
    min_confidence_floors = _parse_min_confidence_specs(min_confidence_specs)
    severity_count_policies = _parse_severity_count_specs(severity_count_specs)
    detector_severity_policies = _parse_detector_severity_specs(detector_severity_specs)

    console.print(f"[bold blue]Neo Symbolic Executor v{__version__}[/]")
    console.print(f"Analyzing: {nef_file}\n")

    # Parse NEF
    nef_data = Path(nef_file).read_bytes()
    try:
        nef = parse_nef(nef_data)
    except ValueError as e:
        console.print(f"[red]Failed to parse NEF: {e}[/]")
        sys.exit(1)

    console.print(f"  Compiler: {nef.compiler}")
    if nef.source:
        console.print(f"  Source: {nef.source}")
    if nef.tokens:
        console.print(f"  Method tokens: {len(nef.tokens)}")
    console.print(f"  Script size: {len(nef.script)} bytes")
    console.print(f"  Instructions: {len(nef.instructions)}\n")

    # Parse manifest
    mf = None
    if manifest:
        try:
            mf = parse_manifest(Path(manifest).read_text())
        except ValueError as exc:
            console.print(f"[red]Failed to parse manifest: {exc}[/]")
            sys.exit(1)
        console.print(f"  Contract: {mf.name}")
        console.print(f"  Methods: {len(mf.abi_methods)}")
        console.print(f"  Standards: {', '.join(mf.supported_standards) or 'none'}\n")

    # Run symbolic execution
    engine = SymbolicEngine(nef, mf)
    engine.MAX_PATHS = max_paths
    engine.MAX_DEPTH = max_depth

    with console.status("[bold green]Running symbolic execution..."):
        entry_points = [m.offset for m in mf.abi_methods if m.offset >= 0] if mf else [0]
        if not entry_points:
            entry_points = [0]
            console.print("[yellow]Manifest has no ABI method offsets; falling back to entry offset 0.[/]")
        all_states = []
        for ep in entry_points:
            states = engine.run(entry_offset=ep)
            all_states.extend(states)

    console.print(f"Explored {len(all_states)} execution paths\n")

    # Run detectors
    selected = [name.strip() for name in detectors.split(",")] if detectors else list(ALL_DETECTORS.keys())
    selected = [name for name in selected if name]
    unknown = [name for name in selected if name not in ALL_DETECTORS]
    if unknown:
        console.print(f"[red]Unknown detector(s): {', '.join(unknown)}[/]")
        sys.exit(2)

    all_findings = []
    for name in selected:
        det = ALL_DETECTORS[name]()
        findings = det.detect(all_states, mf)
        all_findings.extend(findings)

    # Global dedupe to avoid duplicates across detectors.
    deduped = []
    seen: set[tuple[str, str, int]] = set()
    for finding in all_findings:
        key = (finding.detector, finding.title, finding.offset)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(finding)

    # Display results
    table = Table(title="Security Findings")
    table.add_column("Severity", style="bold")
    table.add_column("Detector")
    table.add_column("Title")
    table.add_column("Offset")
    sev_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "blue", "info": "white"}
    for f in sorted(
        deduped,
        key=lambda x: (
            _SEVERITY_RANK_BY_NAME.get(x.severity.value, 99),
            x.offset if x.offset >= 0 else 1_000_000,
            x.title,
        ),
    ):
        table.add_row(
            f"[{sev_colors[f.severity.value]}]{f.severity.value.upper()}[/]",
            f.detector,
            f.title,
            f"0x{f.offset:04X}" if f.offset >= 0 else "-",
        )
    if deduped:
        console.print(table)
    else:
        console.print("[green]No findings detected by selected detectors.[/]")
    console.print(f"\n[bold]Total: {len(deduped)} findings[/]\n")

    # Generate report
    gen = ReportGenerator(mf.name if mf else Path(nef_file).stem)
    report_dict = gen.to_dict(deduped)
    gate_violations = _collect_gate_violations(
        findings=deduped,
        risk_profile=report_dict["risk_profile"],
        fail_on_total_findings=fail_on_total_findings,
        fail_on_max_severity=fail_on_max_severity,
        fail_on_weighted_score=fail_on_weighted_score,
        fail_on_confidence_weighted_score=fail_on_confidence_weighted_score,
        min_confidence_floors=min_confidence_floors,
        severity_count_policies=severity_count_policies,
        detector_severity_policies=detector_severity_policies,
    )
    gate_policies = {
        "fail_on_total_findings": fail_on_total_findings,
        "fail_on_max_severity": fail_on_max_severity,
        "fail_on_weighted_score": fail_on_weighted_score,
        "fail_on_confidence_weighted_score": fail_on_confidence_weighted_score,
        "min_confidence": min_confidence_floors,
        "fail_on_severity_count": severity_count_policies,
        "fail_on_detector_severity": detector_severity_policies,
    }
    gate_evaluation = {
        "passed": not gate_violations,
        "violations": list(gate_violations),
        "policies": gate_policies,
    }
    report_dict["gate_evaluation"] = gate_evaluation

    if fmt == "json":
        report = json.dumps(report_dict, indent=2)
    else:
        report = gen.to_markdown(deduped)
        report = f"{report}\n\n{_render_gate_evaluation_markdown(gate_evaluation)}"

    if output:
        Path(output).write_text(report)
        console.print(f"[green]Report saved to {output}[/]")
    else:
        console.print(report)
    if gate_violations:
        for violation in gate_violations:
            console.print(f"[red]{violation}[/]")
        sys.exit(3)


if __name__ == "__main__":
    main()
