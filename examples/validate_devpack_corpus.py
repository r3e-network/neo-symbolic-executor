"""Validate neo-sym against Neo DevPack TestingArtifacts contracts.

This utility:
1. Extracts embedded manifest/NEF payloads from DevPack `TestingArtifacts/*.cs`.
2. Runs `neo_sym.cli analyze` for every extracted contract.
3. Emits JSON + Markdown validation reports with pass/fail diagnostics.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


MANIFEST_PATTERN = re.compile(
    r"public\s+static\s+.*?\sManifest\s*=>\s*.*?Parse\(@\"(.*?)\"\);",
    re.DOTALL,
)
NEF_PATTERN = re.compile(
    r"public\s+static\s+.*?\sNef\s*=>\s*Convert\.FromBase64String\(@\"(.*?)\"\)"
    r"\.AsSerializable<Neo\.SmartContract\.NefFile>\(\);",
    re.DOTALL,
)


@dataclass
class ExtractedArtifact:
    source_cs: str
    contract_name: str
    nef_path: str
    manifest_path: str
    relative_group: str


@dataclass
class ExtractionFailure:
    source_cs: str
    error: str


@dataclass
class AnalysisResult:
    contract_name: str
    source_cs: str
    nef_path: str
    manifest_path: str
    report_path: str
    exit_code: int
    category: str
    finding_count: int | None
    max_severity: str | None
    stdout_tail: str
    stderr_tail: str


def _normalize_output_root(project_root: Path, output_root: Path) -> Path:
    if output_root.is_absolute():
        return output_root
    return (project_root / output_root).resolve()


def _discover_testing_artifacts(devpack_root: Path) -> list[Path]:
    return sorted(devpack_root.glob("**/TestingArtifacts/*.cs"))


def _decode_csharp_verbatim_string(raw: str) -> str:
    # C# verbatim strings escape quote characters as "".
    return raw.replace('""', '"')


def _extract_single_artifact(source_path: Path, devpack_root: Path, out_root: Path) -> ExtractedArtifact:
    text = source_path.read_text(encoding="utf-8")

    manifest_match = MANIFEST_PATTERN.search(text)
    if not manifest_match:
        raise ValueError("embedded manifest not found")
    nef_match = NEF_PATTERN.search(text)
    if not nef_match:
        raise ValueError("embedded NEF not found")

    manifest_text = _decode_csharp_verbatim_string(manifest_match.group(1))
    manifest_obj = json.loads(manifest_text)
    contract_name = str(manifest_obj.get("name") or source_path.stem)

    nef_b64 = re.sub(r"\s+", "", nef_match.group(1))
    nef_bytes = base64.b64decode(nef_b64, validate=True)

    rel = source_path.relative_to(devpack_root)
    artifact_stem = source_path.stem
    if artifact_stem.endswith(".artifacts"):
        artifact_stem = artifact_stem[: -len(".artifacts")]

    target_dir = out_root / rel.parent
    target_dir.mkdir(parents=True, exist_ok=True)
    nef_path = target_dir / f"{artifact_stem}.nef"
    manifest_path = target_dir / f"{artifact_stem}.manifest.json"

    nef_path.write_bytes(nef_bytes)
    manifest_path.write_text(json.dumps(manifest_obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    relative_group = str(rel.parent)
    return ExtractedArtifact(
        source_cs=str(source_path),
        contract_name=contract_name,
        nef_path=str(nef_path),
        manifest_path=str(manifest_path),
        relative_group=relative_group,
    )


def extract_artifacts(devpack_root: Path, extracted_root: Path) -> tuple[list[ExtractedArtifact], list[ExtractionFailure]]:
    extracted: list[ExtractedArtifact] = []
    failures: list[ExtractionFailure] = []
    for source_path in _discover_testing_artifacts(devpack_root):
        try:
            artifact = _extract_single_artifact(source_path, devpack_root, extracted_root)
            extracted.append(artifact)
        except Exception as exc:  # pragma: no cover - exercised by real corpus failures
            failures.append(ExtractionFailure(source_cs=str(source_path), error=f"{type(exc).__name__}: {exc}"))
    return extracted, failures


def _tail(text: str, max_lines: int = 20) -> str:
    lines = text.splitlines()
    return "\n".join(lines[-max_lines:])


def _categorize_failure(stdout: str, stderr: str, exit_code: int) -> str:
    combined = f"{stdout}\n{stderr}"
    if "Failed to parse NEF" in combined:
        return "nef_parse_failure"
    if "Failed to parse manifest" in combined:
        return "manifest_parse_failure"
    if "Unknown detector(s)" in combined:
        return "detector_config_failure"
    if "Traceback (most recent call last)" in combined:
        return "unhandled_exception"
    return f"exit_{exit_code}"


def run_analysis(
    *,
    project_root: Path,
    extracted: list[ExtractedArtifact],
    analysis_root: Path,
    max_contracts: int | None,
) -> tuple[list[AnalysisResult], Counter[str], Counter[str]]:
    results: list[AnalysisResult] = []
    detector_counts: Counter[str] = Counter()
    severity_counts: Counter[str] = Counter()

    items = extracted[:max_contracts] if max_contracts is not None else extracted
    env = os.environ.copy()
    src_path = str((project_root / "src").resolve())
    if env.get("PYTHONPATH"):
        env["PYTHONPATH"] = f"{src_path}{os.pathsep}{env['PYTHONPATH']}"
    else:
        env["PYTHONPATH"] = src_path

    analysis_root.mkdir(parents=True, exist_ok=True)

    for index, artifact in enumerate(items, start=1):
        rel_report = Path(artifact.relative_group) / (
            Path(artifact.nef_path).stem + ".analysis.json"
        )
        report_path = analysis_root / rel_report
        report_path.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            sys.executable,
            "-m",
            "neo_sym.cli",
            "analyze",
            artifact.nef_path,
            "--manifest",
            artifact.manifest_path,
            "--format",
            "json",
            "--output",
            str(report_path),
        ]
        proc = subprocess.run(
            cmd,
            cwd=project_root,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

        report_json: dict[str, Any] | None = None
        if report_path.exists():
            try:
                report_json = json.loads(report_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                report_json = None

        finding_count: int | None = None
        max_severity: str | None = None
        if report_json is not None:
            findings = report_json.get("findings", [])
            finding_count = len(findings) if isinstance(findings, list) else None
            risk_profile = report_json.get("risk_profile", {})
            if isinstance(risk_profile, dict):
                max_value = risk_profile.get("overall_max_severity")
                max_severity = str(max_value) if max_value is not None else None

            if isinstance(findings, list):
                for finding in findings:
                    detector = finding.get("detector")
                    severity = finding.get("severity")
                    if isinstance(detector, str):
                        detector_counts[detector] += 1
                    if isinstance(severity, str):
                        severity_counts[severity] += 1

        category = "ok" if proc.returncode == 0 else _categorize_failure(proc.stdout, proc.stderr, proc.returncode)
        if proc.returncode != 0 and report_path.exists():
            # Keep only successful analysis reports as canonical artifacts.
            report_path.unlink()

        results.append(
            AnalysisResult(
                contract_name=artifact.contract_name,
                source_cs=artifact.source_cs,
                nef_path=artifact.nef_path,
                manifest_path=artifact.manifest_path,
                report_path=str(report_path),
                exit_code=proc.returncode,
                category=category,
                finding_count=finding_count,
                max_severity=max_severity,
                stdout_tail=_tail(proc.stdout),
                stderr_tail=_tail(proc.stderr),
            )
        )

        if index % 25 == 0 or index == len(items):
            print(f"[analysis] processed {index}/{len(items)} contracts", file=sys.stderr)

    return results, detector_counts, severity_counts


def _counter_to_sorted_dict(counter: Counter[str]) -> dict[str, int]:
    return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))


def _build_summary(
    *,
    project_root: Path,
    devpack_root: Path,
    output_root: Path,
    discovered_count: int,
    extracted: list[ExtractedArtifact],
    extraction_failures: list[ExtractionFailure],
    results: list[AnalysisResult],
    detector_counts: Counter[str],
    severity_counts: Counter[str],
) -> dict[str, Any]:
    exit_code_counts: Counter[str] = Counter(str(result.exit_code) for result in results)
    failure_categories: Counter[str] = Counter(result.category for result in results if result.exit_code != 0)
    ok_results = [result for result in results if result.exit_code == 0]
    failed_results = [result for result in results if result.exit_code != 0]
    findings_total = sum(result.finding_count or 0 for result in ok_results)

    return {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "project_root": str(project_root),
        "devpack_root": str(devpack_root),
        "output_root": str(output_root),
        "discovered_testing_artifacts": discovered_count,
        "extraction": {
            "success_count": len(extracted),
            "failure_count": len(extraction_failures),
            "failures": [asdict(item) for item in extraction_failures],
        },
        "analysis": {
            "attempted_count": len(results),
            "success_count": len(ok_results),
            "failure_count": len(failed_results),
            "success_rate": (len(ok_results) / len(results)) if results else 0.0,
            "total_findings": findings_total,
            "exit_code_counts": _counter_to_sorted_dict(exit_code_counts),
            "failure_categories": _counter_to_sorted_dict(failure_categories),
            "severity_counts": _counter_to_sorted_dict(severity_counts),
            "detector_counts": _counter_to_sorted_dict(detector_counts),
            "failures": [asdict(result) for result in failed_results],
            "contracts": [asdict(result) for result in results],
        },
    }


def _render_markdown(summary: dict[str, Any]) -> str:
    extraction = summary["extraction"]
    analysis = summary["analysis"]
    failures = analysis["failures"]
    lines: list[str] = []

    lines.append("# Neo DevPack Corpus Validation Report")
    lines.append("")
    lines.append(f"- Timestamp (UTC): `{summary['timestamp_utc']}`")
    lines.append(f"- Project root: `{summary['project_root']}`")
    lines.append(f"- DevPack root: `{summary['devpack_root']}`")
    lines.append(f"- Output root: `{summary['output_root']}`")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    lines.append(f"- Discovered `TestingArtifacts/*.cs`: **{summary['discovered_testing_artifacts']}**")
    lines.append(f"- Successfully extracted artifacts: **{extraction['success_count']}**")
    lines.append(f"- Extraction failures: **{extraction['failure_count']}**")
    lines.append(f"- Analyzer attempts: **{analysis['attempted_count']}**")
    lines.append(f"- Analyzer successes: **{analysis['success_count']}**")
    lines.append(f"- Analyzer failures: **{analysis['failure_count']}**")
    lines.append(f"- Success rate: **{analysis['success_rate'] * 100:.2f}%**")
    lines.append(f"- Total findings across successful analyses: **{analysis['total_findings']}**")
    lines.append("")
    lines.append("## Exit Codes")
    lines.append("")
    if analysis["exit_code_counts"]:
        for code, count in analysis["exit_code_counts"].items():
            lines.append(f"- `{code}`: {count}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Failure Categories")
    lines.append("")
    if analysis["failure_categories"]:
        for category, count in analysis["failure_categories"].items():
            lines.append(f"- `{category}`: {count}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Finding Distribution")
    lines.append("")
    lines.append("### By Severity")
    lines.append("")
    if analysis["severity_counts"]:
        for severity, count in analysis["severity_counts"].items():
            lines.append(f"- `{severity}`: {count}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("### By Detector")
    lines.append("")
    if analysis["detector_counts"]:
        for detector, count in analysis["detector_counts"].items():
            lines.append(f"- `{detector}`: {count}")
    else:
        lines.append("- none")
    lines.append("")
    lines.append("## Failure Details (first 20)")
    lines.append("")
    if failures:
        for failure in failures[:20]:
            lines.append(f"- Contract `{failure['contract_name']}` (`exit={failure['exit_code']}`, `category={failure['category']}`)")
            lines.append(f"  - Source: `{failure['source_cs']}`")
            if failure["stdout_tail"]:
                lines.append("  - Stdout tail:")
                lines.append("```text")
                lines.append(failure["stdout_tail"])
                lines.append("```")
            if failure["stderr_tail"]:
                lines.append("  - Stderr tail:")
                lines.append("```text")
                lines.append(failure["stderr_tail"])
                lines.append("```")
    else:
        lines.append("- none")
    lines.append("")
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--devpack-root",
        required=True,
        type=Path,
        help="Path to cloned neo-devpack-dotnet repository.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Path to neo-symbolic-executor project root.",
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=Path("docs/validation/devpack-corpus"),
        help="Output directory (absolute or relative to --project-root).",
    )
    parser.add_argument(
        "--max-contracts",
        type=int,
        default=None,
        help="Optional limit for analysis run (useful for smoke tests).",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Delete previous output-root content before running.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    project_root = args.project_root.resolve()
    devpack_root = args.devpack_root.resolve()
    output_root = _normalize_output_root(project_root, args.output_root)

    if not devpack_root.exists():
        print(f"DevPack root not found: {devpack_root}", file=sys.stderr)
        return 2

    if args.clean and output_root.exists():
        shutil.rmtree(output_root)
    output_root.mkdir(parents=True, exist_ok=True)

    extracted_root = output_root / "extracted"
    analysis_root = output_root / "analysis"

    discovered_count = len(_discover_testing_artifacts(devpack_root))
    extracted, extraction_failures = extract_artifacts(devpack_root, extracted_root)
    (output_root / "artifacts.index.json").write_text(
        json.dumps([asdict(item) for item in extracted], indent=2),
        encoding="utf-8",
    )

    results, detector_counts, severity_counts = run_analysis(
        project_root=project_root,
        extracted=extracted,
        analysis_root=analysis_root,
        max_contracts=args.max_contracts,
    )

    summary = _build_summary(
        project_root=project_root,
        devpack_root=devpack_root,
        output_root=output_root,
        discovered_count=discovered_count,
        extracted=extracted,
        extraction_failures=extraction_failures,
        results=results,
        detector_counts=detector_counts,
        severity_counts=severity_counts,
    )

    summary_json_path = output_root / "summary.json"
    summary_md_path = output_root / "summary.md"
    summary_json_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    summary_md_path.write_text(_render_markdown(summary), encoding="utf-8")

    print(f"Validation summary JSON: {summary_json_path}")
    print(f"Validation summary Markdown: {summary_md_path}")
    print(
        f"Analyzed {summary['analysis']['attempted_count']} contracts: "
        f"{summary['analysis']['success_count']} ok, {summary['analysis']['failure_count']} failed."
    )

    return 0 if summary["analysis"]["failure_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
