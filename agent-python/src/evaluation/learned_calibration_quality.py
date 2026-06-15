from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Mapping


REQUIRED_FILES = [
    "learned_calibration_dataset.csv",
    "learned_calibration_labels.csv",
    "learned_calibration_report.json",
    "learned_calibration_summary.md",
    "learned_calibration_baseline_metrics.json",
    "learned_calibration_model_report.json",
    "learned_calibration_leakage_checks.json",
    "learned_calibration_manifest.json",
    "learned_calibration_thesis_section.md",
    "learned_calibration_limitations.md",
]

JSON_FILES = [
    "learned_calibration_report.json",
    "learned_calibration_baseline_metrics.json",
    "learned_calibration_model_report.json",
    "learned_calibration_leakage_checks.json",
    "learned_calibration_manifest.json",
    "learned_calibration_tables.json",
]

CSV_HEADERS = {
    "learned_calibration_dataset.csv": {"cve_id", "risk_score", "confidence", "severity_signal"},
    "learned_calibration_labels.csv": {"cve_id", "proxy_label_strategy_a", "proxy_binary_high_strategy_a"},
    "learned_calibration_ablation.csv": {"strategy", "ablation", "status", "features"},
    "learned_calibration_case_studies.csv": {"cve_id", "case_group", "key_reason"},
}

MARKDOWN_LIMITATION_FILES = [
    "learned_calibration_summary.md",
    "learned_calibration_thesis_section.md",
    "learned_calibration_limitations.md",
    "learned_calibration_leakage_checks.md",
]

UNSAFE_CLAIMS = [
    "real-world supervised exploitation proof",
    "proves real-world exploitation",
    "production scoring was replaced",
]


def validate_learned_calibration_artifacts(artifact_dir: str | Path) -> dict[str, Any]:
    root = Path(artifact_dir)
    checks: list[dict[str, str]] = []
    for filename in REQUIRED_FILES:
        checks.append(_check(filename, (root / filename).exists(), "required artifact exists"))
    for filename in JSON_FILES:
        checks.append(_check(filename, _json_parseable(root / filename), "json artifact is parseable"))
    for filename, required_headers in CSV_HEADERS.items():
        checks.append(_check(filename, _csv_has_headers(root / filename, required_headers), f"csv headers include {sorted(required_headers)}"))
    combined_markdown = "\n".join(_read_text(root / filename) for filename in MARKDOWN_LIMITATION_FILES)
    checks.append(_check("markdown", "experimental" in combined_markdown.lower(), "describes learned calibration as experimental"))
    checks.append(_check("markdown", "not ground truth" in combined_markdown.lower(), "states proxy labels are not ground truth"))
    checks.append(_check("markdown", "production `risk_score`" in combined_markdown.lower() or "production risk score" in combined_markdown.lower(), "states production risk score is unchanged"))
    checks.append(_check("markdown", "evidence gates" in combined_markdown.lower(), "states evidence gates are unchanged"))
    for claim in UNSAFE_CLAIMS:
        checks.append(_check("unsafe_claims", claim not in combined_markdown.lower(), f"does not contain unsafe claim: {claim}"))
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {"artifact_dir": str(root), "status": status, "checks": checks}


def write_quality_report(report: Mapping[str, Any], artifact_dir: str | Path) -> dict[str, str]:
    root = Path(artifact_dir)
    json_path = root / "learned_calibration_quality_report.json"
    md_path = root / "learned_calibration_quality_report.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    md_path.write_text(render_quality_report_markdown(report), encoding="utf-8")
    return {"json": str(json_path), "markdown": str(md_path)}


def render_quality_report_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Quality Report",
        "",
        f"- Status: `{report.get('status', '')}`",
        "",
        "| File | Status | Details |",
        "| --- | --- | --- |",
    ]
    for check in report.get("checks") or []:
        lines.append(f"| {check.get('file', '')} | {check.get('status', '')} | {check.get('details', '')} |")
    lines.append("")
    return "\n".join(lines)


def _check(filename: str, passed: bool, details: str) -> dict[str, str]:
    return {"file": filename, "status": "passed" if passed else "failed", "details": details}


def _json_parseable(path: Path) -> bool:
    try:
        json.loads(path.read_text(encoding="utf-8"))
        return True
    except Exception:
        return False


def _csv_has_headers(path: Path, required_headers: set[str]) -> bool:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            return required_headers.issubset(set(reader.fieldnames or []))
    except Exception:
        return False


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate learned-calibration thesis artifacts.")
    parser.add_argument("--artifact-dir", default="../reports/thesis")
    args = parser.parse_args()
    report = validate_learned_calibration_artifacts(args.artifact_dir)
    paths = write_quality_report(report, args.artifact_dir)
    print(json.dumps({"status": report["status"], **paths}, indent=2))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
