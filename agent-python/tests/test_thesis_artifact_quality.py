import csv
import json
from pathlib import Path

import pytest

from evaluation.thesis_artifact_quality import ArtifactQualityError, _unsafe_claims, validate_thesis_artifacts
from evaluation.thesis_artifacts import generate_thesis_artifacts
from integration.thesis_scenario import run_thesis_scenario


def _generate_bundle(tmp_path: Path) -> Path:
    report_path = tmp_path / "scenario.json"
    output_dir = tmp_path / "thesis"
    run_thesis_scenario(report_path)
    generate_thesis_artifacts(scenario_report_path=report_path, output_dir=output_dir)
    return output_dir


def _quality_errors(output_dir: Path) -> list[str]:
    with pytest.raises(ArtifactQualityError) as exc_info:
        validate_thesis_artifacts(output_dir)
    return exc_info.value.errors


def _rewrite_manifest(output_dir: Path, payload: dict) -> None:
    (output_dir / "manifest.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _remove_csv_column(path: Path, column: str) -> None:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
        fieldnames = [field for field in (rows[0].keys() if rows else []) if field != column]

    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fieldnames})


def test_thesis_artifact_quality_gate_passes_on_generated_bundle(tmp_path):
    output_dir = _generate_bundle(tmp_path)

    summary = validate_thesis_artifacts(output_dir)

    assert summary["status"] == "passed"
    assert summary["artifact_dir"] == str(output_dir)
    assert summary["checked_files"] >= 16
    assert summary["checked_markdown_files"] >= 8


def test_quality_gate_fails_when_manifest_entry_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    manifest_path = output_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["generated_files"]["scoring_summary"]
    _rewrite_manifest(output_dir, manifest)

    errors = _quality_errors(output_dir)

    assert any("manifest missing generated_files keys" in error for error in errors)
    assert any("scoring_summary" in error for error in errors)


def test_quality_gate_fails_when_listed_file_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    (output_dir / "benchmark_summary.csv").unlink()

    errors = _quality_errors(output_dir)

    assert any("manifest listed file does not exist" in error for error in errors)
    assert any("benchmark_summary" in error for error in errors)


def test_quality_gate_fails_on_malformed_markdown_regression_string(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    markdown_path = output_dir / "methodology_summary.md"
    markdown_path.write_text(
        markdown_path.read_text(encoding="utf-8") + "\nboundedperturbation\nDeterministicanalysis\n",
        encoding="utf-8",
    )

    errors = _quality_errors(output_dir)

    assert any("contains malformed text: boundedperturbation" in error for error in errors)
    assert any("contains malformed text: deterministicanalysis" in error for error in errors)


def test_quality_gate_fails_on_unsafe_generated_claim(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    markdown_path = output_dir / "thesis_defense_pack.md"
    markdown_path.write_text(
        markdown_path.read_text(encoding="utf-8")
        + "\nThis system is production-ready for operational SOC deployment.\n",
        encoding="utf-8",
    )

    errors = _quality_errors(output_dir)

    assert any("contains unsafe thesis claim: production-ready" in error for error in errors)


def test_unsafe_claim_detection_rejects_claim_suffix_bypass():
    assert _unsafe_claims("The system makes production-ready claims.") == ["production-ready"]


def test_unsafe_claim_detection_allows_negated_and_question_framing():
    text = "\n".join(
        [
            "It does not claim deployment readiness for SOC operations.",
            "It is not a fully autonomous LLM-agent system.",
            "### Is this a fully autonomous multi-agent system?",
        ]
    )

    assert _unsafe_claims(text) == []


def test_quality_gate_fails_when_new_artifact_heading_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    markdown_path = output_dir / "limitations_and_validity.md"
    markdown_path.write_text(
        markdown_path.read_text(encoding="utf-8").replace("## Graph Persistence Limitation\n", ""),
        encoding="utf-8",
    )

    errors = _quality_errors(output_dir)

    assert any("limitations_and_validity.md missing required headings" in error for error in errors)
    assert any("## Graph Persistence Limitation" in error for error in errors)


def test_quality_gate_fails_when_methodology_safe_framing_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    markdown_path = output_dir / "methodology_summary.md"
    markdown_path.write_text(
        markdown_path.read_text(encoding="utf-8").replace("not a live CTI benchmark", "not a benchmark"),
        encoding="utf-8",
    )

    errors = _quality_errors(output_dir)

    assert any("methodology_summary.md missing safe methodology framing" in error for error in errors)
    assert any("not a live CTI benchmark" in error for error in errors)


def test_quality_gate_fails_on_inconsistent_markdown_table(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    markdown_path = output_dir / "methodology_summary.md"
    markdown_path.write_text(
        markdown_path.read_text(encoding="utf-8")
        + "\n| A | B |\n| --- | --- |\n| one |\n",
        encoding="utf-8",
    )

    errors = _quality_errors(output_dir)

    assert any("table has inconsistent pipe counts" in error for error in errors)


def test_quality_gate_fails_when_required_case_study_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    case_path = output_dir / "case_studies.json"
    payload = json.loads(case_path.read_text(encoding="utf-8"))
    payload["cases"] = [
        item for item in payload["cases"]
        if item.get("case") != "stale_low_risk"
    ]
    case_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    errors = _quality_errors(output_dir)

    assert any("case_studies.json missing required cases" in error for error in errors)
    assert any("stale_low_risk" in error for error in errors)


def test_quality_gate_fails_when_required_trace_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    trace_path = output_dir / "risk_explanation_traces.json"
    payload = json.loads(trace_path.read_text(encoding="utf-8"))
    payload["traces"] = [
        item for item in payload["traces"]
        if item.get("cve_id") != "CVE-2015-0001"
    ]
    trace_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    errors = _quality_errors(output_dir)

    assert any("risk_explanation_traces.json missing required CVEs" in error for error in errors)
    assert any("CVE-2015-0001" in error for error in errors)


def test_quality_gate_fails_when_required_trace_field_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    trace_path = output_dir / "risk_explanation_traces.json"
    payload = json.loads(trace_path.read_text(encoding="utf-8"))
    for trace in payload["traces"]:
        if trace.get("cve_id") == "CVE-2026-9017":
            del trace["explanation"]
            break
    trace_path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    errors = _quality_errors(output_dir)

    assert any("risk trace CVE-2026-9017 missing fields" in error for error in errors)
    assert any("explanation" in error for error in errors)


def test_quality_gate_fails_when_required_correlation_column_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    _remove_csv_column(output_dir / "correlation_decisions.csv", "evidence_gate_passed")

    errors = _quality_errors(output_dir)

    assert any("correlation_decisions.csv missing required columns" in error for error in errors)
    assert any("evidence_gate_passed" in error for error in errors)


def test_quality_gate_fails_when_required_sensitivity_column_is_missing(tmp_path):
    output_dir = _generate_bundle(tmp_path)
    _remove_csv_column(output_dir / "scoring_sensitivity.csv", "guardrails_passed")

    errors = _quality_errors(output_dir)

    assert any("scoring_sensitivity.csv missing required columns" in error for error in errors)
    assert any("guardrails_passed" in error for error in errors)
