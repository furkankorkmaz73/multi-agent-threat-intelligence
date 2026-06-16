from __future__ import annotations

import json

from evaluation.learned_calibration_quality import (
    CSV_HEADERS,
    JSON_FILES,
    MARKDOWN_LIMITATION_FILES,
    REQUIRED_FILES,
    validate_learned_calibration_artifacts,
    write_quality_report,
)


def _write_minimal_bundle(tmp_path):
    for filename in REQUIRED_FILES:
        path = tmp_path / filename
        if filename.endswith(".json"):
            path.write_text("{}", encoding="utf-8")
        elif filename.endswith(".csv"):
            headers = CSV_HEADERS.get(filename, {"cve_id"})
            path.write_text(",".join(sorted(headers)) + "\n", encoding="utf-8")
        else:
            path.write_text("", encoding="utf-8")
    for filename in JSON_FILES:
        (tmp_path / filename).write_text("{}", encoding="utf-8")
    for filename, headers in CSV_HEADERS.items():
        (tmp_path / filename).write_text(",".join(sorted(headers)) + "\n", encoding="utf-8")
    safe_text = (
        "This learned calibration experiment is experimental. "
        "Proxy labels are not ground truth. "
        "Production `risk_score` is unchanged. "
        "Evidence gates are unchanged."
    )
    for filename in MARKDOWN_LIMITATION_FILES:
        (tmp_path / filename).write_text(safe_text, encoding="utf-8")


def test_learned_calibration_quality_gate_passes_on_minimal_bundle(tmp_path):
    _write_minimal_bundle(tmp_path)

    report = validate_learned_calibration_artifacts(tmp_path)
    paths = write_quality_report(report, tmp_path)

    assert report["status"] == "passed"
    assert json.loads((tmp_path / "learned_calibration_quality_report.json").read_text(encoding="utf-8"))["status"] == "passed"
    assert (tmp_path / "learned_calibration_quality_report.md").exists()
    assert paths["json"].endswith("learned_calibration_quality_report.json")


def test_learned_calibration_quality_gate_fails_missing_file(tmp_path):
    _write_minimal_bundle(tmp_path)
    (tmp_path / "learned_calibration_dataset.csv").unlink()

    report = validate_learned_calibration_artifacts(tmp_path)

    assert report["status"] == "failed"
    assert any(check["file"] == "learned_calibration_dataset.csv" and check["status"] == "failed" for check in report["checks"])


def test_learned_calibration_quality_gate_fails_bad_csv_header(tmp_path):
    _write_minimal_bundle(tmp_path)
    (tmp_path / "learned_calibration_labels.csv").write_text("cve_id\n", encoding="utf-8")

    report = validate_learned_calibration_artifacts(tmp_path)

    assert report["status"] == "failed"
    assert any(check["file"] == "learned_calibration_labels.csv" and check["status"] == "failed" for check in report["checks"])


def test_learned_calibration_quality_gate_fails_unsafe_claim(tmp_path):
    _write_minimal_bundle(tmp_path)
    (tmp_path / "learned_calibration_thesis_section.md").write_text(
        "This experimental section says proxy labels are not ground truth. "
        "Production `risk_score` is unchanged. Evidence gates are unchanged. "
        "It proves real-world exploitation.",
        encoding="utf-8",
    )

    report = validate_learned_calibration_artifacts(tmp_path)

    assert report["status"] == "failed"
    assert any(check["file"] == "unsafe_claims" and check["status"] == "failed" for check in report["checks"])
