from __future__ import annotations

import csv
import json
from copy import deepcopy

import pytest
from pymongo.errors import ServerSelectionTimeoutError

import evaluation.learned_calibration as learned_calibration
from evaluation.learned_calibration import (
    DATASET_COLUMNS,
    build_feasibility_report,
    export_from_documents,
    extract_calibration_row,
    read_analyzed_cves_from_mongo,
    strict_validation_errors,
)


def _synthetic_doc() -> dict:
    return {
        "_id": "CVE-2026-1234",
        "analysis": {
            "entity_id": "CVE-2026-1234",
            "risk_score": 8.1,
            "risk_level": "HIGH",
            "confidence": 0.61,
            "evidence": {
                "cvss_score": 10.0,
                "related_urlhaus_count": 1,
                "related_dread_count": 0,
                "candidate_urlhaus_count": 3,
                "candidate_dread_count": 0,
                "epss_available": True,
                "kev_status_known": True,
                "kev_listed": False,
                "age_days": 5,
                "urlhaus_match_stats": {
                    "raw_candidate_count": 3,
                    "ignored_low_signal_count": 2,
                    "rejected_match_count": 1,
                },
            },
            "feature_breakdown": {
                "severity_signal": 1.0,
                "epss_signal": 0.42,
                "kev_signal": 0.0,
                "recency_signal": 0.8,
                "correlation_signal": 0.2,
                "graph_signal": 0.0,
                "nlp_context_signal": 1.0,
                "score_before_intrinsic_floor": 7.8,
                "intrinsic_criticality_floor_applied": True,
            },
            "confidence_breakdown": {
                "assessment_confidence": 0.64,
                "data_completeness": 0.72,
                "coverage_limitations": ["no_kev_listing"],
            },
        },
    }


def test_extract_calibration_row_from_synthetic_analyzed_cve():
    row = extract_calibration_row(_synthetic_doc())

    assert row is not None
    assert list(row.keys()) == DATASET_COLUMNS
    assert row["cve_id"] == "CVE-2026-1234"
    assert row["cvss_score"] == 10.0
    assert row["risk_score"] == 8.1
    assert row["accepted_urlhaus_count"] == 1
    assert row["urlhaus_raw_candidate_count"] == 3
    assert row["urlhaus_ignored_low_signal_count"] == 2
    assert row["assessment_confidence"] == 0.64
    assert row["coverage_limitations"] == "no_kev_listing"


def test_extract_calibration_row_does_not_mutate_input_document():
    doc = _synthetic_doc()
    before = deepcopy(doc)

    _ = extract_calibration_row(doc)

    assert doc == before


def test_extract_calibration_row_supports_legacy_top_level_shape():
    doc = {
        "_id": "CVE-2026-0002",
        "risk_score": 6.9,
        "risk_level": "MEDIUM",
        "confidence": 0.58,
        "evidence": {
            "cvss_score": 8.8,
            "related_urlhaus_count": 0,
            "candidate_urlhaus_count": 4,
            "urlhaus_match_stats": {
                "raw_candidate_count": 4,
                "ignored_low_signal_count": 3,
                "rejected_match_count": 1,
            },
            "epss_available": False,
            "kev_status_known": False,
            "age_days": 22,
        },
        "features": {
            "severity_signal": 0.88,
            "epss_signal": 0.0,
            "kev_signal": 0.0,
            "recency_signal": 0.7,
            "correlation_signal": 0.0,
            "graph_signal": 0.0,
            "nlp_context_signal": 0.8,
        },
        "confidence_breakdown": {
            "assessment_confidence": 0.6,
            "data_completeness": 0.35,
            "coverage_limitations": ["epss_unavailable", "kev_status_unknown"],
        },
    }

    row = extract_calibration_row(doc)

    assert row is not None
    assert row["cve_id"] == "CVE-2026-0002"
    assert row["risk_score"] == 6.9
    assert row["cvss_score"] == 8.8
    assert row["severity_signal"] == 0.88
    assert row["urlhaus_raw_candidate_count"] == 4
    assert row["urlhaus_ignored_low_signal_count"] == 3
    assert row["coverage_limitations"] == "epss_unavailable;kev_status_unknown"


def test_feasibility_report_from_synthetic_rows():
    rows = [extract_calibration_row(_synthetic_doc()) for _ in range(3)]

    report = build_feasibility_report(rows, total_records_read=5, generated_at="2026-06-16T00:00:00+03:00")

    assert report["total_cve_records_read"] == 5
    assert report["analyzed_records_exported"] == 3
    assert report["records_with_cvss"] == 3
    assert report["epss_availability_count"] == 3
    assert report["kev_known_count"] == 3
    assert report["urlhaus_accepted_count"] == 3
    assert report["dread_accepted_count"] == 0
    assert report["intrinsic_criticality_floor_count"] == 3
    assert report["proxy_supervised_learning_feasibility"] == "not_recommended"
    assert "missing_feature_counts" in report
    assert "missing_feature_accounting" in report
    assert "missing_feature_percentages" in report
    assert "coverage" in report
    assert report["dataset_columns"] == DATASET_COLUMNS


def test_feasibility_report_accounts_for_missing_features():
    row = {column: "" for column in DATASET_COLUMNS}
    row["cve_id"] = "CVE-2026-MISSING"
    row["risk_score"] = 4.1

    report = build_feasibility_report([row], total_records_read=1, generated_at="2026-06-16T00:00:00+03:00")

    assert report["missing_feature_counts"]["risk_score"] == 0
    assert report["missing_feature_counts"]["cvss_score"] == 1
    assert report["missing_feature_percentages"]["cvss_score"] == 1.0
    assert report["missing_feature_accounting"]["counts"]["cvss_score"] == 1
    assert strict_validation_errors(report) == ["No exported records include CVSS scores."]


def test_export_writes_three_output_files(tmp_path):
    docs = [_synthetic_doc()]

    result = export_from_documents(docs, tmp_path, generated_at="2026-06-16T00:00:00+03:00")

    dataset = tmp_path / "learned_calibration_dataset.csv"
    report = tmp_path / "learned_calibration_report.json"
    summary = tmp_path / "learned_calibration_summary.md"
    assert result["paths"] == {
        "dataset": str(dataset),
        "report": str(report),
        "summary": str(summary),
    }
    assert dataset.exists()
    assert report.exists()
    assert summary.exists()
    rows = list(csv.DictReader(dataset.open(encoding="utf-8")))
    assert rows[0]["cve_id"] == "CVE-2026-1234"
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["analyzed_records_exported"] == 1
    text = summary.read_text(encoding="utf-8")
    assert "Proxy labels are not ground truth" in text
    assert "production `risk_score` behavior is unchanged" in text


def test_export_sorts_rows_by_cve_id(tmp_path):
    first = _synthetic_doc()
    first["_id"] = "CVE-2026-2000"
    first["analysis"]["entity_id"] = "CVE-2026-2000"
    second = _synthetic_doc()
    second["_id"] = "CVE-2026-1000"
    second["analysis"]["entity_id"] = "CVE-2026-1000"

    export_from_documents([first, second], tmp_path, generated_at="2026-06-16T00:00:00+03:00")

    rows = list(csv.DictReader((tmp_path / "learned_calibration_dataset.csv").open(encoding="utf-8")))
    assert [row["cve_id"] for row in rows] == ["CVE-2026-1000", "CVE-2026-2000"]


def test_mongodb_unavailable_error_is_clear(monkeypatch):
    class FailingAdmin:
        def command(self, _name):
            raise ServerSelectionTimeoutError("connection refused")

    class FailingClient:
        admin = FailingAdmin()

    monkeypatch.setattr(learned_calibration.pymongo, "MongoClient", lambda *args, **kwargs: FailingClient())

    with pytest.raises(RuntimeError, match="MongoDB is unavailable for learned calibration export"):
        read_analyzed_cves_from_mongo()
