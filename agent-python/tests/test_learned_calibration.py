from __future__ import annotations

import csv
import json
from copy import deepcopy

import pytest
from pymongo.errors import ServerSelectionTimeoutError

import evaluation.learned_calibration as learned_calibration
from evaluation.learned_calibration import (
    DATASET_COLUMNS,
    LABEL_COLUMNS,
    MODEL_FEATURE_COLUMNS,
    build_proxy_label_row,
    build_proxy_label_rows,
    build_feasibility_report,
    compute_baseline_metrics,
    export_from_documents,
    extract_calibration_row,
    read_analyzed_cves_from_mongo,
    strict_validation_errors,
    train_learned_calibration_models,
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


def _row(**overrides) -> dict:
    row = {column: "" for column in DATASET_COLUMNS}
    row.update(
        {
            "cve_id": "CVE-2026-LABEL",
            "cvss_score": 5.0,
            "risk_score": 4.0,
            "confidence": 0.45,
            "epss_signal": 0.0,
            "nlp_context_signal": 0.2,
            "recency_signal": 0.2,
            "accepted_urlhaus_count": 0,
            "accepted_dread_count": 0,
            "epss_available": False,
            "kev_status_known": False,
            "kev_listed": False,
            "intrinsic_criticality_floor_applied": False,
        }
    )
    row.update(overrides)
    return row


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
    assert "proxy_label_class_counts" in report
    assert "proxy_binary_counts" in report
    assert "proxy_label_trainability" in report


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
    labels = tmp_path / "learned_calibration_labels.csv"
    report = tmp_path / "learned_calibration_report.json"
    summary = tmp_path / "learned_calibration_summary.md"
    baseline = tmp_path / "learned_calibration_baseline_metrics.json"
    baseline_summary = tmp_path / "learned_calibration_baseline_metrics.md"
    predictions = tmp_path / "learned_calibration_predictions.csv"
    model_report = tmp_path / "learned_calibration_model_report.json"
    model_summary = tmp_path / "learned_calibration_model_summary.md"
    assert result["paths"] == {
        "dataset": str(dataset),
        "labels": str(labels),
        "report": str(report),
        "summary": str(summary),
        "baseline_metrics": str(baseline),
        "baseline_summary": str(baseline_summary),
        "predictions": str(predictions),
        "model_report": str(model_report),
        "model_summary": str(model_summary),
    }
    assert dataset.exists()
    assert labels.exists()
    assert report.exists()
    assert summary.exists()
    assert baseline.exists()
    assert baseline_summary.exists()
    assert predictions.exists()
    assert model_report.exists()
    assert model_summary.exists()
    rows = list(csv.DictReader(dataset.open(encoding="utf-8")))
    assert rows[0]["cve_id"] == "CVE-2026-1234"
    label_rows = list(csv.DictReader(labels.open(encoding="utf-8")))
    assert list(label_rows[0].keys()) == LABEL_COLUMNS
    assert label_rows[0]["cve_id"] == "CVE-2026-1234"
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["analyzed_records_exported"] == 1
    assert payload["proxy_label_class_counts"]["strategy_a"]["high"] == 1
    baseline_payload = json.loads(baseline.read_text(encoding="utf-8"))
    assert baseline_payload["ranking_method"] == "heuristic_risk_score"
    assert "strategy_a" in baseline_payload["strategies"]
    model_payload = json.loads(model_report.read_text(encoding="utf-8"))
    assert model_payload["model_type"] == "LogisticRegression"
    assert model_payload["leakage_guard"]["risk_score_used_as_feature"] is False
    text = summary.read_text(encoding="utf-8")
    assert "Proxy labels are not ground truth" in text
    assert "production `risk_score` behavior is unchanged" in text
    assert "Proxy labels are deterministic thesis-analysis aids" in text


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


def test_proxy_label_strategy_a_intrinsic_known_evidence_rules():
    kev = build_proxy_label_row(_row(kev_listed=True, kev_status_known=True))
    epss = build_proxy_label_row(_row(epss_signal=0.7, epss_available=True))
    intrinsic = build_proxy_label_row(
        _row(cvss_score=9.8, nlp_context_signal=0.8, recency_signal=0.5)
    )
    medium = build_proxy_label_row(_row(cvss_score=7.0))
    low = build_proxy_label_row(_row(cvss_score=4.0, nlp_context_signal=0.1))

    assert kev["proxy_label_strategy_a"] == "high"
    assert epss["proxy_label_strategy_a"] == "high"
    assert intrinsic["proxy_label_strategy_a"] == "high"
    assert medium["proxy_label_strategy_a"] == "medium"
    assert low["proxy_label_strategy_a"] == "low"
    assert intrinsic["proxy_binary_high_strategy_a"] == 1
    assert "intrinsic criticality pattern" in intrinsic["proxy_label_reason"]


def test_proxy_label_strategy_b_sparse_evidence_and_accepted_support():
    sparse = _row()
    accepted = _row(accepted_urlhaus_count=1, confidence=0.62)

    sparse_label = build_proxy_label_row(sparse)
    accepted_label = build_proxy_label_row(accepted)
    report = build_feasibility_report([sparse, accepted], total_records_read=2, generated_at="2026-06-16T00:00:00+03:00")

    assert sparse_label["proxy_label_strategy_b"] == "low"
    assert accepted_label["proxy_label_strategy_b"] == "high"
    assert "accepted external evidence with adequate confidence" in accepted_label["proxy_label_reason"]
    assert report["proxy_label_trainability"]["strategy_b"] == "not_recommended"
    assert "Strategy B is limited by sparse EPSS/KEV" in " ".join(report["warnings"])


def test_proxy_label_strategy_c_conservative_binary_rules():
    high = build_proxy_label_row(
        _row(
            cvss_score=9.8,
            nlp_context_signal=0.9,
            intrinsic_criticality_floor_applied=True,
        )
    )
    not_high = build_proxy_label_row(_row(cvss_score=9.8, nlp_context_signal=0.9))

    assert high["proxy_label_strategy_c"] == "high"
    assert high["proxy_binary_high_strategy_c"] == 1
    assert not_high["proxy_label_strategy_c"] == "not_high"
    assert not_high["proxy_binary_high_strategy_c"] == 0


def test_proxy_label_generation_does_not_mutate_input_rows():
    rows = [_row(cvss_score=9.8, nlp_context_signal=0.8, recency_signal=0.7)]
    before = deepcopy(rows)

    labels = build_proxy_label_rows(rows)

    assert rows == before
    assert labels[0]["proxy_label_strategy_a"] == "high"


def test_baseline_metrics_precision_recall_and_ndcg():
    rows = [
        _row(cve_id="CVE-1", risk_score=0.9),
        _row(cve_id="CVE-2", risk_score=0.8),
        _row(cve_id="CVE-3", risk_score=0.7),
        _row(cve_id="CVE-4", risk_score=0.6),
    ]
    labels = [
        {**build_proxy_label_row(rows[0]), "proxy_binary_high_strategy_a": 1, "proxy_label_strategy_a": "high"},
        {**build_proxy_label_row(rows[1]), "proxy_binary_high_strategy_a": 0, "proxy_label_strategy_a": "low"},
        {**build_proxy_label_row(rows[2]), "proxy_binary_high_strategy_a": 1, "proxy_label_strategy_a": "high"},
        {**build_proxy_label_row(rows[3]), "proxy_binary_high_strategy_a": 0, "proxy_label_strategy_a": "low"},
    ]

    metrics = compute_baseline_metrics(rows, labels, generated_at="2026-06-16T00:00:00+03:00")
    strategy = metrics["strategies"]["strategy_a"]

    assert strategy["precision_at_k"]["10"] == 0.5
    assert strategy["recall_at_k"]["10"] == 1.0
    assert strategy["ndcg_at_k"]["10"] > 0
    assert strategy["high_label_coverage"] == 0.5


def test_baseline_metrics_handle_no_positive_labels():
    rows = [_row(cve_id="CVE-1", risk_score=0.9), _row(cve_id="CVE-2", risk_score=0.8)]
    labels = [
        {**build_proxy_label_row(rows[0]), "proxy_binary_high_strategy_b": 0, "proxy_label_strategy_b": "low"},
        {**build_proxy_label_row(rows[1]), "proxy_binary_high_strategy_b": 0, "proxy_label_strategy_b": "low"},
    ]

    metrics = compute_baseline_metrics(rows, labels, generated_at="2026-06-16T00:00:00+03:00")
    strategy = metrics["strategies"]["strategy_b"]

    assert strategy["status"] == "no_positive_labels"
    assert strategy["precision_at_k"]["10"] is None
    assert strategy["recall_at_k"]["50"] is None
    assert strategy["ndcg_at_k"]["50"] is None


def test_baseline_metrics_use_cve_id_for_tied_score_ordering():
    rows = [_row(cve_id="CVE-B", risk_score=5.0), _row(cve_id="CVE-A", risk_score=5.0)]
    labels = [
        {**build_proxy_label_row(rows[0]), "proxy_binary_high_strategy_a": 0, "proxy_label_strategy_a": "low"},
        {**build_proxy_label_row(rows[1]), "proxy_binary_high_strategy_a": 1, "proxy_label_strategy_a": "high"},
    ]

    metrics = compute_baseline_metrics(rows, labels, generated_at="2026-06-16T00:00:00+03:00")

    assert metrics["strategies"]["strategy_a"]["precision_at_k"]["10"] == 0.5
    assert metrics["strategies"]["strategy_a"]["recall_at_k"]["10"] == 1.0


def test_baseline_metrics_include_bucket_distributions():
    rows = [
        _row(cve_id="CVE-H", risk_score=8.2, risk_level="HIGH", confidence=0.75),
        _row(cve_id="CVE-L", risk_score=3.2, risk_level="LOW", confidence=0.25),
    ]
    labels = [
        {**build_proxy_label_row(rows[0]), "proxy_binary_high_strategy_a": 1, "proxy_label_strategy_a": "high"},
        {**build_proxy_label_row(rows[1]), "proxy_binary_high_strategy_a": 0, "proxy_label_strategy_a": "low"},
    ]

    metrics = compute_baseline_metrics(rows, labels, generated_at="2026-06-16T00:00:00+03:00")
    strategy = metrics["strategies"]["strategy_a"]

    assert strategy["risk_bucket_distribution_by_proxy_class"]["high"]["HIGH"] == 1
    assert strategy["risk_bucket_distribution_by_proxy_class"]["low"]["LOW"] == 1
    assert strategy["confidence_distribution_by_proxy_class"]["high"]["high"] == 1
    assert strategy["confidence_distribution_by_proxy_class"]["low"]["low"] == 1


def test_model_training_skips_when_sklearn_unavailable(monkeypatch):
    monkeypatch.setattr(learned_calibration, "_load_sklearn", lambda: None)
    rows = [_row(cve_id="CVE-1"), _row(cve_id="CVE-2")]
    labels = build_proxy_label_rows(rows)

    result = train_learned_calibration_models(rows, labels, generated_at="2026-06-16T00:00:00+03:00")

    assert result["predictions"] == []
    assert result["report"]["status"] == "skipped"
    assert "scikit-learn is not installed" in result["report"]["skip_reason"]


def test_model_features_exclude_risk_score_and_proxy_labels():
    assert "risk_score" not in MODEL_FEATURE_COLUMNS
    assert all(not feature.startswith("proxy_") for feature in MODEL_FEATURE_COLUMNS)


def test_model_training_single_class_skip_if_sklearn_available():
    pytest.importorskip("sklearn")
    rows = [_row(cve_id=f"CVE-{index}", cvss_score=5.0 + index) for index in range(12)]
    labels = [
        {**build_proxy_label_row(row), "proxy_binary_high_strategy_a": 0, "proxy_label_strategy_a": "low"}
        for row in rows
    ]

    result = train_learned_calibration_models(rows, labels, generated_at="2026-06-16T00:00:00+03:00")

    assert result["report"]["strategies"]["strategy_a"]["status"] == "skipped"
    assert result["report"]["strategies"]["strategy_a"]["skip_reason"] == "single-class proxy labels"


def test_model_training_is_deterministic_if_sklearn_available():
    pytest.importorskip("sklearn")
    rows = [
        _row(
            cve_id=f"CVE-{index:04d}",
            cvss_score=9.8 if index % 2 else 4.0,
            severity_signal=0.98 if index % 2 else 0.4,
            nlp_context_signal=0.9 if index % 2 else 0.2,
            recency_signal=0.8 if index % 2 else 0.1,
            intrinsic_criticality_floor_applied=bool(index % 2),
        )
        for index in range(40)
    ]
    labels = [
        {
            **build_proxy_label_row(row),
            "proxy_binary_high_strategy_a": int(index % 2 == 1),
            "proxy_label_strategy_a": "high" if index % 2 == 1 else "low",
        }
        for index, row in enumerate(rows)
    ]

    first = train_learned_calibration_models(rows, labels, generated_at="2026-06-16T00:00:00+03:00")
    second = train_learned_calibration_models(rows, labels, generated_at="2026-06-16T00:00:00+03:00")

    assert first["predictions"] == second["predictions"]
    assert first["report"]["strategies"]["strategy_a"]["status"] in {"limited", "meaningful"}
