from __future__ import annotations

import csv
import json
from copy import deepcopy

import pytest
from pymongo.errors import ServerSelectionTimeoutError

import evaluation.learned_calibration as learned_calibration
from evaluation.learned_calibration import (
    ABLATION_COLUMNS,
    CASE_STUDY_COLUMNS,
    DATASET_COLUMNS,
    DISAGREEMENT_COLUMNS,
    FEATURE_IMPORTANCE_COLUMNS,
    LABEL_COLUMNS,
    MODEL_FEATURE_COLUMNS,
    ablation_plan,
    build_proxy_label_row,
    build_proxy_label_rows,
    build_leakage_checks,
    build_learned_calibration_manifest,
    build_publication_tables,
    build_feasibility_report,
    compute_baseline_metrics,
    compute_disagreement_cases,
    compute_learned_vs_heuristic_comparison,
    compute_proxy_threshold_sensitivity,
    compute_ablation_experiments,
    export_from_documents,
    extract_feature_importance,
    model_registry,
    extract_calibration_row,
    proxy_threshold_grid,
    read_analyzed_cves_from_mongo,
    select_case_studies,
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
    comparison = tmp_path / "learned_vs_heuristic_comparison.json"
    comparison_summary = tmp_path / "learned_vs_heuristic_comparison.md"
    disagreements = tmp_path / "learned_calibration_disagreements.csv"
    disagreements_summary = tmp_path / "learned_calibration_disagreements.md"
    importance = tmp_path / "learned_calibration_feature_importance.csv"
    importance_summary = tmp_path / "learned_calibration_feature_importance.md"
    ablation = tmp_path / "learned_calibration_ablation.csv"
    ablation_summary = tmp_path / "learned_calibration_ablation.md"
    leakage = tmp_path / "learned_calibration_leakage_checks.json"
    leakage_summary = tmp_path / "learned_calibration_leakage_checks.md"
    thesis_section = tmp_path / "learned_calibration_thesis_section.md"
    limitations = tmp_path / "learned_calibration_limitations.md"
    case_studies = tmp_path / "learned_calibration_case_studies.csv"
    case_studies_summary = tmp_path / "learned_calibration_case_studies.md"
    tables = tmp_path / "learned_calibration_tables.json"
    tables_summary = tmp_path / "learned_calibration_tables.md"
    proxy_sensitivity = tmp_path / "learned_calibration_proxy_sensitivity.csv"
    proxy_sensitivity_json = tmp_path / "learned_calibration_proxy_sensitivity.json"
    proxy_sensitivity_summary = tmp_path / "learned_calibration_proxy_sensitivity.md"
    manifest = tmp_path / "learned_calibration_manifest.json"
    manifest_summary = tmp_path / "learned_calibration_manifest.md"
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
        "learned_vs_heuristic_comparison": str(comparison),
        "learned_vs_heuristic_summary": str(comparison_summary),
        "disagreements": str(disagreements),
        "disagreements_summary": str(disagreements_summary),
        "feature_importance": str(importance),
        "feature_importance_summary": str(importance_summary),
        "ablation": str(ablation),
        "ablation_summary": str(ablation_summary),
        "leakage_checks": str(leakage),
        "leakage_checks_summary": str(leakage_summary),
        "thesis_section": str(thesis_section),
        "limitations": str(limitations),
        "case_studies": str(case_studies),
        "case_studies_summary": str(case_studies_summary),
        "tables": str(tables),
        "tables_summary": str(tables_summary),
        "proxy_sensitivity": str(proxy_sensitivity),
        "proxy_sensitivity_json": str(proxy_sensitivity_json),
        "proxy_sensitivity_summary": str(proxy_sensitivity_summary),
        "manifest": str(manifest),
        "manifest_summary": str(manifest_summary),
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
    assert comparison.exists()
    assert comparison_summary.exists()
    assert disagreements.exists()
    assert disagreements_summary.exists()
    assert importance.exists()
    assert importance_summary.exists()
    assert ablation.exists()
    assert ablation_summary.exists()
    assert leakage.exists()
    assert leakage_summary.exists()
    assert thesis_section.exists()
    assert limitations.exists()
    assert case_studies.exists()
    assert case_studies_summary.exists()
    assert tables.exists()
    assert tables_summary.exists()
    assert proxy_sensitivity.exists()
    assert proxy_sensitivity_json.exists()
    assert proxy_sensitivity_summary.exists()
    assert manifest.exists()
    assert manifest_summary.exists()
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
    assert "random_forest" in model_payload["model_registry"]
    comparison_payload = json.loads(comparison.read_text(encoding="utf-8"))
    assert comparison_payload["status"] in {"completed", "skipped"}
    disagreement_rows = list(csv.DictReader(disagreements.open(encoding="utf-8")))
    if disagreement_rows:
        assert list(disagreement_rows[0].keys()) == DISAGREEMENT_COLUMNS
    importance_rows = list(csv.DictReader(importance.open(encoding="utf-8")))
    if importance_rows:
        assert list(importance_rows[0].keys()) == FEATURE_IMPORTANCE_COLUMNS
    ablation_rows = list(csv.DictReader(ablation.open(encoding="utf-8")))
    assert list(ablation_rows[0].keys()) == ABLATION_COLUMNS
    leakage_payload = json.loads(leakage.read_text(encoding="utf-8"))
    assert leakage_payload["status"] == "passed"
    thesis_text = thesis_section.read_text(encoding="utf-8")
    limitations_text = limitations.read_text(encoding="utf-8")
    assert "not ground truth exploitation outcomes" in thesis_text
    assert "production risk score remains heuristic" in thesis_text
    assert "does not replace the deterministic scoring engine" in limitations_text
    case_study_rows = list(csv.DictReader(case_studies.open(encoding="utf-8")))
    if case_study_rows:
        assert list(case_study_rows[0].keys()) == CASE_STUDY_COLUMNS
    table_payload = json.loads(tables.read_text(encoding="utf-8"))
    assert "dataset_coverage_summary" in table_payload
    assert "artifact_inventory" in table_payload
    proxy_payload = json.loads(proxy_sensitivity_json.read_text(encoding="utf-8"))
    assert proxy_payload["grid_size"] == 320
    manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
    assert manifest_payload["status"] == "complete"
    assert any(item["group"] == "dataset" for item in manifest_payload["artifacts"])
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
    assert result["report"]["alternative_models"]["dummy"]["status"] == "skipped"


def test_model_features_exclude_risk_score_and_proxy_labels():
    assert "risk_score" not in MODEL_FEATURE_COLUMNS
    assert all(not feature.startswith("proxy_") for feature in MODEL_FEATURE_COLUMNS)


def test_model_registry_reports_unavailable_models_without_sklearn():
    registry = model_registry(None)

    assert registry["random_forest"]["available"] is False
    assert registry["hist_gradient_boosting"]["available"] is False
    assert registry["dummy"]["available"] is False


def test_model_registry_uses_fixed_random_seed_for_available_models():
    registry = model_registry(
        {
            "LogisticRegression": object,
            "RandomForestClassifier": object,
            "HistGradientBoostingClassifier": object,
            "DummyClassifier": object,
        }
    )

    assert registry["random_forest"]["available"] is True
    assert registry["hist_gradient_boosting"]["random_seed"] == 42
    assert registry["dummy"]["random_seed"] == 42


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


def test_learned_vs_heuristic_comparison_top_k_overlap_and_metrics():
    rows = [
        _row(cve_id="CVE-1", risk_score=0.9, severity_signal=0.9),
        _row(cve_id="CVE-2", risk_score=0.8, severity_signal=0.8),
        _row(cve_id="CVE-3", risk_score=0.7, severity_signal=0.7),
    ]
    labels = [
        {**build_proxy_label_row(rows[0]), "proxy_binary_high_strategy_a": 1, "proxy_label_strategy_a": "high"},
        {**build_proxy_label_row(rows[1]), "proxy_binary_high_strategy_a": 0, "proxy_label_strategy_a": "low"},
        {**build_proxy_label_row(rows[2]), "proxy_binary_high_strategy_a": 1, "proxy_label_strategy_a": "high"},
    ]
    predictions = [
        {"cve_id": "CVE-3", "strategy": "strategy_a", "learned_probability": 0.95},
        {"cve_id": "CVE-1", "strategy": "strategy_a", "learned_probability": 0.9},
        {"cve_id": "CVE-2", "strategy": "strategy_a", "learned_probability": 0.1},
    ]

    comparison = compute_learned_vs_heuristic_comparison(
        rows, labels, predictions, generated_at="2026-06-16T00:00:00+03:00"
    )
    strategy = comparison["strategies"]["strategy_a"]

    assert strategy["status"] == "evaluated"
    assert strategy["top_k_overlap"]["10"]["count"] == 3
    assert strategy["learned_metrics"]["precision_at_k"]["10"] == 0.6667
    assert strategy["heuristic_metrics"]["precision_at_k"]["10"] == 0.6667
    assert strategy["spearman_like_rank_correlation"] is not None


def test_learned_vs_heuristic_comparison_extracts_rank_difference_cases():
    rows = [
        _row(cve_id="CVE-LOW", risk_score=1.0, cvss_score=4.0),
        _row(cve_id="CVE-HIGH", risk_score=9.0, cvss_score=9.8),
        _row(cve_id="CVE-MID", risk_score=5.0, cvss_score=6.0),
    ]
    labels = build_proxy_label_rows(rows)
    predictions = [
        {"cve_id": "CVE-LOW", "strategy": "strategy_a", "learned_probability": 0.99},
        {"cve_id": "CVE-MID", "strategy": "strategy_a", "learned_probability": 0.5},
        {"cve_id": "CVE-HIGH", "strategy": "strategy_a", "learned_probability": 0.01},
    ]

    comparison = compute_learned_vs_heuristic_comparison(
        rows, labels, predictions, generated_at="2026-06-16T00:00:00+03:00"
    )
    strategy = comparison["strategies"]["strategy_a"]

    assert strategy["learned_ranks_much_higher"][0]["cve_id"] == "CVE-LOW"
    assert strategy["heuristic_ranks_much_higher"][0]["cve_id"] == "CVE-HIGH"
    assert strategy["learned_ranks_much_higher"][0]["rank_delta"] > 0
    assert strategy["heuristic_ranks_much_higher"][0]["rank_delta"] < 0


def test_learned_vs_heuristic_comparison_skips_without_predictions():
    rows = [_row(cve_id="CVE-1", risk_score=0.9)]
    labels = build_proxy_label_rows(rows)

    comparison = compute_learned_vs_heuristic_comparison(
        rows, labels, [], generated_at="2026-06-16T00:00:00+03:00"
    )

    assert comparison["status"] == "skipped"
    assert comparison["strategies"]["strategy_a"]["status"] == "skipped"
    assert comparison["strategies"]["strategy_a"]["skip_reason"] == "no learned predictions available for this strategy"


def test_disagreement_cases_include_expected_categories_and_reasons():
    rows = [
        _row(
            cve_id="CVE-HIGH",
            cvss_score=10.0,
            risk_score=8.2,
            risk_level="HIGH",
            confidence=0.35,
            severity_signal=1.0,
            nlp_context_signal=0.9,
            intrinsic_criticality_floor_applied=True,
            coverage_limitations="epss_unavailable;kev_status_unknown",
        ),
        _row(
            cve_id="CVE-LEARNED",
            cvss_score=5.0,
            risk_score=4.0,
            risk_level="MEDIUM",
            confidence=0.3,
            coverage_limitations="no_accepted_external_evidence",
        ),
    ]
    labels = build_proxy_label_rows(rows)
    predictions = [
        {"cve_id": "CVE-HIGH", "strategy": "strategy_a", "learned_probability": 0.2},
        {"cve_id": "CVE-LEARNED", "strategy": "strategy_a", "learned_probability": 0.95},
    ]

    cases = compute_disagreement_cases(rows, labels, predictions)
    by_type = {case["disagreement_type"]: case for case in cases}

    assert by_type["heuristic_high_learned_low"]["cve_id"] == "CVE-HIGH"
    assert "heuristic risk is high" in by_type["heuristic_high_learned_low"]["reason"]
    assert by_type["cvss_10_learned_probability_not_high"]["cve_id"] == "CVE-HIGH"
    assert by_type["intrinsic_floor_applied_learned_probability_low"]["cve_id"] == "CVE-HIGH"
    assert by_type["learned_high_heuristic_medium_low"]["cve_id"] == "CVE-LEARNED"
    assert by_type["low_confidence_high_learned_probability"]["cve_id"] == "CVE-LEARNED"


def test_disagreement_cases_limit_examples_per_category():
    rows = [
        _row(cve_id=f"CVE-{index}", risk_score=8.0, risk_level="HIGH", cvss_score=9.8)
        for index in range(10)
    ]
    labels = build_proxy_label_rows(rows)
    predictions = [
        {"cve_id": row["cve_id"], "strategy": "strategy_a", "learned_probability": 0.1}
        for row in rows
    ]

    cases = compute_disagreement_cases(rows, labels, predictions, max_examples_per_category=3)
    high_low = [case for case in cases if case["disagreement_type"] == "heuristic_high_learned_low"]

    assert len(high_low) == 3


def test_disagreement_cases_empty_when_predictions_unavailable():
    rows = [_row(cve_id="CVE-1")]
    labels = build_proxy_label_rows(rows)

    assert compute_disagreement_cases(rows, labels, []) == []


def test_feature_importance_extracts_and_sorts_coefficients():
    report = {
        "strategies": {
            "strategy_a": {
                "status": "limited",
                "coefficients": {
                    "severity_signal": 0.2,
                    "epss_signal": -1.3,
                    "recency_signal": 0.7,
                },
            }
        }
    }

    rows = [_row(epss_signal=0.4, severity_signal=1.0, recency_signal=0.8)]
    importance = extract_feature_importance(report, rows)

    assert [row["feature"] for row in importance] == ["epss_signal", "recency_signal", "severity_signal"]
    assert importance[0]["absolute_coefficient_rank"] == 1
    assert importance[0]["sign_interpretation"] == "negative association with high proxy label"
    assert importance[0]["feature_coverage_note"] == "available for all exported rows"


def test_feature_importance_skips_without_coefficients():
    report = {"strategies": {"strategy_a": {"status": "skipped"}}}

    assert extract_feature_importance(report, [_row()]) == []


def test_ablation_plan_contains_expected_variants_and_excludes_risk_score():
    names = [item["name"] for item in ablation_plan()]

    assert names == [
        "all_features",
        "no_cvss_severity",
        "no_recency",
        "no_nlp_context",
        "no_confidence_data_completeness",
        "no_intrinsic_floor_flag",
        "evidence_only",
        "signals_only",
        "metadata_context_only",
    ]
    assert all("risk_score" not in item["features"] for item in ablation_plan())


def test_ablation_experiments_skip_when_model_not_completed():
    report = {"status": "skipped", "skip_reason": "scikit-learn unavailable"}

    rows = compute_ablation_experiments(report)

    assert len(rows) == 27
    assert all(row["status"] == "skipped" for row in rows)
    assert rows[0]["skip_reason"] == "scikit-learn unavailable"
    assert set(rows[0].keys()) == set(ABLATION_COLUMNS)


def test_ablation_experiments_emit_metric_table_shape_for_completed_report():
    report = {
        "status": "completed",
        "strategies": {
            "strategy_a": {
                "status": "limited",
                "metrics": {
                    "accuracy": 0.8,
                    "balanced_accuracy": 0.75,
                    "precision": 0.5,
                    "recall": 0.6,
                    "f1": 0.55,
                    "roc_auc": 0.7,
                    "pr_auc": 0.4,
                },
            }
        },
    }

    rows = compute_ablation_experiments(report)

    assert rows[0]["status"] == "baseline_only"
    assert rows[0]["balanced_accuracy"] == 0.75
    assert set(rows[0].keys()) == set(ABLATION_COLUMNS)


def test_leakage_checks_pass_for_default_configuration():
    report = {
        "leakage_guard": {
            "risk_score_used_as_feature": False,
            "proxy_label_fields_used_as_features": [],
        }
    }
    feasibility = {"proxy_supervised_learning_feasibility": "limited"}

    checks = build_leakage_checks(
        report,
        feasibility,
        summary_text="Proxy labels are not ground truth, and production risk_score behavior is unchanged.",
    )

    assert checks["status"] == "passed"
    names = {check["check"] for check in checks["checks"]}
    assert "final_risk_score_not_model_input" in names
    assert "dread_live_crawling_not_used" in names


def test_leakage_checks_fail_when_limitation_text_missing():
    checks = build_leakage_checks(
        {"leakage_guard": {"risk_score_used_as_feature": False}},
        {},
        summary_text="",
    )

    assert checks["status"] == "failed"
    failed = [check for check in checks["checks"] if check["status"] == "failed"]
    assert failed[0]["check"] == "proxy_label_limitations_text_present"


def test_case_study_selection_covers_requested_groups():
    rows = [
        _row(cve_id="CVE-HH", risk_score=8.0, confidence=0.6, cvss_score=9.0),
        _row(cve_id="CVE-HL", risk_score=8.1, confidence=0.6, cvss_score=10.0, intrinsic_criticality_floor_applied=True),
        _row(cve_id="CVE-LH", risk_score=5.0, confidence=0.2, cvss_score=5.0),
        _row(cve_id="CVE-MISSING", risk_score=8.2, confidence=0.5, cvss_score=10.0, epss_available=False, kev_status_known=False),
        _row(cve_id="CVE-URL", risk_score=4.5, confidence=0.5, urlhaus_ignored_low_signal_count=6),
        _row(cve_id="CVE-LOWCONF", risk_score=7.5, confidence=0.2, cvss_score=8.8),
    ]
    labels = build_proxy_label_rows(rows)
    predictions = [
        {"cve_id": "CVE-HH", "learned_probability": 0.9, "strategy": "strategy_a"},
        {"cve_id": "CVE-HL", "learned_probability": 0.1, "strategy": "strategy_a"},
        {"cve_id": "CVE-LH", "learned_probability": 0.95, "strategy": "strategy_a"},
    ]

    cases = select_case_studies(rows, labels, predictions)
    groups = {case["case_group"] for case in cases}

    assert "high_heuristic_risk_and_high_learned_probability" in groups
    assert "high_heuristic_risk_but_low_learned_probability" in groups
    assert "low_medium_heuristic_risk_but_high_learned_probability" in groups
    assert "intrinsic_floor_applied" in groups
    assert "missing_epss_kev_high_intrinsic_severity" in groups
    assert "rejected_ignored_urlhaus_heavy" in groups
    assert "low_confidence_but_high_risk" in groups


def test_case_study_selection_limits_examples_per_group():
    rows = [_row(cve_id=f"CVE-{index}", risk_score=8.0, confidence=0.6) for index in range(10)]
    labels = build_proxy_label_rows(rows)
    predictions = [{"cve_id": row["cve_id"], "learned_probability": 0.9, "strategy": "strategy_a"} for row in rows]

    cases = select_case_studies(rows, labels, predictions, max_per_group=3)
    high = [case for case in cases if case["case_group"] == "high_heuristic_risk_and_high_learned_probability"]

    assert len(high) == 3


def test_publication_tables_generated_from_artifact_payloads():
    feasibility = {
        "analyzed_records_exported": 10,
        "records_with_cvss": 8,
        "epss_availability_count": 2,
        "kev_known_count": 1,
        "accepted_external_evidence_count": 0,
        "proxy_label_class_counts": {"strategy_a": {"high": 1, "low": 9}},
    }
    baseline = {"strategies": {"strategy_a": {"status": "tiny_positive_class", "precision_at_k": {"10": 0.1}, "recall_at_k": {"50": 1.0}, "ndcg_at_k": {"50": 0.5}}}}
    model = {"strategies": {"strategy_a": {"status": "skipped", "metrics": {}}}}
    ablations = [{"ablation": "all_features", "status": "skipped", "interpretation": "baseline feature set for comparison"}]
    leakage = {"checks": [{"check": "risk_score", "status": "passed", "details": "excluded"}]}

    tables = build_publication_tables(
        feasibility_report=feasibility,
        baseline_metrics=baseline,
        model_report=model,
        ablations=ablations,
        leakage_checks=leakage,
    )

    assert tables["dataset_coverage_summary"][0]["value"] == 10
    assert tables["proxy_label_class_distribution"][0]["strategy"] == "strategy_a"
    assert tables["heuristic_baseline_metrics"][0]["precision_at_10"] == 0.1
    assert tables["learned_model_metrics"][0]["status"] == "skipped"
    assert tables["ablation_summary"][0]["ablation"] == "all_features"
    assert tables["leakage_robustness_checks"][0]["status"] == "passed"


def test_learned_calibration_manifest_reports_files(tmp_path):
    (tmp_path / "learned_calibration_dataset.csv").write_text("cve_id\nCVE-1\n", encoding="utf-8")
    (tmp_path / "learned_calibration_labels.csv").write_text("cve_id\nCVE-1\n", encoding="utf-8")
    for name in (
        "learned_calibration_baseline_metrics.json",
        "learned_calibration_baseline_metrics.md",
        "learned_calibration_model_report.json",
        "learned_calibration_model_summary.md",
        "learned_calibration_predictions.csv",
        "learned_vs_heuristic_comparison.json",
        "learned_vs_heuristic_comparison.md",
        "learned_calibration_disagreements.csv",
        "learned_calibration_disagreements.md",
        "learned_calibration_feature_importance.csv",
        "learned_calibration_feature_importance.md",
        "learned_calibration_ablation.csv",
        "learned_calibration_ablation.md",
        "learned_calibration_leakage_checks.json",
        "learned_calibration_leakage_checks.md",
        "learned_calibration_thesis_section.md",
        "learned_calibration_limitations.md",
        "learned_calibration_tables.json",
        "learned_calibration_tables.md",
        "learned_calibration_case_studies.csv",
        "learned_calibration_case_studies.md",
        "learned_calibration_proxy_sensitivity.csv",
        "learned_calibration_proxy_sensitivity.json",
        "learned_calibration_proxy_sensitivity.md",
    ):
        (tmp_path / name).write_text("x", encoding="utf-8")

    manifest = build_learned_calibration_manifest(tmp_path)

    assert manifest["status"] == "complete"
    assert manifest["artifact_count"] >= 20
    dataset = next(item for item in manifest["artifacts"] if item["group"] == "dataset")
    assert dataset["exists"] is True
    assert dataset["size_bytes"] > 0
    assert dataset["producer"] == "evaluation.learned_calibration"


def test_proxy_threshold_grid_size_and_values():
    grid = proxy_threshold_grid()

    assert len(grid) == 320
    assert grid[0] == {
        "epss_high_threshold": 0.5,
        "cvss_critical_threshold": 9.0,
        "nlp_context_threshold": 0.6,
        "recency_threshold": 0.3,
    }


def test_proxy_threshold_sensitivity_stability_and_classification():
    rows = [
        _row(cve_id="CVE-H", risk_score=9.0, cvss_score=9.8, nlp_context_signal=0.9, recency_signal=0.8),
        _row(cve_id="CVE-M", risk_score=5.0, cvss_score=7.0, nlp_context_signal=0.4, recency_signal=0.1),
        _row(cve_id="CVE-L", risk_score=1.0, cvss_score=3.0, nlp_context_signal=0.1, recency_signal=0.1),
    ]
    labels = build_proxy_label_rows(rows)

    result = compute_proxy_threshold_sensitivity(rows, labels)

    assert result["grid_size"] == 320
    first = result["rows"][0]
    assert first["high_count"] == 1
    assert first["medium_count"] == 1
    assert first["low_count"] == 1
    assert first["label_stability_vs_strategy_a"] == 1.0
    assert first["classification"] == "too_narrow"
