import csv
import json

from evaluation.objectives import (
    build_exploitation_priority_evaluation,
    build_operational_risk_evaluation,
    build_severity_evaluation,
    objective_definitions,
    run_objective_evaluation,
)


FIXED_NOW = "2026-06-10T00:00:00+00:00"


def _write_json(path, payload):
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def _balanced_dir(tmp_path):
    path = tmp_path / "balanced"
    path.mkdir()
    records = [
        {
            "cve_id": "CVE-2024-1000",
            "bucket": "kev_positive",
            "is_kev": "True",
            "cvss_score": "9.8",
            "epss_score": "0.94",
            "epss_percentile": "0.99",
            "model_risk_score": "8.0",
            "model_confidence": "0.8",
            "has_model_result": "True",
            "missing_model_result": "False",
            "published": "2024-01-01T00:00:00.000",
            "rationale": "positive",
        },
        {
            "cve_id": "CVE-2024-1001",
            "bucket": "high_cvss_low_epss_non_kev",
            "is_kev": "False",
            "cvss_score": "10.0",
            "epss_score": "0.01",
            "epss_percentile": "0.10",
            "model_risk_score": "4.0",
            "model_confidence": "0.7",
            "has_model_result": "True",
            "missing_model_result": "False",
            "published": "2024-01-02T00:00:00.000",
            "rationale": "severity control",
        },
        {
            "cve_id": "CVE-2024-1002",
            "bucket": "medium_severity_control",
            "is_kev": "False",
            "cvss_score": "5.5",
            "epss_score": "0.80",
            "epss_percentile": "0.95",
            "model_risk_score": "6.0",
            "model_confidence": "0.9",
            "has_model_result": "True",
            "missing_model_result": "False",
            "published": "2024-01-03T00:00:00.000",
            "rationale": "high epss medium severity",
        },
    ]
    summary = {
        "generated_at": FIXED_NOW,
        "metric_config": {"k_values": [1, 3], "label": "kev_or_exploitation_evidence"},
        "baselines": {
            "model_risk": {"ranking": ["CVE-2024-1000"], "metrics": {"precision_at_1": 1.0, "recall_at_1": 1.0}, "spearman_vs_model_risk": 1.0},
            "cvss_only": {"ranking": ["CVE-2024-1001"], "metrics": {"precision_at_1": 0.0}, "spearman_vs_model_risk": 0.5},
            "epss_only": {"ranking": ["CVE-2024-1000"], "metrics": {"precision_at_1": 1.0}, "spearman_vs_model_risk": 0.8},
            "cvss_epss": {"ranking": ["CVE-2024-1000"], "metrics": {"precision_at_1": 1.0}, "spearman_vs_model_risk": 0.7},
            "model_confidence_weighted": {"ranking": ["CVE-2024-1000"], "metrics": {"precision_at_1": 1.0}, "spearman_vs_model_risk": 0.9},
        },
        "records": records,
    }
    diagnostics = {"record_count": 3, "warnings": ["small_fixture"], "correlation_subset": {"status": "fixture"}}
    candidates = {
        "high_cvss_low_exploitation_signal_case": records[1],
        "old_but_actively_exploited_case": records[0],
    }
    _write_json(path / "benchmark_summary.json", summary)
    _write_json(path / "benchmark_diagnostics.json", diagnostics)
    _write_json(path / "case_candidates.json", candidates)
    _write_csv(path / "benchmark_records.csv", records)
    return path


def _correlation_dir(tmp_path):
    path = tmp_path / "correlation"
    path.mkdir()
    _write_json(
        path / "correlation_evaluation.json",
        {
            "label_counts": {"confirmed_positive": 1, "confirmed_negative": 1, "unknown": 1},
            "decision_counts": {"accepted": 1, "rejected": 2},
            "included_ground_truth_count": 2,
            "unknown_excluded_count": 1,
            "true_positives": 1,
            "true_negatives": 1,
            "false_positives": 0,
            "false_negatives": 0,
            "manual_review_count": 0,
            "manual_review_positive_count": 0,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
        },
    )
    _write_json(path / "correlation_case_candidates.json", {"accepted_confirmed_positives": [{"cve_id": "CVE-2024-1000"}]})
    _write_json(
        path / "paired_model_results.json",
        {
            "records": [
                {
                    "cve_id": "CVE-2024-1000",
                    "risk_score_delta": 1.2,
                    "confidence_delta": 0.1,
                    "graph_edge_delta": 1,
                    "cross_source_edge_delta": 1,
                }
            ]
        },
    )
    _write_csv(
        path / "correlation_records.csv",
        [
            {
                "cve_id": "CVE-2024-1000",
                "label": "confirmed_positive",
                "predicted_status": "accepted",
                "accepted_count": "1",
                "manual_review_count": "0",
                "rejected_count": "0",
            }
        ],
    )
    return path


def _operational_report():
    return {
        "fixture_metadata": {"asset_count": 2},
        "asset_operational_risk": [
            {
                "cve_id": "CVE-2024-1000",
                "asset_id": "edge",
                "source_risk_score": 6.0,
                "final_operational_risk_score": 9.0,
                "component_breakdown": {"criticality": "critical", "exposure": "internet", "patch_state": "unpatched"},
                "applicability": {"status": "applicable"},
            },
            {
                "cve_id": "CVE-2024-1000",
                "asset_id": "internal",
                "source_risk_score": 6.0,
                "final_operational_risk_score": 0.0,
                "component_breakdown": {"criticality": "low", "exposure": "internal", "patch_state": "patched"},
                "applicability": {"status": "not_applicable"},
            },
        ],
    }


def test_objective_definitions_are_distinct_and_explicit_about_proxies():
    definitions = objective_definitions()

    assert set(definitions) == {"severity", "exploitation_priority", "operational_risk"}
    assert definitions["severity"]["production_score_suitability"] == "proxy_only"
    assert definitions["operational_risk"]["production_score_suitability"] == "not_directly_suitable"


def test_severity_reference_comparison_reports_disagreements():
    rows = [
        {"cve_id": "CVE-2024-1000", "cvss_score": 10.0, "model_risk_score": 4.0, "model_confidence": 0.8, "is_kev": False},
        {"cve_id": "CVE-2024-1001", "cvss_score": 5.0, "model_risk_score": 8.0, "model_confidence": 0.7, "is_kev": True},
    ]

    report = build_severity_evaluation(rows, generated_at=FIXED_NOW)

    assert report["reference"].startswith("CVSS technical severity")
    assert report["metrics"]["max_absolute_score_delta"] == 6.0
    assert report["disagreement_cases"][0]["cve_id"] == "CVE-2024-1000"


def test_exploitation_priority_keeps_correlation_subset_separate(tmp_path):
    balanced_path = _balanced_dir(tmp_path)
    correlation_path = _correlation_dir(tmp_path)
    balanced = {
        "summary": json.loads((balanced_path / "benchmark_summary.json").read_text(encoding="utf-8")),
        "diagnostics": {"warnings": []},
        "records": list(csv.DictReader((balanced_path / "benchmark_records.csv").open())),
    }
    correlation = {
        "evaluation": json.loads((correlation_path / "correlation_evaluation.json").read_text(encoding="utf-8")),
        "paired_records": [{"risk_score_delta": 1.2, "confidence_delta": 0.1, "graph_edge_delta": 1, "cross_source_edge_delta": 1}],
        "case_candidates": {},
    }

    report = build_exploitation_priority_evaluation(balanced, correlation, generated_at=FIXED_NOW)

    assert report["balanced_benchmark"]["model_risk"]["metrics"]["precision_at_1"] == 1.0
    assert report["correlation_focused_subset"]["metrics"]["precision"] == 1.0
    assert report["correlation_focused_subset"]["accepted_manual_review_are_separate"] is True


def test_operational_risk_comparison_marks_fixture_source():
    report = build_operational_risk_evaluation(_operational_report(), source="deterministic_thesis_fixture", generated_at=FIXED_NOW)

    assert report["fixture_derived"] is True
    assert report["comparisons"]["applicability"]["applicable"]["mean_final_operational_risk_score"] == 9.0
    assert report["comparisons"]["applicability"]["not_applicable"]["mean_final_operational_risk_score"] == 0.0


def test_runner_writes_deterministic_artifacts_and_reports_missing_optional_input(tmp_path, monkeypatch):
    balanced = _balanced_dir(tmp_path)
    correlation = _correlation_dir(tmp_path)

    def fake_operational_loader(path):
        assert path is None
        return _operational_report(), "deterministic_thesis_fixture"

    monkeypatch.setattr("evaluation.objectives._load_operational_report", fake_operational_loader)
    first = run_objective_evaluation(
        balanced_dir=balanced,
        correlation_dir=correlation,
        output_dir=tmp_path / "first",
        generated_at=FIXED_NOW,
    )
    second = run_objective_evaluation(
        balanced_dir=balanced,
        correlation_dir=correlation,
        output_dir=tmp_path / "second",
        generated_at=FIXED_NOW,
    )

    assert first == second
    assert first["evaluation_objectives"]["missing_optional_inputs"][0]["input"] == "operational_report_path"
    for name in (
        "evaluation_objectives.json",
        "severity_evaluation.json",
        "exploitation_priority_evaluation.json",
        "operational_risk_evaluation.json",
        "objective_comparison.csv",
        "objective_metrics.csv",
        "objective_case_candidates.json",
        "thesis_results_summary.json",
    ):
        assert (tmp_path / "first" / name).exists()
    assert (tmp_path / "first" / "thesis_results_summary.json").read_text(encoding="utf-8") == (
        tmp_path / "second" / "thesis_results_summary.json"
    ).read_text(encoding="utf-8")
