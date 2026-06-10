import csv
import hashlib
import json

import pytest

from evaluation.thesis_reporting import REQUIRED_CHARTS, load_reporting_inputs, run_thesis_reporting, ReportingInputs


FIXED_NOW = "2026-06-10T00:00:00+00:00"


def _write_json(path, payload):
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")


def _write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def _fixture_artifacts(tmp_path):
    objective = tmp_path / "objective"
    balanced = tmp_path / "balanced"
    correlation = tmp_path / "correlation"
    objective.mkdir()
    balanced.mkdir()
    correlation.mkdir()
    balanced_records = [
        {
            "cve_id": "CVE-2024-1000",
            "bucket": "kev_positive",
            "is_kev": "True",
            "cvss_score": "9.8",
            "epss_score": "0.94",
            "model_risk_score": "8.0",
            "model_confidence": "0.8",
            "has_model_result": "True",
            "missing_model_result": "False",
            "published": "2024-01-01",
            "rationale": "kev",
        },
        {
            "cve_id": "CVE-2024-1001",
            "bucket": "high_cvss_low_epss_non_kev",
            "is_kev": "False",
            "cvss_score": "10.0",
            "epss_score": "0.01",
            "model_risk_score": "4.0",
            "model_confidence": "0.7",
            "has_model_result": "True",
            "missing_model_result": "False",
            "published": "2024-01-02",
            "rationale": "control",
        },
        {
            "cve_id": "CVE-2024-1002",
            "bucket": "medium_severity_control",
            "is_kev": "False",
            "cvss_score": "5.5",
            "epss_score": "0.80",
            "model_risk_score": "6.0",
            "model_confidence": "0.9",
            "has_model_result": "True",
            "missing_model_result": "False",
            "published": "2024-01-03",
            "rationale": "medium",
        },
    ]
    _write_csv(objective / "objective_comparison.csv", [
        {
            "objective": "severity",
            "measures": "Technical severity",
            "source_signals": "CVSS; model",
            "labels_or_references": "CVSS",
            "metrics": "Spearman",
            "production_score_suitability": "proxy_only",
            "proxy_usage": "proxy",
            "known_limitations": "CVSS is not ground truth.",
        },
        {
            "objective": "operational_risk",
            "measures": "Asset-specific impact",
            "source_signals": "asset context",
            "labels_or_references": "fixture",
            "metrics": "group contrasts",
            "production_score_suitability": "not_directly_suitable",
            "proxy_usage": "source risk is input",
            "known_limitations": "Fixture-derived.",
        },
    ])
    _write_csv(objective / "objective_metrics.csv", [{"objective": "severity", "scope": "cvss", "metric": "spearman", "value": "0.5"}])
    _write_json(objective / "evaluation_objectives.json", {"objectives": {"severity": {"name": "severity"}}})
    _write_json(
        objective / "severity_evaluation.json",
        {
            "reference": "CVSS technical severity reference, not perfect ground truth",
            "record_count": 3,
            "metrics": {"spearman_model_vs_cvss": 0.5, "mean_absolute_score_delta": 2.0},
            "disagreement_cases": [
                {"cve_id": "CVE-2024-1001", "absolute_delta": 6.0, "cvss_score": 10.0, "model_risk_score": 4.0, "direction": "model_lower"}
            ],
        },
    )
    exploitation = {
        "balanced_benchmark": {
            name: {
                "metrics": {
                    "precision_at_1": value,
                    "precision_at_3": value,
                    "ndcg_at_1": value,
                    "ndcg_at_3": value,
                    "mrr": value,
                    "recall_at_1": value,
                },
                "ranking_count": 3,
                "spearman_vs_model_risk": value,
            }
            for name, value in {
                "model_risk": 1.0,
                "cvss_only": 0.0,
                "epss_only": 1.0,
                "cvss_epss": 1.0,
                "model_confidence_weighted": 1.0,
            }.items()
        },
        "epss_correlation": {"spearman_model_vs_epss": 0.4, "records_with_epss": 3},
        "correlation_focused_subset": {
            "record_count": 3,
            "label_counts": {"confirmed_positive": 1, "confirmed_negative": 1, "unknown": 1},
            "decision_counts": {"accepted": 1, "rejected": 2},
            "included_ground_truth_count": 2,
            "unknown_excluded_count": 1,
            "metrics": {"precision": 1.0, "recall": 1.0, "f1": 1.0, "true_positives": 1, "false_positives": 0, "true_negatives": 1, "false_negatives": 0},
        },
    }
    _write_json(objective / "exploitation_priority_evaluation.json", exploitation)
    operational = {
        "fixture_derived": True,
        "record_count": 2,
        "comparisons": {
            "applicability": {
                "applicable": {"count": 1, "mean_final_operational_risk_score": 9.0, "max_final_operational_risk_score": 9.0, "mean_source_risk_score": 6.0},
                "not_applicable": {"count": 1, "mean_final_operational_risk_score": 0.0, "max_final_operational_risk_score": 0.0, "mean_source_risk_score": 6.0},
            },
            "exposure": {
                "internet": {"count": 1, "mean_final_operational_risk_score": 9.0, "max_final_operational_risk_score": 9.0, "mean_source_risk_score": 6.0},
                "internal": {"count": 1, "mean_final_operational_risk_score": 0.0, "max_final_operational_risk_score": 0.0, "mean_source_risk_score": 6.0},
            },
            "patch_state": {
                "unpatched": {"count": 1, "mean_final_operational_risk_score": 9.0, "max_final_operational_risk_score": 9.0, "mean_source_risk_score": 6.0},
                "patched": {"count": 1, "mean_final_operational_risk_score": 0.0, "max_final_operational_risk_score": 0.0, "mean_source_risk_score": 6.0},
            },
            "criticality": {
                "critical": {"count": 1, "mean_final_operational_risk_score": 9.0, "max_final_operational_risk_score": 9.0, "mean_source_risk_score": 6.0},
                "low": {"count": 1, "mean_final_operational_risk_score": 0.0, "max_final_operational_risk_score": 0.0, "mean_source_risk_score": 6.0},
            },
        },
        "top_operational_risk_cases": [
            {
                "cve_id": "CVE-2024-1002",
                "asset_id": "edge",
                "source_risk_score": 6.0,
                "final_operational_risk_score": 9.0,
                "component_breakdown": {"criticality": "critical", "exposure": "internet", "patch_state": "unpatched"},
                "applicability": {"status": "applicable"},
            }
        ],
        "non_actionable_cases": [
            {
                "cve_id": "CVE-2024-1000",
                "asset_id": "internal",
                "source_risk_score": 8.0,
                "final_operational_risk_score": 0.0,
                "component_breakdown": {"criticality": "low", "exposure": "internal", "patch_state": "patched"},
                "applicability": {"status": "not_applicable"},
            }
        ],
    }
    _write_json(objective / "operational_risk_evaluation.json", operational)
    _write_json(
        objective / "objective_case_candidates.json",
        {
            "high_severity_low_exploitation_priority": balanced_records[1],
            "correlation_driven_uplift_case": {"cve_id": "CVE-2024-1000", "risk_score_delta": 1.2},
            "old_but_still_actively_exploited_case": balanced_records[0],
            "high_exploitation_priority_low_operational_risk": operational["non_actionable_cases"][0],
            "moderate_severity_high_operational_risk_due_to_asset_context": operational["top_operational_risk_cases"][0],
            "strongest_severity_disagreement": {"cve_id": "CVE-2024-1001", "cvss_score": 10.0, "model_risk_score": 4.0},
            "low_or_medium_severity_high_exploitation_priority": {"available": False, "reason": "No case in fixture."},
        },
    )
    _write_json(objective / "thesis_results_summary.json", {"limitations": ["CVSS is not ground truth.", "Fixture-derived operational risk."]})
    _write_csv(balanced / "benchmark_records.csv", balanced_records)
    _write_json(
        balanced / "benchmark_summary.json",
        {
            "baselines": {
                "model_risk": {"ranking": ["CVE-2024-1000", "CVE-2024-1002", "CVE-2024-1001"], "metrics": {"precision_at_1": 1.0}},
                "cvss_only": {"ranking": ["CVE-2024-1001", "CVE-2024-1000", "CVE-2024-1002"], "metrics": {"precision_at_1": 0.0}},
                "epss_only": {"ranking": ["CVE-2024-1000", "CVE-2024-1002", "CVE-2024-1001"], "metrics": {"precision_at_1": 1.0}},
                "cvss_epss": {"ranking": ["CVE-2024-1000", "CVE-2024-1001", "CVE-2024-1002"], "metrics": {"precision_at_1": 1.0}},
            }
        },
    )
    _write_json(balanced / "case_candidates.json", {})
    _write_json(balanced / "benchmark_diagnostics.json", {"warnings": ["fixture_warning"]})
    _write_json(
        correlation / "correlation_evaluation.json",
        {
            "true_positives": 1,
            "false_positives": 0,
            "true_negatives": 1,
            "false_negatives": 0,
            "manual_review_count": 0,
            "unknown_excluded_count": 1,
            "precision": 1.0,
            "recall": 1.0,
            "f1": 1.0,
        },
    )
    _write_csv(
        correlation / "correlation_records.csv",
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
    _write_json(correlation / "correlation_case_candidates.json", {"accepted_confirmed_positives": [{"cve_id": "CVE-2024-1000"}]})
    _write_json(
        correlation / "paired_model_results.json",
        {
            "records": [
                {
                    "cve_id": "CVE-2024-1000",
                    "baseline_risk_score": 8.0,
                    "evidence_risk_score": 9.2,
                    "risk_score_delta": 1.2,
                    "baseline_confidence": 0.7,
                    "evidence_confidence": 0.9,
                    "confidence_delta": 0.2,
                    "graph_edge_delta": 1,
                    "cross_source_edge_delta": 1,
                    "evidence_related_urlhaus_count": 1,
                    "evidence_related_dread_count": 0,
                }
            ]
        },
    )
    return objective, balanced, correlation


def test_load_reporting_inputs_and_missing_required_input(tmp_path):
    objective, balanced, correlation = _fixture_artifacts(tmp_path)

    loaded = load_reporting_inputs(ReportingInputs(objective, balanced, correlation))

    assert loaded["severity"]["record_count"] == 3
    assert loaded["hashes"]["severity"] == hashlib.sha256((objective / "severity_evaluation.json").read_bytes()).hexdigest()

    (objective / "severity_evaluation.json").unlink()
    with pytest.raises(FileNotFoundError):
        load_reporting_inputs(ReportingInputs(objective, balanced, correlation))


def test_reporting_runner_writes_tables_charts_cases_and_manifest(tmp_path):
    objective, balanced, correlation = _fixture_artifacts(tmp_path)
    output = tmp_path / "out"

    report = run_thesis_reporting(
        objective_dir=objective,
        balanced_dir=balanced,
        correlation_dir=correlation,
        output_dir=output,
        generated_at=FIXED_NOW,
    )

    assert len(report["charts"]) == len(REQUIRED_CHARTS)
    for chart in report["charts"].values():
        path = output / "charts" / chart["png"].split("/")[-1]
        assert path.exists()
        assert chart["width_px"] > 0
        assert chart["height_px"] > 0
    for name in (
        "table_objective_comparison.csv",
        "table_objective_comparison.md",
        "table_severity_results.csv",
        "table_exploitation_results.csv",
        "table_correlation_results.csv",
        "table_operational_risk_results.csv",
        "table_case_studies.csv",
        "table_validity_limitations.md",
    ):
        assert (output / name).exists()
    assert (output / "case_studies.json").exists()
    assert (output / "case_study_summary.md").exists()
    assert (output / "cases" / "correlation_driven_uplift_case.json").exists()
    assert "strongest_model_vs_epss_disagreement" in report["case_studies"]["unavailable"]
    assert report["manifest"]["input_hashes"]["severity"] == hashlib.sha256((objective / "severity_evaluation.json").read_bytes()).hexdigest()
    assert report["thesis_findings"]["statistical_significance_claimed"] is False


def test_reporting_output_is_deterministic_for_fixed_inputs(tmp_path):
    objective, balanced, correlation = _fixture_artifacts(tmp_path)
    first = run_thesis_reporting(objective_dir=objective, balanced_dir=balanced, correlation_dir=correlation, output_dir=tmp_path / "first", generated_at=FIXED_NOW)
    second = run_thesis_reporting(objective_dir=objective, balanced_dir=balanced, correlation_dir=correlation, output_dir=tmp_path / "second", generated_at=FIXED_NOW)

    first_manifest = dict(first["manifest"])
    second_manifest = dict(second["manifest"])
    first_manifest.pop("generated_output_paths")
    second_manifest.pop("generated_output_paths")

    assert first_manifest == second_manifest
    assert (tmp_path / "first" / "table_case_studies.csv").read_text(encoding="utf-8") == (
        tmp_path / "second" / "table_case_studies.csv"
    ).read_text(encoding="utf-8")
