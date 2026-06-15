import json

from api.schemas import AnalyzeResponse, FindingDetail, FindingSummary
from integration.thesis_scenario import run_thesis_scenario


def test_full_fixture_pipeline_execution_generates_report(tmp_path):
    report_path = tmp_path / "thesis_report.json"

    report = run_thesis_scenario(report_path)

    assert report_path.exists()
    assert json.loads(report_path.read_text(encoding="utf-8")) == report
    assert report["fixture_metadata"] == {
        "asset_count": 2,
        "cve_count": 3,
        "dread_count": 2,
        "epss_count": 24,
        "evaluation_record_count": 24,
        "kev_count": 7,
        "urlhaus_count": 3,
    }
    assert len(report["source_results"]) == 8
    assert all(item["orchestration_summary"]["trace_count"] > 0 for item in report["source_results"])
    assert all(item["orchestration_summary"]["plan_count"] > 0 for item in report["source_results"])


def test_duplicate_suppression_and_terminal_job_lifecycle():
    report = run_thesis_scenario()
    jobs = report["job_lifecycle"]["jobs"]

    assert report["job_lifecycle"]["duplicate_suppressed"] is True
    assert report["job_lifecycle"]["metrics"]["processed_jobs"] == 8
    assert report["job_lifecycle"]["metrics"]["successful_jobs"] == 8
    assert {job["state"] for job in jobs} == {"completed"}
    assert all(job["transition_history"][-1]["to_state"] == "completed" for job in jobs)
    assert any(event["event"] == "job_duplicate_skipped" for event in report["job_lifecycle"]["events"])


def test_correlation_decision_status_coverage():
    report = run_thesis_scenario()
    decisions = report["correlation_decisions"]

    assert {decision["status"] for decision in decisions} == {"accepted", "manual_review", "rejected"}
    assert any(decision["target_identifier"] == "UH-9001" and decision["status"] == "accepted" for decision in decisions)
    assert any(decision["target_identifier"] == "UH-9002" and decision["status"] == "manual_review" for decision in decisions)
    assert all(decision["evidence_references"] for decision in decisions)
    assert all(decision["provenance_summary"] for decision in decisions)


def test_asset_operational_risk_differs_by_applicability_and_exposure():
    report = run_thesis_scenario()
    rows = report["asset_operational_risk"]

    applicable = next(item for item in rows if item["cve_id"] == "CVE-2026-9001" and item["asset_id"] == "asset-vpn-prod")
    non_applicable = next(item for item in rows if item["cve_id"] == "CVE-2026-9001" and item["asset_id"] == "asset-backup-internal")

    assert applicable["applicability"]["status"] == "applicable"
    assert applicable["final_operational_risk_score"] > 0
    assert applicable["component_breakdown"]["exposure_contribution"] > 0
    assert non_applicable["applicability"]["status"] == "not_applicable"
    assert non_applicable["final_operational_risk_score"] == 0.0


def test_api_compatible_response_keys_are_preserved():
    report = run_thesis_scenario()
    api_results = report["api_compatible_results"]

    assert api_results["finding_summary_keys"] == sorted(FindingSummary.model_fields)
    assert api_results["finding_detail_keys"] == sorted(FindingDetail.model_fields)
    assert api_results["analyze_response_keys"] == sorted(AnalyzeResponse.model_fields)
    assert api_results["sample_summary"]["source"] == "cve"
    assert "risk_score" in api_results["sample_summary"]


def test_evaluation_report_contains_model_and_baseline_metrics():
    report = run_thesis_scenario()
    evaluation = report["evaluation"]

    assert evaluation["dataset"]["record_count"] == 24
    assert evaluation["dataset"]["kev_count"] == 7
    assert evaluation["dataset"]["epss_available_count"] == 24
    assert {"model_risk", "cvss_only", "epss_only", "cvss_epss", "kev_first", "model_confidence_weighted", "signal_based_model"} <= set(evaluation["baselines"])
    assert "precision_at_1" in evaluation["baselines"]["model_risk"]["metrics"]
    assert evaluation["metric_config"]["k_values"] == [1, 3, 5, 10]


def test_report_output_is_deterministic_for_fixed_fixtures(tmp_path):
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"

    first = run_thesis_scenario(first_path)
    second = run_thesis_scenario(second_path)

    assert first == second
    assert first_path.read_text(encoding="utf-8") == second_path.read_text(encoding="utf-8")
