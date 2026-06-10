import os

import pytest

from integration import e2e_system


def test_e2e_runner_refuses_to_reset_non_e2e_database(tmp_path):
    with pytest.raises(ValueError):
        e2e_system.run_e2e_system(
            output_dir=tmp_path,
            mongo_uri="mongodb://127.0.0.1:27017",
            db_name="threat_intel",
            start_mongodb=False,
        )


def test_api_checks_capture_auth_and_response_shape(monkeypatch):
    def fake_http_json(url, headers=None):
        if url.endswith("/health"):
            return {"status_code": 200, "json": {"status": "ok"}}
        if "/findings/recent" in url and not headers:
            return {"status_code": 401, "json": {"detail": "Authentication required"}}
        if "/findings/recent" in url:
            return {"status_code": 200, "json": [{"source": "cve", "risk_score": 8.0}]}
        if "/findings/detail" in url:
            return {"status_code": 200, "json": {"source": "cve", "risk_score": 8.0, "evidence_summary": {}}}
        if "/status/overview" in url and headers and headers.get("x-api-key") == e2e_system.VIEWER_KEY:
            return {"status_code": 403, "json": {"detail": "Insufficient permissions"}}
        if "/status/overview" in url:
            return {"status_code": 200, "json": {"totals": {}}}
        raise AssertionError(url)

    monkeypatch.setattr(e2e_system, "_http_json", fake_http_json)

    checks = e2e_system._run_api_checks(12345)

    assert checks["health"]["status_code"] == 200
    assert checks["unauthorized_recent"]["status_code"] == 401
    assert checks["viewer_forbidden_status"]["status_code"] == 403
    assert checks["operator_status"]["status_code"] == 200
    assert checks["response_shape"]["recent_count"] == 1
    assert checks["response_shape"]["detail_has_risk_score"] is True


def test_lifecycle_validation_rejects_processed_records_without_persisted_lifecycle():
    validation = e2e_system._lifecycle_validation(
        [
            {
                "source": "urlhaus",
                "document_id": "mongo-object-id",
                "processed": True,
                "has_analysis": True,
                "job_state": None,
                "idempotency_key_present": False,
                "transition_states": [],
            }
        ]
    )

    assert validation["valid"] is False
    assert {item["reason"] for item in validation["violations"]} == {
        "missing_terminal_job_state",
        "missing_idempotency_key",
        "missing_lifecycle_transition_history",
    }


def test_lifecycle_validation_accepts_processed_records_with_terminal_lifecycle():
    validation = e2e_system._lifecycle_validation(
        [
            {
                "source": "urlhaus",
                "document_id": "mongo-object-id",
                "processed": True,
                "has_analysis": True,
                "job_state": "completed",
                "idempotency_key_present": True,
                "transition_states": ["pending", "running", "completed"],
            }
        ]
    )

    assert validation["valid"] is True


def test_full_e2e_system_opt_in(tmp_path):
    if os.getenv("RUN_E2E_SYSTEM") != "1":
        pytest.skip("Set RUN_E2E_SYSTEM=1 to run Docker/Mongo-backed E2E system test")

    report = e2e_system.run_e2e_system(output_dir=tmp_path, generated_at="2026-06-10T00:00:00+00:00")

    assert (tmp_path / "e2e_system_report.json").exists()
    assert report["ingestion"]["counts_after_ingest"]["cve"]["total"] >= 2
    assert report["ingestion"]["counts_after_ingest"]["urlhaus"]["total"] >= 2
    assert report["worker"]["processed_result_count"] >= 4
    assert report["duplicate_suppression"]["analysis_history_unchanged"] is True
    assert report["api_checks"]["health"]["status_code"] == 200
    assert report["api_checks"]["unauthorized_recent"]["status_code"] == 401
    assert report["api_checks"]["authorized_recent"]["status_code"] == 200
