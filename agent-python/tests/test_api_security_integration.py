from types import SimpleNamespace

from fastapi.testclient import TestClient

import api.app as app_module
from api.audit import StructuredAuditLogger
from api.security import APIKeyAuthenticator, Authorizer
from config import SecurityConfig
from worker.job_lifecycle import JobState, new_job
from worker.job_repository import DatabaseJobRepositoryAdapter


class RepoStub:
    def ping(self):
        return True

    def get_recent_findings(self, source, limit=10):
        return [
            {
                "_id": "CVE-2026-1",
                "analysis": {
                    "entity_id": "CVE-2026-1",
                    "risk_level": "HIGH",
                    "risk_score": 8.1,
                    "confidence": 0.9,
                    "diagnosis": "demo",
                    "evidence": {"cvss_score": 9.8},
                },
            }
        ]


class AnalysisDBStub:
    def __init__(self):
        self.persisted = []

    def persist_analysis_result(self, source, original_doc, analysis_result):
        self.persisted.append((source, original_doc, analysis_result))
        return analysis_result.get("entity_id")

    def get_status_overview(self):
        return {
            "sources": {
                "cve": {"total": 1, "processed": 1, "unprocessed": 0, "analyzed": 1, "analysis_coverage": 1.0, "avg_risk_score": 8.1},
                "urlhaus": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0},
                "dread": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0},
            },
            "totals": {"total": 1, "processed": 1, "unprocessed": 0, "analyzed": 1, "analysis_coverage": 1.0},
            "pipeline_version": "test",
        }


class DiagnosticStub:
    def analyze(self, source, payload, db=None):
        return {
            "entity_type": source,
            "entity_id": payload.get("_id", "demo"),
            "risk_level": "LOW",
            "risk_score": 1.0,
            "confidence": 0.8,
            "diagnosis": "demo",
            "explanation": [],
            "recommendations": [],
            "feature_breakdown": {},
            "graph_summary": {},
            "graph_edges": [],
        }

    def plan(self, source, payload):
        return {"source": source, "execution_plan": [{"step": 1, "agent": "planner", "action": "seed", "status": "pending", "details": {}}]}


class RecommenderStub:
    def suggest(self, analysis_result, source, original_doc):
        return ["review"]


class LifecycleDB:
    def __init__(self):
        self.saved = {}

    def update_job_lifecycle(self, source, doc_id, job_lifecycle):
        self.saved[job_lifecycle["idempotency_key"]] = job_lifecycle

    def get_job_lifecycle_by_idempotency(self, idempotency_key):
        return self.saved.get(idempotency_key)


def _secure_client(monkeypatch):
    audit_logger = StructuredAuditLogger()
    config = SecurityConfig(auth_mode="api_key", api_keys=["viewer-key:viewer:viewer-1", "analyst-key:analyst:analyst-1", "operator-key:operator:operator-1", "admin-key:admin:admin-1"])
    authenticator = APIKeyAuthenticator(config, audit_sink=audit_logger)
    authorizer = Authorizer(audit_sink=audit_logger)
    monkeypatch.setattr(app_module, "repo", RepoStub())
    monkeypatch.setattr(app_module, "analysis_db", AnalysisDBStub())
    monkeypatch.setattr(app_module, "diagnostic_agent", DiagnosticStub())
    monkeypatch.setattr(app_module, "recommender_agent", RecommenderStub())
    monkeypatch.setattr(app_module, "audit_logger", audit_logger)
    monkeypatch.setattr(app_module.app.state, "audit_logger", audit_logger, raising=False)
    monkeypatch.setattr(app_module.app.state, "authenticator", authenticator, raising=False)
    monkeypatch.setattr(app_module.app.state, "authorizer", authorizer, raising=False)
    return TestClient(app_module.app), audit_logger


def test_health_and_sources_remain_public(monkeypatch):
    client, _audit = _secure_client(monkeypatch)

    assert client.get("/health").status_code == 200
    assert client.get("/sources").status_code == 200


def test_unauthorized_access_returns_deterministic_error(monkeypatch):
    client, audit = _secure_client(monkeypatch)

    response = client.get("/findings/recent", params={"source": "cve"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required"
    assert audit.events[-1].to_dict()["outcome"] == "failure"


def test_viewer_can_read_but_cannot_trigger_analysis(monkeypatch):
    client, audit = _secure_client(monkeypatch)

    read = client.get("/findings/recent", params={"source": "cve"}, headers={"x-api-key": "viewer-key"})
    denied = client.post("/analyze/cve", json={"_id": "CVE-2026-1"}, headers={"x-api-key": "viewer-key"})

    assert read.status_code == 200
    assert denied.status_code == 403
    assert denied.json()["detail"] == "Insufficient permissions"
    assert audit.events[-1].action == "authorize:trigger_analysis"
    assert audit.events[-1].to_dict()["outcome"] == "denied"


def test_analyst_can_trigger_analysis_and_audit_event_is_emitted(monkeypatch):
    client, audit = _secure_client(monkeypatch)

    response = client.post("/analyze/cve", json={"_id": "CVE-2026-1"}, headers={"authorization": "Bearer analyst-key"})

    assert response.status_code == 200
    body = response.json()
    assert body["entity_id"] == "CVE-2026-1"
    assert body["recommendations"] == ["review"]
    assert any(event.action == "analysis_trigger" and event.actor_id == "analyst-1" for event in audit.events)


def test_operator_can_view_job_status_but_viewer_cannot(monkeypatch):
    client, _audit = _secure_client(monkeypatch)

    denied = client.get("/status/overview", headers={"x-api-key": "viewer-key"})
    allowed = client.get("/status/overview", headers={"x-api-key": "operator-key"})

    assert denied.status_code == 403
    assert allowed.status_code == 200


def test_admin_settings_access_is_audited_and_shape_is_unchanged(monkeypatch):
    client, audit = _secure_client(monkeypatch)

    response = client.get("/settings", headers={"x-api-key": "admin-key"})

    assert response.status_code == 200
    body = response.json()
    assert "database" in body
    assert "runtime" in body
    assert "security" not in body
    assert any(event.action == "admin_view_settings" for event in audit.events)


def test_audit_event_sanitizes_secrets():
    audit = StructuredAuditLogger()
    event = SimpleNamespace(
        actor_id="actor",
        role="admin",
        action="test",
        target="target",
        outcome=SimpleNamespace(value="success"),
        to_dict=lambda: {},
    )
    # Exercise through the real event path used by authentication details.
    from api.audit import AuditEvent, AuditOutcome

    audit.write(AuditEvent(actor_id="actor", role="admin", action="test", target="target", outcome=AuditOutcome.SUCCESS, details={"authorization": "Bearer x", "api_key": "x", "safe": "ok"}))

    payload = audit.events[-1].to_dict()
    assert payload["details"] == {"safe": "ok"}
    assert event.actor_id == "actor"


def test_worker_lifecycle_persistence_adapter_round_trips_metadata():
    db = LifecycleDB()
    repo = DatabaseJobRepositoryAdapter(db)
    job = new_job("cve", "CVE-2026-1", "0.4.0")

    claimed = repo.claim(job, now=job.created_at)
    repo.save(claimed.transition(JobState.RUNNING, now=job.created_at))

    stored = repo.get(job.idempotency_key)
    assert stored.state == JobState.RUNNING
    assert db.saved[job.idempotency_key]["state"] == "running"


def test_orchestration_result_compatibility_under_authenticated_trigger(monkeypatch):
    client, _audit = _secure_client(monkeypatch)

    response = client.post("/analyze/plan/cve", json={"_id": "CVE-2026-1"}, headers={"x-api-key": "analyst-key"})

    assert response.status_code == 200
    assert set(response.json()) == {"source", "execution_plan"}
