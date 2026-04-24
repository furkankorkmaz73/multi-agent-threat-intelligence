import sys
from types import SimpleNamespace

from fastapi.testclient import TestClient


class _DummyMongoClient:
    def __init__(self, *args, **kwargs):
        self.admin = SimpleNamespace(command=lambda *_args, **_kwargs: {"ok": 1})
    def __getitem__(self, name):
        return self


sys.modules.setdefault("pymongo", SimpleNamespace(MongoClient=_DummyMongoClient, DESCENDING=-1, ASCENDING=1))

import api.app as app_module




class StubRepo:
    def ping(self):
        return True

    def get_cve_analysis_docs(self, limit=None):
        return [{
            "_id": "CVE-2026-1000",
            "published": "2026-04-10T00:00:00.000",
            "descriptions": [{"lang": "en", "value": "vpn rce"}],
            "analysis": {
                "risk_score": 8.4,
                "risk_level": "HIGH",
                "confidence": 0.82,
                "diagnosis": "demo",
                "recommendations": ["patch immediately"],
                "critic_review": {"status": "passed"},
                "pipeline_version": "0.4.0",
                "persistence_meta": {"pipeline_version": "0.4.0"},
                "feature_breakdown": {
                    "base_cvss_component": 4.95,
                    "recentness_bonus": 1.2,
                    "urlhaus_correlation_bonus": 1.0,
                    "dread_correlation_bonus": 0.8,
                    "graph_bonus": 0.4,
                    "pre_graph_score": 7.9,
                    "final_score": 8.4,
                    "urlhaus_avg_semantic_score": 0.6,
                    "dread_avg_semantic_score": 0.4,
                },
                "graph_summary": {"centrality_score": 0.55, "average_edge_confidence": 0.7, "structural_strength": 0.62},
                "evidence": {"cvss_score": 9.0, "age_days": 2, "related_urlhaus_count": 1, "related_dread_count": 1},
                "counterfactuals": {},
                "source_contributions": {},
                "relation_summary": {},
            },
        }]


def test_evaluation_diagnostics_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "repo", StubRepo())
    client = TestClient(app_module.app)
    response = client.get("/evaluation/cve/diagnostics")
    assert response.status_code == 200
    body = response.json()
    assert body["record_count"] == 1
    assert body["pipeline_versions"] == ["0.4.0"]


def test_health_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "repo", StubRepo())
    client = TestClient(app_module.app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


class StubDiagnosticAgent:
    def plan(self, source, payload):
        return {"source": source, "execution_plan": [{"step": 1, "agent": "planner", "action": "seed", "status": "planned"}]}


def test_analyze_plan_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "diagnostic_agent", StubDiagnosticAgent())
    client = TestClient(app_module.app)
    response = client.post("/analyze/plan/cve", json={"id": "CVE-2026-1000"})
    assert response.status_code == 200
    body = response.json()
    assert body["source"] == "cve"
    assert body["execution_plan"][0]["agent"] == "planner"


def test_report_brief_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "repo", StubRepo())
    client = TestClient(app_module.app)
    response = client.get("/evaluation/cve/report-brief?limit=10&top_k=5")
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]
    assert body["case_studies"]
    assert body["markdown"]


def test_methodology_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "repo", StubRepo())
    client = TestClient(app_module.app)
    response = client.get("/evaluation/cve/methodology?limit=10&top_k=5")
    assert response.status_code == 200
    body = response.json()
    assert body["methodology"]["analysis_layers"]
    assert body["markdown"].startswith("# Technical Methodology Summary")


class StubAnalysisDB:
    def __init__(self):
        self.persist_calls = []

    def persist_analysis_result(self, source, original_doc, analysis_result):
        self.persist_calls.append({"source": source, "original_doc": original_doc, "analysis_result": analysis_result})
        return analysis_result.get("entity_id")

    def get_status_overview(self):
        return {
            "sources": {
                "cve": {"total": 2, "processed": 2, "unprocessed": 0, "analyzed": 2, "analysis_coverage": 1.0, "avg_risk_score": 8.1},
                "urlhaus": {"total": 1, "processed": 1, "unprocessed": 0, "analyzed": 1, "analysis_coverage": 1.0, "avg_risk_score": 7.2},
                "dread": {"total": 1, "processed": 0, "unprocessed": 1, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0},
            },
            "totals": {"total": 4, "processed": 3, "unprocessed": 1, "analyzed": 3, "analysis_coverage": 0.75},
            "pipeline_version": "0.4.0",
        }


class StubAnalyzeAgent:
    def analyze(self, source, payload, db=None):
        return {
            "entity_type": source,
            "entity_id": payload.get("_id") or payload.get("url") or payload.get("title") or "demo-id",
            "risk_level": "HIGH",
            "risk_score": 8.5,
            "confidence": 0.88,
            "diagnosis": "demo",
            "explanation": ["x"],
            "recommendations": [],
            "feature_breakdown": {},
            "graph_summary": {"centrality_score": 0.2},
            "graph_edges": [],
        }


class StubRecommender:
    def suggest(self, analysis_result, source, original_doc):
        return [f"review {source}"]


def test_analyze_persist_endpoint(monkeypatch):
    db = StubAnalysisDB()
    monkeypatch.setattr(app_module, "analysis_db", db)
    monkeypatch.setattr(app_module, "diagnostic_agent", StubAnalyzeAgent())
    monkeypatch.setattr(app_module, "recommender_agent", StubRecommender())
    client = TestClient(app_module.app)
    response = client.post("/analyze/cve/persist", json={"_id": "CVE-2026-2000"})
    assert response.status_code == 200
    assert db.persist_calls[0]["source"] == "cve"
    assert response.json()["recommendations"] == ["review cve"]


def test_batch_analyze_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "analysis_db", StubAnalysisDB())
    monkeypatch.setattr(app_module, "diagnostic_agent", StubAnalyzeAgent())
    monkeypatch.setattr(app_module, "recommender_agent", StubRecommender())
    client = TestClient(app_module.app)
    response = client.post("/analyze/batch/dread?persist=false&limit=2", json=[{"title": "a"}, {"title": "b"}, {"title": "c"}])
    assert response.status_code == 200
    body = response.json()
    assert body["requested"] == 3
    assert body["analyzed"] == 2
    assert len(body["results"]) == 2


def test_status_overview_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "analysis_db", StubAnalysisDB())
    client = TestClient(app_module.app)
    response = client.get("/status/overview")
    assert response.status_code == 200
    body = response.json()
    assert body["totals"]["analysis_coverage"] == 0.75


def test_evaluation_export_endpoint(monkeypatch):
    monkeypatch.setattr(app_module, "repo", StubRepo())
    client = TestClient(app_module.app)
    response = client.get("/evaluation/cve/export?limit=10&top_k=5")
    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["record_count"] == 1
    assert body["rows"]
    assert "feature_importance" in body["refinement"]



def test_findings_search_endpoint(monkeypatch):
    from api import app as api_app

    class RepoStub:
        def ping(self):
            return True

    class SearchDBStub:
        def get_status_overview(self):
            return {
                "sources": {"cve": {"total": 1, "processed": 1, "unprocessed": 0, "analyzed": 1, "analysis_coverage": 1.0, "avg_risk_score": 7.2}, "urlhaus": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0}, "dread": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0}},
                "totals": {"total": 1, "processed": 1, "unprocessed": 0, "analyzed": 1, "analysis_coverage": 1.0},
                "pipeline_version": "test",
            }

        def search_analyzed_findings(self, source, query, limit):
            return [{
                "_id": "CVE-TEST-1",
                "analysis": {
                    "entity_id": "CVE-TEST-1",
                    "risk_level": "HIGH",
                    "risk_score": 7.2,
                    "confidence": 0.82,
                    "diagnosis": "matched by search",
                    "pipeline_version": "test",
                    "persistence_meta": {"pipeline_version": "test"},
                },
            }]

    monkeypatch.setattr(api_app, "repo", RepoStub())
    monkeypatch.setattr(api_app, "analysis_db", SearchDBStub())

    client = TestClient(api_app.app)
    response = client.get("/findings/search", params={"source": "cve", "query": "CVE-TEST", "limit": 5})
    assert response.status_code == 200
    payload = response.json()
    assert payload[0]["entity_id"] == "CVE-TEST-1"
    assert payload[0]["pipeline_version"] == "test"


def test_batch_analyze_collects_failures(monkeypatch):
    from api import app as api_app
    from fastapi import HTTPException

    class RepoStub:
        def ping(self):
            return True

    class DBStub:
        def get_status_overview(self):
            return {
                "sources": {"cve": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0}, "urlhaus": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0}, "dread": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0, "avg_risk_score": 0.0}},
                "totals": {"total": 0, "processed": 0, "unprocessed": 0, "analyzed": 0, "analysis_coverage": 0.0},
                "pipeline_version": "test",
            }

    def fake_analyze(source, payload, persist=False):
        if payload.get("fail"):
            raise HTTPException(status_code=400, detail="forced failure")
        return api_app.AnalyzeResponse(
            entity_type="cve",
            entity_id=payload.get("id", "ok"),
            risk_level="MEDIUM",
            risk_score=5.1,
            confidence=0.7,
            diagnosis="ok",
            explanation=[],
            recommendations=[],
            feature_breakdown={},
            graph_summary={},
            graph_edges=[],
        )

    monkeypatch.setattr(api_app, "repo", RepoStub())
    monkeypatch.setattr(api_app, "analysis_db", DBStub())
    monkeypatch.setattr(api_app, "_analyze", fake_analyze)

    client = TestClient(api_app.app)
    response = client.post("/analyze/batch/cve?persist=false&limit=10", json=[{"id": "a"}, {"fail": True}, {"id": "b"}])
    assert response.status_code == 200
    payload = response.json()
    assert payload["analyzed"] == 2
    assert payload["failed"] == 1
    assert payload["items"][1]["success"] is False
