from datetime import datetime, timezone

from fastapi.testclient import TestClient

from api.app import app


class FakeRepo:
    def ping(self):
        return True

    def get_recent_findings(self, source: str, limit: int = 10):
        return [
            {
                "_id": "CVE-2026-1111",
                "analysis": {
                    "entity_id": "CVE-2026-1111",
                    "risk_level": "HIGH",
                    "risk_score": 8.7,
                    "confidence": 0.91,
                    "diagnosis": "High-risk CVE finding.",
                    "analyzed_at": datetime(2026, 4, 23, 1, 0, 0, tzinfo=timezone.utc),
                },
            }
        ][:limit]

    def get_top_risky_findings(self, source=None, limit: int = 10):
        docs = [
            {
                "_source": "urlhaus",
                "urlhaus_id": "UH-1",
                "analysis": {
                    "entity_id": "UH-1",
                    "risk_level": "MEDIUM",
                    "risk_score": 6.7,
                    "confidence": 0.60,
                    "diagnosis": "Malicious URL intelligence evaluated as MEDIUM.",
                    "analyzed_at": datetime(2026, 4, 23, 1, 2, 0, tzinfo=timezone.utc),
                },
            },
            {
                "_source": "cve",
                "_id": "CVE-2026-1111",
                "analysis": {
                    "entity_id": "CVE-2026-1111",
                    "risk_level": "HIGH",
                    "risk_score": 8.7,
                    "confidence": 0.91,
                    "diagnosis": "High-risk CVE finding.",
                    "analyzed_at": datetime(2026, 4, 23, 1, 0, 0, tzinfo=timezone.utc),
                },
            },
        ]
        if source:
            docs = [doc for doc in docs if doc["_source"] == source]
        return docs[:limit]

    def get_cve_analysis_docs(self, limit: int | None = None):
        docs = [
            {
                "_id": "CVE-2026-1111",
                "published": "2026-04-23T00:00:00+00:00",
                "descriptions": [{"lang": "en", "value": "Remote code execution in Example Product."}],
                "analysis": {
                    "risk_score": 8.0,
                    "risk_level": "HIGH",
                    "confidence": 0.91,
                    "diagnosis": "High-risk CVE finding.",
                    "evidence": {"cvss_score": 9.8, "age_days": 1, "related_urlhaus_count": 2, "related_dread_count": 1, "keywords": ["rce", "loader"]},
                    "feature_breakdown": {"base_cvss_component": 5.39, "recentness_bonus": 0.2, "urlhaus_correlation_bonus": 1.0, "dread_correlation_bonus": 0.8, "graph_bonus": 0.61, "pre_graph_score": 7.39, "final_score": 8.0},
                    "graph_summary": {"centrality_score": 0.66, "average_edge_confidence": 0.83},
                    "counterfactuals": {"score_without_graph": 7.39, "score_without_urlhaus": 7.0, "score_without_dread": 7.2, "score_without_llm_context": 7.8},
                    "source_contributions": {"base_component": 5.39, "graph_component": 0.61},
                    "relation_summary": {"relation_count": 3},
                },
            },
            {
                "_id": "CVE-2026-2222",
                "published": "2026-04-22T00:00:00+00:00",
                "descriptions": [{"lang": "en", "value": "Privilege escalation issue."}],
                "analysis": {
                    "risk_score": 5.1,
                    "risk_level": "MEDIUM",
                    "confidence": 0.72,
                    "diagnosis": "Medium-risk CVE finding.",
                    "evidence": {"cvss_score": 5.0, "age_days": 2, "related_urlhaus_count": 1, "related_dread_count": 0, "keywords": ["privilege", "escalation"]},
                    "feature_breakdown": {"base_cvss_component": 2.75, "recentness_bonus": 0.7, "urlhaus_correlation_bonus": 0.9, "dread_correlation_bonus": 0.0, "graph_bonus": 0.75, "pre_graph_score": 4.35, "final_score": 5.1},
                    "graph_summary": {"centrality_score": 0.75, "average_edge_confidence": 0.79},
                    "counterfactuals": {"score_without_graph": 4.35, "score_without_urlhaus": 4.2, "score_without_dread": 5.1, "score_without_llm_context": 5.1},
                    "source_contributions": {"base_component": 2.75, "graph_component": 0.75},
                    "relation_summary": {"relation_count": 2},
                },
            },
        ]
        return docs[:limit] if limit else docs

    def get_finding_by_entity_id(self, source: str, entity_id: str):
        if source == "cve" and entity_id == "CVE-2026-1111":
            return {
                "_id": "CVE-2026-1111",
                "analysis": {
                    "entity_id": "CVE-2026-1111",
                    "risk_level": "HIGH",
                    "risk_score": 8.7,
                    "confidence": 0.91,
                    "diagnosis": "High-risk CVE finding.",
                    "explanation": ["Exploitability is high.", "Cross-source evidence exists."],
                    "recommendations": ["Patch immediately.", "Monitor related assets."],
                    "evidence": {"cvss_score": 9.8, "related_urlhaus_count": 2},
                    "feature_breakdown": {"base_cvss_component": 5.39, "graph_bonus": 0.82},
                    "graph_summary": {"node_count": 8, "edge_count": 7, "centrality_score": 0.68},
                    "graph_edges": [
                        {
                            "source": "cve:CVE-2026-1111",
                            "target": "product:example-product",
                            "relation": "affects_product",
                            "weight": 1.0,
                        }
                    ],
                    "analyzed_at": datetime(2026, 4, 23, 1, 0, 0, tzinfo=timezone.utc),
                },
            }
        return None


def build_client(monkeypatch):
    fake_repo = FakeRepo()
    monkeypatch.setattr("api.app.repo", fake_repo)
    return TestClient(app)


def test_health(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "threat-agent-api"
    assert data["database"] == "ok"


def test_sources(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get("/sources")

    assert response.status_code == 200
    data = response.json()
    assert "sources" in data
    assert data["sources"] == ["cve", "urlhaus", "dread"]


def test_recent_findings(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get("/findings/recent", params={"source": "cve", "limit": 5})

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["source"] == "cve"
    assert data[0]["entity_id"] == "CVE-2026-1111"
    assert data[0]["risk_level"] == "HIGH"


def test_top_findings(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get("/findings/top", params={"limit": 5})

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "source" in data[0]
    assert "risk_score" in data[0]


def test_top_findings_filtered(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get("/findings/top", params={"source": "cve", "limit": 5})

    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["source"] == "cve"


def test_finding_detail_success(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get(
        "/findings/detail",
        params={"source": "cve", "entity_id": "CVE-2026-1111"},
    )

    assert response.status_code == 200
    data = response.json()
    assert data["source"] == "cve"
    assert data["entity_id"] == "CVE-2026-1111"
    assert data["risk_level"] == "HIGH"
    assert isinstance(data["explanation"], list)
    assert isinstance(data["recommendations"], list)
    assert isinstance(data["feature_breakdown"], dict)
    assert isinstance(data["graph_summary"], dict)
    assert isinstance(data["graph_edges"], list)


def test_finding_detail_not_found(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get(
        "/findings/detail",
        params={"source": "cve", "entity_id": "CVE-DOES-NOT-EXIST"},
    )

    assert response.status_code == 404
    data = response.json()
    assert data["detail"] == "Finding not found"

def test_evaluation_cve_snapshot(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get("/evaluation/cve?limit=10&top_k=2")
    assert response.status_code == 200

    data = response.json()
    assert data["summary"]["record_count"] == 2
    assert len(data["rows"]) == 2
    assert data["rows"][0]["cve_id"].startswith("CVE-")


def test_evaluation_cve_summary(monkeypatch):
    client = build_client(monkeypatch)

    response = client.get("/evaluation/cve/summary?limit=10&top_k=2")
    assert response.status_code == 200

    data = response.json()
    assert data["record_count"] == 2
    assert data["top_k"] == 2
    assert "avg_lift_from_cvss_only" in data
