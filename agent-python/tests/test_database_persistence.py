from datetime import datetime

from core.database import DatabaseManager


class FakeCursor(list):
    def limit(self, _n):
        return self


class FakeCollection:
    def __init__(self, total=0, processed=0, analyzed=0):
        self.created_indexes = []
        self.last_update = None
        self.total = total
        self.processed = processed
        self.analyzed = analyzed

    def create_index(self, spec):
        self.created_indexes.append(spec)

    def update_one(self, flt, update, upsert=False):
        self.last_update = {"filter": flt, "update": update, "upsert": upsert}

    def count_documents(self, query):
        if query == {}:
            return self.total
        if query == {"processed": True}:
            return self.processed
        if query == {"analysis": {"$exists": True}}:
            return self.analyzed
        return self.analyzed

    def find(self, query, projection=None):
        if "analysis.risk_score" in query:
            return FakeCursor([{"analysis": {"risk_score": 8.0}} for _ in range(max(self.analyzed, 1))])
        return FakeCursor([])


class FakeDBManager(DatabaseManager):
    def __init__(self):
        self.client = object()
        self.db = object()
        self.collections = {"cve": FakeCollection(), "urlhaus": FakeCollection(), "dread": FakeCollection()}
        self._ensure_indexes()


def test_update_analysis_persists_history_and_meta():
    db = FakeDBManager()
    analysis = {
        "entity_id": "CVE-2026-9999",
        "risk_score": 8.7,
        "risk_level": "HIGH",
        "confidence": 0.91,
        "recommendations": ["patch"],
        "feature_breakdown": {
            "urlhaus_avg_semantic_score": 0.61,
            "dread_avg_semantic_score": 0.22,
        },
        "graph_summary": {"centrality_score": 0.44},
    }
    db.update_analysis("cve", "CVE-2026-9999", analysis)

    saved = db.collections["cve"].last_update
    assert saved is not None
    assert saved["filter"] == {"_id": "CVE-2026-9999"}

    set_payload = saved["update"]["$set"]
    push_payload = saved["update"]["$push"]["analysis_history"]

    assert set_payload["processed"] is True
    assert set_payload["analysis"]["persistence_meta"]["pipeline_version"]
    assert isinstance(set_payload["analysis_updated_at"], datetime)
    assert push_payload["$slice"] == -10
    history_entry = push_payload["$each"][0]
    assert history_entry["risk_score"] == 8.7
    assert history_entry["semantic_signal"] == 0.61
    assert history_entry["graph_centrality"] == 0.44


def test_ensure_indexes_runs_for_all_sources():
    db = FakeDBManager()
    assert len(db.collections["cve"].created_indexes) >= 3
    assert len(db.collections["urlhaus"].created_indexes) >= 3
    assert len(db.collections["dread"].created_indexes) >= 3


def test_persist_analysis_result_uses_upsert_and_doc_resolution():
    db = FakeDBManager()
    original = {"url": "https://mal.example/test", "threat": "malware"}
    analysis = {
        "entity_id": "https://mal.example/test",
        "risk_score": 7.3,
        "risk_level": "HIGH",
        "confidence": 0.8,
        "recommendations": ["block domain"],
        "feature_breakdown": {},
        "graph_summary": {},
    }
    doc_id = db.persist_analysis_result("urlhaus", original, analysis)
    saved = db.collections["urlhaus"].last_update
    assert doc_id == "https://mal.example/test"
    assert saved["upsert"] is True
    assert saved["update"]["$set"]["processed"] is True
    assert saved["update"]["$set"]["analysis"]["persistence_meta"]["persist_mode"] == "api"


def test_status_overview_aggregates_source_counts():
    db = FakeDBManager()
    db.collections = {
        "cve": FakeCollection(total=10, processed=6, analyzed=5),
        "urlhaus": FakeCollection(total=4, processed=4, analyzed=4),
        "dread": FakeCollection(total=2, processed=1, analyzed=1),
    }
    overview = db.get_status_overview()
    assert overview["totals"]["total"] == 16
    assert overview["totals"]["analyzed"] == 10
    assert overview["sources"]["cve"]["analysis_coverage"] == 0.5
