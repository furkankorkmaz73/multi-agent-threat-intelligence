from analysis.semantic_similarity import semantic_similarity
from agents.orchestrator import ThreatAnalysisOrchestrator
from core.database import DatabaseManager


class MinimalCollection:
    def __init__(self):
        self.docs = {}
        self.indexes = []
    def create_index(self, *args, **kwargs):
        self.indexes.append((args, kwargs))
    def update_one(self, query, update, upsert=False):
        doc_id = query.get("_id")
        doc = self.docs.setdefault(doc_id, {"_id": doc_id})
        doc.update(update.get("$set", {}))
        for key, value in update.get("$push", {}).items():
            entry = value.get("$each", [value])[0] if isinstance(value, dict) else value
            doc.setdefault(key, []).append(entry)
            if isinstance(value, dict) and "$slice" in value:
                doc[key] = doc[key][value["$slice"]:]
    def count_documents(self, query):
        if not query:
            return len(self.docs)
        if query == {"processed": True}:
            return sum(1 for d in self.docs.values() if d.get("processed") is True)
        if query == {"analysis": {"$exists": True}}:
            return sum(1 for d in self.docs.values() if "analysis" in d)
        return 0
    def find(self, *args, **kwargs):
        return []


class MinimalDB(DatabaseManager):
    def __init__(self):
        self.collections = {"cve": MinimalCollection(), "urlhaus": MinimalCollection(), "dread": MinimalCollection()}


def test_semantic_fallback_handles_empty_inputs():
    assert semantic_similarity("", "") == 0.0
    assert 0.0 <= semantic_similarity("vpn rce", "remote code execution in vpn") <= 1.0


def test_orchestrator_handles_minimal_payload_without_db():
    result = ThreatAnalysisOrchestrator().run("cve", {"_id": "CVE-EMPTY"}, db=None)
    assert result["entity_id"] == "CVE-EMPTY"
    assert result["critic_review"]["status"] in {"passed", "needs-review"}


def test_persist_history_is_capped_and_meta_is_written():
    db = MinimalDB()
    for i in range(12):
        db.persist_analysis_result("cve", {"_id": "CVE-HISTORY"}, {"entity_id": "CVE-HISTORY", "risk_score": i, "risk_level": "LOW", "confidence": 0.5, "feature_breakdown": {}, "graph_summary": {}, "recommendations": []})
    doc = db.collections["cve"].docs["CVE-HISTORY"]
    assert doc["processed"] is True
    assert len(doc["analysis_history"]) == 10
    assert doc["analysis"]["persistence_meta"]["persist_mode"] == "api"
