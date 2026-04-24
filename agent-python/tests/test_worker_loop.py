from main import process_source


class FakeDB:
    def __init__(self):
        self.updated = []

    def get_unprocessed(self, source, limit=10):
        return [{"_id": "doc-1"}, {"_id": "doc-2"}]

    def update_analysis(self, source, doc_id, analysis):
        self.updated.append((source, doc_id, analysis))


class FakeDiagnosticAgent:
    def analyze(self, source, doc, db=None):
        return {
            "entity_type": source,
            "entity_id": doc["_id"],
            "risk_level": "MEDIUM",
            "risk_score": 5.0,
            "confidence": 0.75,
            "diagnosis": "ok",
            "explanation": [],
            "feature_breakdown": {},
            "graph_summary": {},
            "graph_edges": [],
        }


class FakeRecommenderAgent:
    def suggest(self, analysis_result, source, original_doc):
        return [f"review-{original_doc['_id']}"]


def test_process_source_updates_each_pending_doc():
    db = FakeDB()
    processed = process_source(
        source="cve",
        db=db,
        thinker=FakeDiagnosticAgent(),
        recommender=FakeRecommenderAgent(),
        batch_size=10,
    )
    assert processed == 2
    assert len(db.updated) == 2
    assert db.updated[0][1] == "doc-1"
    assert db.updated[0][2]["recommendations"] == ["review-doc-1"]
