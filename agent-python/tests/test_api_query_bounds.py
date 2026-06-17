import pymongo

from api.repository import APIRepository, FINDING_SUMMARY_PROJECTION as API_SUMMARY_PROJECTION
from core.database import DatabaseManager, FINDING_SUMMARY_PROJECTION as CORE_SUMMARY_PROJECTION


class RecordingCursor:
    def __init__(self, docs=None):
        self.docs = docs or []
        self.sort_spec = None
        self.limit_value = None

    def sort(self, spec):
        self.sort_spec = spec
        return self

    def limit(self, value):
        self.limit_value = value
        return self

    def __iter__(self):
        return iter(self.docs)


class RecordingCollection:
    def __init__(self, docs=None):
        self.cursor = RecordingCursor(docs)
        self.find_calls = []

    def find(self, query, projection=None):
        self.find_calls.append({"query": query, "projection": projection})
        return self.cursor


def test_top_findings_python_sorted_modes_use_projection_and_candidate_window():
    collection = RecordingCollection()
    repo = APIRepository.__new__(APIRepository)
    repo.collections = {"cve": collection}

    docs = repo._candidate_top_findings("cve", limit=5, mode="needs_review")

    assert docs == []
    assert collection.find_calls[0]["projection"] == API_SUMMARY_PROJECTION
    assert collection.cursor.limit_value == 100
    assert collection.cursor.sort_spec == [
        ("analysis.risk_score", pymongo.DESCENDING),
        ("analysis.confidence", pymongo.DESCENDING),
        ("analysis.analyzed_at", pymongo.DESCENDING),
    ]


def test_top_findings_index_sorted_modes_keep_requested_limit():
    collection = RecordingCollection()
    repo = APIRepository.__new__(APIRepository)
    repo.collections = {"urlhaus": collection}

    repo._candidate_top_findings("urlhaus", limit=7, mode="top")

    assert collection.find_calls[0]["projection"] == API_SUMMARY_PROJECTION
    assert collection.cursor.limit_value == 7


def test_search_analyzed_findings_uses_summary_projection_and_limit():
    collection = RecordingCollection()
    db = DatabaseManager.__new__(DatabaseManager)
    db.collections = {"cve": collection}

    docs = db.search_analyzed_findings("cve", "vpn", limit=9)

    assert docs == []
    assert collection.find_calls[0]["projection"] == CORE_SUMMARY_PROJECTION
    assert collection.cursor.limit_value == 9
    assert collection.cursor.sort_spec == [("analysis.risk_score", pymongo.DESCENDING), ("_id", pymongo.DESCENDING)]
