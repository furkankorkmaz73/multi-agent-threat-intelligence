import re

from analysis.evidence import NullRelatedEvidenceProvider, RelatedEvidenceAdapter, coerce_related_evidence_provider
from core.database import DatabaseManager, _urlhaus_retrieval_terms


class FakeCursor:
    def __init__(self, rows):
        self.rows = rows

    def limit(self, limit):
        return self.rows[:limit]


class RecordingCollection:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.queries = []

    def find(self, query, projection=None):
        self.queries.append({"query": query, "projection": projection})
        return FakeCursor(self.rows)


def test_none_related_evidence_provider_returns_empty_results():
    provider = coerce_related_evidence_provider(None)

    assert isinstance(provider, NullRelatedEvidenceProvider)
    assert provider.find_related_urlhaus(["rce"], limit=3) == []
    assert provider.find_related_dread(["rce"], limit=3) == []
    assert provider.find_related_cves(["rce"], limit=3) == []


def test_related_evidence_adapter_preserves_existing_fake_db_methods():
    class PartialFakeDB:
        def __init__(self):
            self.calls = []

        def find_related_dread(self, keywords, limit=20):
            self.calls.append(("dread", keywords, limit))
            return [{"title": "Exploit thread"}]

    db = PartialFakeDB()
    provider = coerce_related_evidence_provider(db)

    assert isinstance(provider, RelatedEvidenceAdapter)
    assert provider.find_related_dread(["vpn"], limit=7) == [{"title": "Exploit thread"}]
    assert provider.find_related_urlhaus(["vpn"], limit=7) == []
    assert provider.find_related_cves(["vpn"], limit=7) == []
    assert db.calls == [("dread", ["vpn"], 7)]


def _database_manager_with_urlhaus_rows(rows):
    manager = object.__new__(DatabaseManager)
    manager.collections = {
        "urlhaus": RecordingCollection(rows),
        "dread": RecordingCollection([]),
        "cve": RecordingCollection([]),
    }
    return manager


def test_urlhaus_generic_terms_do_not_query_mongodb():
    manager = _database_manager_with_urlhaus_rows([{"url": "https://noise.example/payload"}])

    result = manager.find_related_urlhaus(
        [
            "remote",
            "code",
            "execution",
            "vulnerability",
            "attacker",
            "service",
            "overflow",
            "users",
            "windows",
            "server",
        ],
        limit=5,
    )

    assert result == []
    assert manager.collections["urlhaus"].queries == []
    assert _urlhaus_retrieval_terms(["remote", "code", "execution", "windows"]) == []


def test_urlhaus_strong_terms_still_query_mongodb():
    row = {"url": "https://payload.example/CVE-2026-1234/examplevpn-loader"}
    manager = _database_manager_with_urlhaus_rows([row])

    result = manager.find_related_urlhaus(
        ["remote", "CVE-2026-1234", "examplevpn", "loader", "1.2.3"],
        limit=5,
    )

    assert result == [row]
    indexed_query = manager.collections["urlhaus"].queries[0]["query"]
    assert indexed_query == {"normalized_fields.keywords": {"$in": ["cve-2026-1234", "examplevpn", "loader"]}}

    query = manager.collections["urlhaus"].queries[1]["query"]
    regex_values = [clause[field]["$regex"].lower() for clause in query["$or"] for field in clause]
    assert re.escape("cve-2026-1234") in regex_values
    assert "examplevpn" in regex_values
    assert "loader" in regex_values
    assert "remote" not in regex_values
    assert re.escape("1.2.3") not in regex_values


def test_indexed_keyword_lookup_can_satisfy_related_evidence_without_regex_fallback():
    row = {"url": "https://payload.example/CVE-2026-1234/examplevpn-loader"}
    manager = _database_manager_with_urlhaus_rows([row])

    result = manager.find_related_urlhaus(["CVE-2026-1234", "examplevpn", "loader"], limit=1)

    assert result == [row]
    assert len(manager.collections["urlhaus"].queries) == 1
    assert manager.collections["urlhaus"].queries[0]["query"] == {
        "normalized_fields.keywords": {"$in": ["cve-2026-1234", "examplevpn", "loader"]}
    }
