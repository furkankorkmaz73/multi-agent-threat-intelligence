import re

from analysis.risk_engine import RiskEngine
from core.database import DatabaseManager


class FakeDB:
    def find_related_urlhaus(self, keywords, limit=10):
        return [
            {
                "url": "http://bad.example/payload.exe",
                "threat": "malware",
                "tags": ["ransomware", "loader"],
                "url_status": "online",
                "date_added": "2026-04-21T10:00:00+00:00",
            }
        ]

    def find_related_dread(self, keywords, limit=10):
        return [
            {
                "title": "Exploit sale for CVE-2026-1111",
                "content": "RCE exploit available now",
                "category": "market",
                "author": "user1",
                "url": "http://example.onion/post/1",
                "created_at": "2026-04-21T12:00:00+00:00",
            }
        ]

    def find_related_cves(self, keywords, limit=10):
        return [
            {
                "_id": "CVE-2026-1111",
                "published": "2026-04-20T10:00:00+00:00",
            }
        ]


def test_evaluate_cve_returns_expected_structure():
    engine = RiskEngine()
    db = FakeDB()

    data = {
        "_id": "CVE-2026-1111",
        "published": "2026-04-20T10:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": "Remote code execution vulnerability in Example Product that may allow takeover."
            }
        ],
        "metrics": {
            "cvss_metric_v31": [
                {
                    "cvss_data": {
                        "base_score": 9.8
                    }
                }
            ]
        },
    }

    llm_info = {
        "products": ["Example Product"],
        "versions": ["1.0"],
        "vuln_type": "rce",
        "impact": "remote compromise",
    }

    result = engine.evaluate_cve(data=data, db=db, llm_info=llm_info)

    assert result["entity_type"] == "cve"
    assert result["entity_id"] == "CVE-2026-1111"
    assert "risk_score" in result
    assert "feature_breakdown" in result
    assert "graph_summary" in result
    assert "graph_edges" in result
    assert result["risk_score"] > 0
    assert result["confidence"] > 0


def test_evaluate_urlhaus_returns_expected_structure():
    engine = RiskEngine()
    db = FakeDB()

    data = {
        "urlhaus_id": "UH-1",
        "url": "http://bad.example/payload.exe",
        "threat": "malware",
        "tags": ["ransomware", "loader"],
        "url_status": "online",
    }

    result = engine.evaluate_urlhaus(data=data, db=db)

    assert result["entity_type"] == "urlhaus"
    assert result["entity_id"] == "UH-1"
    assert result["risk_score"] > 0
    assert "graph_summary" in result
    assert "feature_breakdown" in result


def test_evaluate_dread_returns_expected_structure():
    engine = RiskEngine()
    db = FakeDB()

    data = {
        "_id": "post-1",
        "title": "Exploit sale thread",
        "content": "Selling RCE exploit for CVE-2026-1111",
        "author": "user1",
        "category": "market",
    }

    llm_cls = {
        "category": "exploit_sale",
        "confidence": 0.91,
    }

    result = engine.evaluate_dread(data=data, db=db, llm_cls=llm_cls)

    assert result["entity_type"] == "dread"
    assert result["entity_id"] == "post-1"
    assert result["risk_score"] > 0
    assert "graph_summary" in result
    assert "feature_breakdown" in result
    assert result["confidence"] > 0


def test_graph_bonus_is_present_in_cve_breakdown():
    engine = RiskEngine()
    db = FakeDB()

    data = {
        "_id": "CVE-2026-2222",
        "published": "2026-04-20T10:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": "Remote code execution issue in Product X."
            }
        ],
        "metrics": {
            "cvss_metric_v31": [
                {
                    "cvss_data": {
                        "base_score": 8.8
                    }
                }
            ]
        },
    }

    result = engine.evaluate_cve(
        data=data,
        db=db,
        llm_info={"products": ["Product X"], "vuln_type": "rce", "impact": "takeover"},
    )

    breakdown = result["feature_breakdown"]

    assert "graph_bonus" in breakdown
    assert breakdown["graph_bonus"] >= 0

class WeakCorrelationDB:
    def find_related_urlhaus(self, keywords, limit=10):
        return [
            {
                "url": "https://refundonex.com/cloud/form_96986.pdf.ps1",
                "threat": "malware_download",
                "tags": ["ascii", "opendir", "powershell", "ps1"],
                "url_status": "offline",
                "date_added": "2026-05-04T10:00:00+00:00",
            }
        ]

    def find_related_dread(self, keywords, limit=10):
        return []


class NoEvidenceDB:
    def find_related_urlhaus(self, keywords, limit=10):
        return []

    def find_related_dread(self, keywords, limit=10):
        return []


class AcceptedUrlhausExactCveDB:
    def find_related_urlhaus(self, keywords, limit=10):
        return [
            {
                "url": "https://malware.example/dropper/CVE-2026-20104.exe",
                "threat": "malware_download",
                "tags": ["CVE-2026-20104", "loader"],
                "url_status": "online",
                "date_added": "2026-03-04T10:00:00+00:00",
            }
        ]

    def find_related_dread(self, keywords, limit=10):
        return []


class KeywordOnlyUrlhausDB:
    def find_related_urlhaus(self, keywords, limit=10):
        return [
            {
                "url": "https://payload.example/vpn-loader.exe",
                "threat": "malware_download",
                "tags": ["vpn", "gateway"],
                "url_status": "online",
                "date_added": "2026-03-04T10:00:00+00:00",
            }
        ]

    def find_related_dread(self, keywords, limit=10):
        return []


class IgnoredUrlhausNoiseDB:
    def find_related_urlhaus(self, keywords, limit=10):
        return [
            {
                "url": "https://cdn.example.invalid/download/file.bin",
                "threat": "malware_download",
                "tags": ["ascii", "opendir"],
                "url_status": "offline",
                "date_added": "",
            }
        ]

    def find_related_dread(self, keywords, limit=10):
        return []


class QueryCursor:
    def __init__(self, rows):
        self.rows = rows

    def limit(self, limit):
        return self.rows[:limit]


class QueryMatchingCollection:
    def __init__(self, rows):
        self.rows = rows

    def find(self, query):
        clauses = query.get("$or", [])
        matches = []
        for row in self.rows:
            if any(_matches_clause(row, clause) for clause in clauses):
                matches.append(row)
        return QueryCursor(matches)


def _matches_clause(row, clause):
    for field, condition in clause.items():
        pattern = condition.get("$regex", "")
        options = re.IGNORECASE if "i" in condition.get("$options", "") else 0
        value = _nested_value(row, field)
        values = value if isinstance(value, list) else [value]
        if any(re.search(pattern, str(item or ""), options) for item in values):
            return True
    return False


def _nested_value(row, field):
    current = row
    for part in field.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def _database_manager_with_urlhaus(rows):
    manager = object.__new__(DatabaseManager)
    manager.collections = {
        "urlhaus": QueryMatchingCollection(rows),
        "dread": QueryMatchingCollection([]),
        "cve": QueryMatchingCollection([]),
    }
    return manager


def test_rejected_urlhaus_candidates_do_not_drive_graph_or_confidence():
    engine = RiskEngine()
    data = {
        "_id": "CVE-2026-20100",
        "published": "2026-03-04T10:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "A vulnerability in the Lua interpreter access feature of Cisco Secure Firewall "
                    "Adaptive Security Appliance and Secure Firewall Threat Defense Software could "
                    "allow an authenticated remote attacker to cause a denial of service condition."
                ),
            }
        ],
        "metrics": {
            "cvss_metric_v31": [{"cvss_data": {"base_score": 7.7}}],
        },
    }

    result = engine.evaluate_cve(data=data, db=WeakCorrelationDB())

    assert result["evidence"]["candidate_urlhaus_count"] == 1
    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["evidence"]["sample_urlhaus_hits"] == []
    assert result["evidence"]["urlhaus_match_stats"]["accepted_match_count"] == 0
    assert result["feature_breakdown"]["urlhaus_correlation_bonus"] == 0
    assert result["feature_breakdown"]["graph_bonus"] == 0
    assert all(edge.get("relation") != "correlated_urlhaus" for edge in result["graph_edges"])
    assert result["confidence"] <= 0.70


def test_ignored_low_signal_urlhaus_candidate_does_not_change_risk_confidence_or_graph():
    engine = RiskEngine()
    data = {
        "_id": "CVE-2026-20102",
        "published": "2026-03-04T10:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "A remote code execution vulnerability in Example VPN Gateway could allow "
                    "an unauthenticated attacker to execute arbitrary commands."
                ),
            }
        ],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 9.0}}]},
    }

    baseline = engine.evaluate_cve(data=data, db=NoEvidenceDB())
    with_noise = engine.evaluate_cve(data=data, db=IgnoredUrlhausNoiseDB())

    stats = with_noise["evidence"]["urlhaus_match_stats"]
    assert stats["raw_candidate_count"] == 1
    assert stats["ignored_low_signal_count"] == 1
    assert stats["rejected_match_count"] == 0
    assert stats["accepted_match_count"] == 0
    assert with_noise["feature_breakdown"]["urlhaus_correlation_bonus"] == 0
    assert with_noise["feature_breakdown"]["correlation_signal"] == 0
    assert with_noise["feature_breakdown"]["graph_bonus"] == baseline["feature_breakdown"]["graph_bonus"]
    assert with_noise["risk_score"] == baseline["risk_score"]
    assert with_noise["confidence"] == baseline["confidence"]
    assert all(edge.get("relation") != "correlated_urlhaus" for edge in with_noise["graph_edges"])


def test_cve_generic_terms_do_not_accumulate_raw_urlhaus_candidates_from_database_provider():
    engine = RiskEngine()
    data = {
        "_id": "CVE-2026-20103",
        "published": "2026-03-04T10:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "Remote code execution vulnerability allows attackers to cause denial "
                    "of service in affected software."
                ),
            }
        ],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 8.0}}]},
    }
    db = _database_manager_with_urlhaus(
        [
            {
                "url": "https://noise.example/remote/code/execution/service",
                "threat": "malware_download",
                "tags": ["remote", "code", "execution", "service"],
                "normalized_fields": {"search_text": "remote code execution service"},
                "date_added": "2026-03-04T10:00:00+00:00",
            }
        ]
    )

    result = engine.evaluate_cve(data=data, db=db)

    assert result["evidence"]["candidate_urlhaus_count"] == 0
    assert result["evidence"]["urlhaus_match_stats"]["raw_candidate_count"] == 0
    assert result["evidence"]["urlhaus_match_stats"]["ignored_low_signal_count"] == 0
    assert result["feature_breakdown"]["urlhaus_correlation_bonus"] == 0
    assert result["feature_breakdown"]["correlation_signal"] == 0


def test_urlhaus_match_stats_explain_accepted_reason_distribution():
    engine = RiskEngine()
    data = {
        "_id": "CVE-2026-20104",
        "published": "2026-03-04T10:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": "Remote code execution vulnerability in Example VPN Gateway exploited by malware loader.",
            }
        ],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 9.0}}]},
    }

    result = engine.evaluate_cve(data=data, db=AcceptedUrlhausExactCveDB())
    stats = result["evidence"]["urlhaus_match_stats"]

    assert stats["accepted_match_count"] == 1
    assert stats["status_distribution"]["accepted"] == 1
    assert stats["accepted_reason_distribution"] == {"exact_cve": 1}
    assert stats["reason_code_distribution"]["exact_cve"] == 1


def test_urlhaus_keyword_only_match_remains_non_accepted_diagnostic_evidence():
    engine = RiskEngine()
    data = {
        "_id": "CVE-2026-20105",
        "published": "2026-03-04T10:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": "Remote code execution vulnerability in Example VPN Gateway allows command execution.",
            }
        ],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 9.0}}]},
    }

    result = engine.evaluate_cve(data=data, db=KeywordOnlyUrlhausDB())
    stats = result["evidence"]["urlhaus_match_stats"]

    assert result["evidence"]["related_urlhaus_count"] == 0
    assert stats["accepted_match_count"] == 0
    assert stats["status_distribution"]["accepted"] == 0
    assert stats["signal_candidate_count"] == 1
    assert stats["manual_review_match_count"] + stats["rejected_match_count"] == 1
    assert result["feature_breakdown"]["urlhaus_correlation_bonus"] == 0
