from analysis.risk_engine import RiskEngine


class ManualReviewDreadDB:
    def find_related_urlhaus(self, keywords, limit=25):
        return []

    def find_related_dread(self, keywords, limit=25):
        return [
            {
                "title": "VPN exploit chatter",
                "content": "Selling rce exploit access for exposed VPN appliances.",
                "category": "market",
                "created_at": "2026-05-02T00:00:00+00:00",
            }
        ]


def _cve():
    return {
        "_id": "CVE-2026-7777",
        "published": "2026-05-01T00:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": "Remote code execution vulnerability in Example VPN appliance allows unauthenticated attackers to execute code.",
            }
        ],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.0}}]},
    }


def test_manual_review_dread_does_not_leak_into_graph_or_correlation_signal():
    result = RiskEngine().evaluate_cve(_cve(), db=ManualReviewDreadDB())

    assert result["evidence"]["related_dread_count"] == 0
    assert result["evidence"]["accepted_dread_categories"] == []
    assert "exploit_sale" in result["evidence"]["observed_dread_categories"]
    assert result["feature_breakdown"]["dread_correlation_bonus"] == 0.0
    assert result["feature_breakdown"]["correlation_signal"] == 0.0
    assert result["evidence"]["dread_match_stats"]["accepted_evidence_count"] == 0
    assert (
        result["evidence"]["dread_match_stats"]["manual_review_evidence_count"]
        + result["evidence"]["dread_match_stats"]["rejected_evidence_count"]
    ) == 1
    assert all(edge["relation"] != "linked_darkweb_signal" for edge in result["graph_edges"])
