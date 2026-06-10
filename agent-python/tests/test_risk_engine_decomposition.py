from analysis.evidence import RelatedEvidenceAdapter, coerce_related_evidence_provider
from analysis.graph_builder import GraphBuilder
from analysis.risk_engine import RiskEngine
from analysis.scorers.cve import CveRiskScorer
from analysis.scorers.urlhaus import UrlhausRiskScorer


class ShapeDB:
    def find_related_urlhaus(self, keywords, limit=25):
        return [
            {
                "url": "https://malware.example/CVE-2026-7777/payload.exe",
                "threat": "malware_download",
                "tags": ["ransomware", "exploit", "rce"],
                "url_status": "online",
                "date_added": "2026-06-08T00:00:00+00:00",
            }
        ]

    def find_related_dread(self, keywords, limit=25):
        return [
            {
                "title": "Exploit sale for CVE-2026-7777",
                "content": "Selling RCE exploit for CVE-2026-7777",
                "category": "market",
                "author": "seller",
                "created_at": "2026-06-08T00:00:00+00:00",
            }
        ]

    def find_related_cves(self, keywords, limit=25):
        return [{"_id": "CVE-2026-7777"}]


def _cve_payload():
    return {
        "_id": "CVE-2026-7777",
        "published": "2026-06-01T00:00:00+00:00",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "Remote code execution vulnerability in Example VPN gateway allows "
                    "attackers to execute commands and gain initial access."
                ),
            }
        ],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 9.8}}]},
    }


def _urlhaus_payload():
    return {
        "urlhaus_id": "UH-7777",
        "url": "http://bad.example/update/payload.exe",
        "threat": "malware_download",
        "tags": ["SmartLoader", "exe", "zip"],
        "url_status": "online",
        "date_added": "2026-06-08T00:00:00+00:00",
    }


def test_risk_engine_delegates_cve_to_source_specific_scorer(monkeypatch):
    calls = []

    class FakeCveScorer:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        def evaluate(self, *, data, evidence_provider, llm_info):
            calls.append(("evaluate", data, evidence_provider, llm_info))
            return {"entity_type": "cve", "entity_id": "delegated"}

    monkeypatch.setattr("analysis.risk_engine.CveRiskScorer", FakeCveScorer)

    db = ShapeDB()
    result = RiskEngine().evaluate_cve(_cve_payload(), db=db, llm_info={"products": ["Example VPN"]})

    assert result == {"entity_type": "cve", "entity_id": "delegated"}
    assert calls[0][0] == "init"
    assert calls[1][0] == "evaluate"
    assert calls[1][1]["_id"] == "CVE-2026-7777"
    assert isinstance(calls[1][2], RelatedEvidenceAdapter)
    assert calls[1][3] == {"products": ["Example VPN"]}


def test_risk_engine_delegates_urlhaus_to_source_specific_scorer(monkeypatch):
    calls = []

    class FakeUrlhausScorer:
        def __init__(self, **kwargs):
            calls.append(("init", kwargs))

        def evaluate(self, *, data, evidence_provider):
            calls.append(("evaluate", data, evidence_provider))
            return {"entity_type": "urlhaus", "entity_id": "delegated"}

    monkeypatch.setattr("analysis.risk_engine.UrlhausRiskScorer", FakeUrlhausScorer)

    db = ShapeDB()
    result = RiskEngine().evaluate_urlhaus(_urlhaus_payload(), db=db)

    assert result == {"entity_type": "urlhaus", "entity_id": "delegated"}
    assert calls[0][0] == "init"
    assert calls[1][0] == "evaluate"
    assert calls[1][1]["urlhaus_id"] == "UH-7777"
    assert isinstance(calls[1][2], RelatedEvidenceAdapter)


def test_cve_scorer_preserves_risk_engine_response_shape():
    db = ShapeDB()
    engine_result = RiskEngine().evaluate_cve(_cve_payload(), db=db, llm_info={"products": ["Example VPN"]})
    scorer_result = CveRiskScorer(graph_builder=GraphBuilder()).evaluate(
        data=_cve_payload(),
        evidence_provider=coerce_related_evidence_provider(db),
        llm_info={"products": ["Example VPN"]},
    )

    assert set(scorer_result) == set(engine_result)
    assert set(scorer_result["evidence"]) == set(engine_result["evidence"])
    assert set(scorer_result["feature_breakdown"]) == set(engine_result["feature_breakdown"])
    assert set(scorer_result["confidence_breakdown"]) == set(engine_result["confidence_breakdown"])
    assert set(scorer_result["relation_summary"]) == set(engine_result["relation_summary"])


def test_urlhaus_scorer_preserves_risk_engine_response_shape():
    db = ShapeDB()
    engine_result = RiskEngine().evaluate_urlhaus(_urlhaus_payload(), db=db)
    scorer_result = UrlhausRiskScorer(graph_builder=GraphBuilder()).evaluate(
        data=_urlhaus_payload(),
        evidence_provider=coerce_related_evidence_provider(db),
    )

    assert set(scorer_result) == set(engine_result)
    assert set(scorer_result["evidence"]) == set(engine_result["evidence"])
    assert set(scorer_result["feature_breakdown"]) == set(engine_result["feature_breakdown"])
    assert set(scorer_result["confidence_breakdown"]) == set(engine_result["confidence_breakdown"])
    assert set(scorer_result["relation_summary"]) == set(engine_result["relation_summary"])
