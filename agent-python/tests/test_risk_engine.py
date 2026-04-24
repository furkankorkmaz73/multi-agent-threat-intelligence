from analysis.risk_engine import RiskEngine


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