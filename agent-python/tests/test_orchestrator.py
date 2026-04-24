from agents.orchestrator import ThreatAnalysisOrchestrator


class DummyDB:
    def find_related_urlhaus(self, keywords, limit=25):
        return [{"url": "http://bad.test/payload", "threat": "malware_download", "tags": ["phishing"], "url_status": "online"}]

    def find_related_dread(self, keywords, limit=25):
        return [{"title": "exploit sale for vpn", "content": "selling RCE exploit for vpn gateway", "category": "exploit_sale", "url": "dread://post/1"}]

    def find_related_cves(self, keywords, limit=25):
        return []


def test_orchestrator_returns_plan_trace_and_critic_review():
    orch = ThreatAnalysisOrchestrator()
    payload = {
        "_id": "CVE-2026-9999",
        "published": "2026-04-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Critical remote code execution in VPN gateway allows unauthenticated attackers."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
    }
    result = orch.run("cve", payload, db=DummyDB())
    assert result is not None
    assert len(result["execution_plan"]) >= 5
    assert result["critic_review"]["status"] in {"passed", "needs-review"}
    assert any(step["agent"] == "planner" for step in result["orchestration_trace"])
    assert "agent_outputs" in result
