from types import SimpleNamespace

import agents.llm_helper as llm_helper


class _FakeCompletions:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def create(self, **kwargs):
        self.calls += 1
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=response)
                )
            ]
        )


class _FakeClient:
    def __init__(self, responses):
        self.completions = _FakeCompletions(responses)
        self.chat = SimpleNamespace(completions=self.completions)


def test_extract_cve_info_returns_empty_when_disabled(monkeypatch):
    monkeypatch.setattr(llm_helper, "client", None)

    assert llm_helper.extract_cve_info("Remote code execution in product X") == {}


def test_extract_cve_info_validates_schema(monkeypatch):
    fake = _FakeClient([
        '{"products":["VPN Gateway",123],"versions":["1.0"],"vuln_type":"rce","impact":"remote code execution","ignored":"x"}'
    ])
    monkeypatch.setattr(llm_helper, "client", fake)

    result = llm_helper.extract_cve_info("Remote code execution in a VPN gateway")

    assert result == {
        "products": ["VPN Gateway", "123"],
        "versions": ["1.0"],
        "vuln_type": "rce",
        "impact": "remote code execution",
    }


def test_classify_dread_clamps_confidence_and_rejects_unknown_category(monkeypatch):
    fake = _FakeClient(['{"category":"unknown","confidence":5}'])
    monkeypatch.setattr(llm_helper, "client", fake)

    result = llm_helper.classify_dread("selling access")

    assert result == {"category": "noise", "confidence": 1.0}


def test_json_fence_is_accepted(monkeypatch):
    fake = _FakeClient(['```json\n{"category":"access_sale","confidence":0.72}\n```'])
    monkeypatch.setattr(llm_helper, "client", fake)

    assert llm_helper.classify_dread("vpn access for sale") == {
        "category": "access_sale",
        "confidence": 0.72,
    }


def test_retry_on_transient_error(monkeypatch):
    fake = _FakeClient([
        RuntimeError("rate limited"),
        '{"products":["Firewall"],"versions":[],"vuln_type":"auth_bypass","impact":"access"}',
    ])
    monkeypatch.setattr(llm_helper, "client", fake)
    monkeypatch.setattr(llm_helper, "LLM_MAX_RETRIES", 1)
    monkeypatch.setattr(llm_helper.time, "sleep", lambda *_args, **_kwargs: None)

    result = llm_helper.extract_cve_info("authentication bypass in firewall")

    assert fake.completions.calls == 2
    assert result["products"] == ["Firewall"]
    assert result["vuln_type"] == "auth_bypass"


def test_generate_explanation_returns_text(monkeypatch):
    fake = _FakeClient(["Prioritize this because it is online malware infrastructure."])
    monkeypatch.setattr(llm_helper, "client", fake)

    result = llm_helper.generate_explanation({"source": "urlhaus", "risk_score": 6.8})

    assert "online malware" in result
