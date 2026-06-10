from agents.orchestrator import ThreatAnalysisOrchestrator
from orchestration.policy import ExecutionLimits, TimeoutBudgetPolicy
from orchestration.state import AnalysisState


class EmptyDB:
    def find_related_urlhaus(self, keywords, limit=25):
        return []

    def find_related_dread(self, keywords, limit=25):
        return []

    def find_related_cves(self, keywords, limit=25):
        return []


class FailingEvidenceDB(EmptyDB):
    def find_related_urlhaus(self, keywords, limit=25):
        raise RuntimeError("evidence unavailable")


class CountingRiskEngine:
    def __init__(self, fail=False):
        self.calls = []
        self.fail = fail

    def evaluate_cve(self, data, db=None, llm_info=None):
        self.calls.append(("cve", db is None, dict(llm_info or {})))
        if self.fail:
            raise RuntimeError("risk failed")
        if db is not None:
            db.find_related_urlhaus(["vpn"])
        return _result("cve", data.get("_id", "CVE-TEST"), 7.0)

    def evaluate_urlhaus(self, data, db=None):
        self.calls.append(("urlhaus", db is None, {}))
        if self.fail:
            raise RuntimeError("risk failed")
        return _result("urlhaus", data.get("url", "http://bad.test/payload"), 6.2)

    def evaluate_dread(self, data, db=None, llm_cls=None):
        self.calls.append(("dread", db is None, dict(llm_cls or {})))
        if self.fail:
            raise RuntimeError("risk failed")
        return _result("dread", data.get("title", "post"), 4.4)


class ActionCritic:
    def __init__(self, action):
        self.action = action
        self.calls = 0

    def review(self, analysis_result):
        self.calls += 1
        if self.calls == 1:
            return {
                "status": "needs-review",
                "issues": ["critic requested action"],
                "warnings": [],
                "summary": "first pass",
                "actions": [self.action],
            }
        return {"status": "passed", "issues": [], "warnings": [], "summary": "second pass"}


class AlwaysRetryCritic:
    def review(self, analysis_result):
        return {
            "status": "needs-review",
            "issues": ["retry"],
            "warnings": [],
            "summary": "retry",
            "actions": ["retry_current_step"],
        }


def _result(source, entity_id, score):
    return {
        "entity_type": source,
        "entity_id": entity_id,
        "risk_score": score,
        "risk_level": "HIGH" if score >= 6.5 else "MEDIUM",
        "confidence": 0.8,
        "diagnosis": "stub",
        "explanation": ["stub"],
        "evidence": {"related_urlhaus_count": 0, "related_dread_count": 0},
        "feature_breakdown": {"final_score": score},
        "graph_summary": {"node_count": 1, "edge_count": 0, "centrality_score": 0.0},
        "graph_edges": [],
        "counterfactuals": {},
        "source_contributions": {},
        "relation_summary": {},
        "orchestration_trace": [{"agent": "risk", "action": "score", "status": "completed", "details": {}}],
    }


def _cve_payload():
    return {
        "_id": "CVE-2026-9999",
        "published": "2026-04-01T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Critical remote code execution in VPN gateway."}],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 9.8}}]},
    }


def test_normal_cve_flow_preserves_public_shape():
    result = ThreatAnalysisOrchestrator().run("cve", _cve_payload(), db=EmptyDB())

    assert result["entity_type"] == "cve"
    assert result["entity_id"] == "CVE-2026-9999"
    assert "execution_plan" in result
    assert "critic_review" in result
    assert "agent_outputs" in result
    assert "orchestration_trace" in result
    assert any(step["status"] in {"pending", "completed"} for step in result["execution_plan"])


def test_urlhaus_flow_uses_stateful_orchestrator():
    result = ThreatAnalysisOrchestrator().run("urlhaus", {"url": "http://bad.test/payload.exe", "threat": "malware_download"}, db=EmptyDB())

    assert result["entity_type"] == "urlhaus"
    assert result["execution_plan"]
    assert result["critic_review"]["status"] in {"passed", "needs-review"}


def test_dread_flow_uses_stateful_orchestrator():
    result = ThreatAnalysisOrchestrator().run("dread", {"title": "Exploit sale", "content": "selling vpn rce"}, db=EmptyDB())

    assert result["entity_type"] == "dread"
    assert result["execution_plan"]
    assert result["critic_review"]["status"] in {"passed", "needs-review"}


def test_llm_disabled_falls_back_to_deterministic_context(monkeypatch):
    import orchestration.engine as engine_module

    monkeypatch.setattr(engine_module.llm_helper, "is_enabled", lambda: False)
    result = ThreatAnalysisOrchestrator(risk_engine=CountingRiskEngine()).run("cve", _cve_payload(), db=EmptyDB())

    context_steps = [step for step in result["execution_plan"] if step["action"] == "extract-deterministic-context"]
    assert context_steps
    assert result["risk_score"] == 7.0


def test_evidence_provider_failure_retries_with_null_provider():
    risk_engine = CountingRiskEngine()
    result = ThreatAnalysisOrchestrator(risk_engine=risk_engine).run("cve", _cve_payload(), db=FailingEvidenceDB())

    assert result["risk_score"] == 7.0
    assert len(risk_engine.calls) == 2
    assert risk_engine.calls[-1][1] is True
    assert any(step.get("fallback") == "null_evidence_provider" for step in result["orchestration_trace"])


def test_risk_step_failure_returns_structured_fallback():
    result = ThreatAnalysisOrchestrator(risk_engine=CountingRiskEngine(fail=True)).run("cve", _cve_payload(), db=EmptyDB())

    assert result["entity_id"] == "CVE-2026-9999"
    assert result["risk_score"] == 0.0
    assert result["confidence"] == 0.0
    assert result["critic_review"]["status"] in {"passed", "needs-review"}


def test_critic_triggered_retry_is_bounded_and_recomputes_risk():
    risk_engine = CountingRiskEngine()
    result = ThreatAnalysisOrchestrator(
        risk_engine=risk_engine,
        critic=ActionCritic("retry_current_step"),
        limits=ExecutionLimits(max_retries=1, max_replans=1, max_total_steps=16),
    ).run("cve", _cve_payload(), db=EmptyDB())

    assert len(risk_engine.calls) == 2
    assert result["critic_review"]["status"] == "passed"


def test_critic_triggered_replan_adds_missing_evidence_step():
    result = ThreatAnalysisOrchestrator(
        risk_engine=CountingRiskEngine(),
        critic=ActionCritic("add_missing_evidence_step"),
        limits=ExecutionLimits(max_retries=1, max_replans=1, max_total_steps=16),
    ).run("cve", _cve_payload(), db=EmptyDB())

    assert any(step["action"] == "retrieve-missing-evidence" for step in result["execution_plan"])
    assert result["critic_review"]["status"] == "passed"


def test_retry_limit_prevents_infinite_loop():
    risk_engine = CountingRiskEngine()
    result = ThreatAnalysisOrchestrator(
        risk_engine=risk_engine,
        critic=AlwaysRetryCritic(),
        limits=ExecutionLimits(max_retries=1, max_replans=1, max_total_steps=10),
    ).run("cve", _cve_payload(), db=EmptyDB())

    assert len(risk_engine.calls) == 2
    risk_steps = [step for step in result["orchestration_trace"] if step.get("agent") == "risk" and step.get("action") == "compute-dynamic-risk"]
    assert len(risk_steps) <= 2


def test_replan_limit_prevents_infinite_loop():
    result = ThreatAnalysisOrchestrator(
        risk_engine=CountingRiskEngine(),
        critic=ActionCritic("add_missing_evidence_step"),
        limits=ExecutionLimits(max_retries=0, max_replans=0, max_total_steps=10),
    ).run("cve", _cve_payload(), db=EmptyDB())

    assert not any(step["action"] == "retrieve-missing-evidence" for step in result["execution_plan"])


def test_timeout_fallback_is_structured():
    result = ThreatAnalysisOrchestrator(
        timeout_policy=TimeoutBudgetPolicy(timeout_actions=frozenset({"compute-dynamic-risk"})),
    ).run("cve", _cve_payload(), db=EmptyDB())

    assert result["risk_score"] == 0.0
    assert result["evidence"]["errors"][0]["error"] == "step_timeout"
    assert any(step.get("error") == "step_timeout" for step in result["orchestration_trace"])


def test_analysis_state_serialization_is_deterministic():
    state = AnalysisState(source="cve", entity_id="CVE-2026-1", raw_input={"_id": "CVE-2026-1"})

    assert state.to_dict() == state.to_dict()
    assert state.to_dict()["final_status"] == "pending"


def test_public_response_shape_compatibility_contains_existing_keys():
    result = ThreatAnalysisOrchestrator().run("cve", _cve_payload(), db=EmptyDB())
    required = {
        "entity_type",
        "entity_id",
        "risk_score",
        "risk_level",
        "confidence",
        "diagnosis",
        "explanation",
        "feature_breakdown",
        "graph_summary",
        "graph_edges",
        "orchestration_trace",
        "execution_plan",
        "critic_review",
        "agent_outputs",
    }

    assert required.issubset(result)
    assert result["orchestration_trace"][0]["agent"] == "planner"
