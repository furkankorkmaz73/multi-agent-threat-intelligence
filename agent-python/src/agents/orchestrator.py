from __future__ import annotations

from typing import Any, Dict, Optional

from agents.correlation import CorrelationAgent
from agents.critic import CriticAgent
from agents.graph import GraphAnalysisAgent
from agents.llm_helper import classify_dread, extract_cve_info
from agents.planner import PlannerAgent
from agents.risk_assessment import RiskAssessmentAgent
from analysis.risk_engine import RiskEngine


class ThreatAnalysisOrchestrator:
    def __init__(self) -> None:
        self.planner = PlannerAgent()
        self.correlation_agent = CorrelationAgent()
        self.graph_agent = GraphAnalysisAgent()
        self.risk_agent = RiskAssessmentAgent()
        self.critic = CriticAgent()
        self.risk_engine = RiskEngine()

    def run(self, source: str, data: Dict[str, Any], db: Optional[Any] = None) -> Optional[Dict[str, Any]]:
        execution_plan = self.planner.build_plan(source=source, data=data)

        if source == "cve":
            description = self._get_primary_description(data)
            llm_info = extract_cve_info(description) if description else {}
            result = self.risk_engine.evaluate_cve(data=data, db=db, llm_info=llm_info)
        elif source == "urlhaus":
            result = self.risk_engine.evaluate_urlhaus(data=data, db=db)
        elif source == "dread":
            combined = f"{data.get('title', '')} {data.get('content', '')}".strip().lower()
            llm_cls = classify_dread(combined) if combined else {}
            result = self.risk_engine.evaluate_dread(data=data, db=db, llm_cls=llm_cls)
        else:
            return None

        critic_review = self.critic.review(result)
        result["execution_plan"] = execution_plan
        result["critic_review"] = critic_review
        result["agent_outputs"] = {
            "correlation": self.correlation_agent.summarize(result),
            "graph": self.graph_agent.summarize_for_trace(result.get("graph_summary", {})),
            "risk": self.risk_agent.summarize(result),
            "critic": critic_review,
        }

        trace = list(result.get("orchestration_trace", []))
        trace.insert(0, {"agent": "planner", "action": "draft-execution-plan", "status": "completed", "details": {"steps": len(execution_plan), "source": source}})
        trace.append({"agent": "critic", "action": "review-analysis-artifacts", "status": critic_review.get("status", "completed"), "details": {"warnings": len(critic_review.get("warnings", [])), "issues": len(critic_review.get("issues", []))}})
        trace.append({"agent": "recommender", "action": "await-recommendation-stage", "status": "completed", "details": {"source": source}})
        result["orchestration_trace"] = trace
        return result

    def _get_primary_description(self, data: Dict[str, Any]) -> str:
        descriptions = data.get("descriptions", []) or []
        for item in descriptions:
            if item.get("lang", "").lower() == "en":
                return item.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""
