from __future__ import annotations

from typing import Any, Dict, Optional

from agents import llm_helper
from agents.correlation import CorrelationAgent
from agents.critic import CriticAgent
from agents.graph import GraphAnalysisAgent
from agents.planner import PlannerAgent
from agents.recommender import RecommenderAgent
from agents.risk_assessment import RiskAssessmentAgent
from analysis.risk_engine import RiskEngine
from orchestration.engine import OrchestrationEngine
from orchestration.planner import DynamicPlanner
from orchestration.policy import ExecutionLimits, TimeoutBudgetPolicy


class ThreatAnalysisOrchestrator:
    def __init__(
        self,
        *,
        risk_engine: Optional[Any] = None,
        critic: Optional[Any] = None,
        limits: Optional[ExecutionLimits] = None,
        timeout_policy: Optional[TimeoutBudgetPolicy] = None,
    ) -> None:
        self.planner = PlannerAgent()
        self.correlation_agent = CorrelationAgent()
        self.graph_agent = GraphAnalysisAgent()
        self.risk_agent = RiskAssessmentAgent()
        self.critic = critic or CriticAgent()
        self.recommender = RecommenderAgent()
        self.risk_engine = risk_engine or RiskEngine(explanation_generator=llm_helper.generate_explanation)
        self.engine = OrchestrationEngine(
            planner=DynamicPlanner(),
            risk_engine=self.risk_engine,
            correlation_agent=self.correlation_agent,
            graph_agent=self.graph_agent,
            risk_agent=self.risk_agent,
            critic=self.critic,
            recommender=self.recommender,
            limits=limits,
            timeout_policy=timeout_policy,
        )

    def run(self, source: str, data: Dict[str, Any], db: Optional[Any] = None) -> Optional[Dict[str, Any]]:
        if source not in {"cve", "urlhaus", "dread"}:
            return None
        return self.engine.run(source=source, data=data, db=db)

    def _get_primary_description(self, data: Dict[str, Any]) -> str:
        descriptions = data.get("descriptions", []) or []
        for item in descriptions:
            if item.get("lang", "").lower() == "en":
                return item.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""
