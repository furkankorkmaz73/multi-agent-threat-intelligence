from __future__ import annotations

from typing import Any, Dict, Optional

from agents.orchestrator import ThreatAnalysisOrchestrator
from agents.planner import PlannerAgent


class DiagnosticAgent:
    def __init__(self) -> None:
        self.orchestrator = ThreatAnalysisOrchestrator()
        self.planner = PlannerAgent()

    def analyze(self, source: str, data: Dict[str, Any], db: Optional[Any] = None) -> Optional[Dict[str, Any]]:
        return self.orchestrator.run(source=source, data=data, db=db)

    def plan(self, source: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return {"source": source, "execution_plan": self.planner.build_plan(source=source, data=data)}
