from __future__ import annotations

from typing import Any, Dict, List

from orchestration.planner import DynamicPlanner, candidate_sources, resolve_identity


class PlannerAgent:
    def __init__(self) -> None:
        self.dynamic_planner = DynamicPlanner()

    def build_plan(self, source: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [step.to_plan_dict() for step in self.dynamic_planner.build_plan(source=source, data=data)]

    def _resolve_identity(self, source: str, data: Dict[str, Any]) -> str:
        return resolve_identity(source, data)

    def _candidate_sources(self, source: str) -> List[str]:
        return candidate_sources(source)
