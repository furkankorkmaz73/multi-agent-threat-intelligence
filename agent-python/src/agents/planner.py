from __future__ import annotations

from typing import Any, Dict, List


class PlannerAgent:
    def build_plan(self, source: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        identity = self._resolve_identity(source, data)
        plan = [
            {"step": 1, "agent": "planner", "action": "normalize-input", "status": "planned", "details": {"source": source, "entity_hint": identity}},
            {"step": 2, "agent": "correlation", "action": "retrieve-cross-source-candidates", "status": "planned", "details": {"candidate_sources": self._candidate_sources(source)}},
            {"step": 3, "agent": "graph", "action": "build-graph-context", "status": "planned", "details": {"root_entity": identity}},
            {"step": 4, "agent": "risk", "action": "compute-dynamic-risk", "status": "planned", "details": {"scoring_mode": "hybrid_explainable"}},
            {"step": 5, "agent": "critic", "action": "consistency-review", "status": "planned", "details": {"checks": ["confidence", "counterfactuals", "source-diversity"]}},
            {"step": 6, "agent": "recommender", "action": "generate-actions", "status": "planned", "details": {"target": identity}},
        ]
        return plan

    def _resolve_identity(self, source: str, data: Dict[str, Any]) -> str:
        if source == "cve":
            return str(data.get("_id", "unknown-cve"))
        if source == "urlhaus":
            return str(data.get("url") or data.get("urlhaus_id") or "unknown-urlhaus")
        if source == "dread":
            return str(data.get("title") or data.get("url") or "unknown-dread")
        return "unknown"

    def _candidate_sources(self, source: str) -> List[str]:
        mapping = {
            "cve": ["urlhaus", "dread"],
            "urlhaus": ["cve", "dread"],
            "dread": ["cve", "urlhaus"],
        }
        return mapping.get(source, [])
