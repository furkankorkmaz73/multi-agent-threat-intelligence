from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping

from orchestration.state import OrchestrationStep, StepStatus


class DynamicPlanner:
    def build_plan(
        self,
        *,
        source: str,
        data: Mapping[str, Any],
        evidence_available: bool = True,
        llm_available: bool = False,
        critic_findings: Iterable[Mapping[str, Any]] = (),
        start_step: int = 1,
    ) -> tuple[OrchestrationStep, ...]:
        identity = resolve_identity(source, data)
        steps: List[OrchestrationStep] = [
            self._step(start_step, "planner", "normalize-input", {"source": source, "entity_hint": identity}),
        ]
        next_step = start_step + 1

        if source in {"cve", "dread"} and _has_text_for_context(source, data):
            action = "extract-llm-context" if llm_available else "extract-deterministic-context"
            details = {"llm_available": llm_available}
            steps.append(self._step(next_step, "planner", action, details))
            next_step += 1

        if evidence_available:
            steps.append(
                self._step(
                    next_step,
                    "correlation",
                    "retrieve-cross-source-candidates",
                    {"candidate_sources": candidate_sources(source)},
                )
            )
        else:
            steps.append(self._step(next_step, "correlation", "skip-cross-source-candidates", {"reason": "no_evidence_provider"}))
        next_step += 1

        for finding in critic_findings:
            if finding.get("action") == "add_missing_evidence_step":
                steps.append(self._step(next_step, "correlation", "retrieve-missing-evidence", {"reason": finding.get("reason", "critic_request")}))
                next_step += 1

        steps.extend(
            [
                self._step(next_step, "risk", "compute-dynamic-risk", {"scoring_mode": "hybrid_explainable"}),
                self._step(next_step + 1, "graph", "summarize-graph-context", {"root_entity": identity}),
                self._step(next_step + 2, "critic", "consistency-review", {"checks": ["confidence", "counterfactuals", "source-diversity"]}),
                self._step(next_step + 3, "recommender", "generate-actions", {"target": identity}),
            ]
        )
        return tuple(steps)

    def _step(self, step: int, agent: str, action: str, details: Mapping[str, Any]) -> OrchestrationStep:
        return OrchestrationStep(step=step, agent=agent, action=action, status=StepStatus.PENDING, details=dict(details))


def resolve_identity(source: str, data: Mapping[str, Any]) -> str:
    if source == "cve":
        return str(data.get("_id", "unknown-cve"))
    if source == "urlhaus":
        return str(data.get("url") or data.get("urlhaus_id") or data.get("_id") or "unknown-urlhaus")
    if source == "dread":
        return str(data.get("title") or data.get("url") or data.get("_id") or "unknown-dread")
    return "unknown"


def candidate_sources(source: str) -> List[str]:
    mapping = {
        "cve": ["urlhaus", "dread"],
        "urlhaus": ["cve", "dread"],
        "dread": ["cve", "urlhaus"],
    }
    return mapping.get(source, [])


def _has_text_for_context(source: str, data: Mapping[str, Any]) -> bool:
    if source == "cve":
        descriptions = data.get("descriptions", []) or []
        return bool(descriptions)
    if source == "dread":
        return bool(f"{data.get('title', '')} {data.get('content', '')}".strip())
    return False
