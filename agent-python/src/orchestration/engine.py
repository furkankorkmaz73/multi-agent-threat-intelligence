from __future__ import annotations

from typing import Any, Dict, Iterable, Mapping, Optional

from agents import llm_helper
from orchestration.planner import DynamicPlanner, resolve_identity
from orchestration.policy import ExecutionLimits, TimeoutBudgetPolicy, can_execute_more_steps
from orchestration.state import AnalysisState, FinalStatus, OrchestrationStep, StepStatus


class OrchestrationEngine:
    def __init__(
        self,
        *,
        planner: DynamicPlanner,
        risk_engine: Any,
        correlation_agent: Any,
        graph_agent: Any,
        risk_agent: Any,
        critic: Any,
        recommender: Any,
        limits: Optional[ExecutionLimits] = None,
        timeout_policy: Optional[TimeoutBudgetPolicy] = None,
    ) -> None:
        self.planner = planner
        self.risk_engine = risk_engine
        self.correlation_agent = correlation_agent
        self.graph_agent = graph_agent
        self.risk_agent = risk_agent
        self.critic = critic
        self.recommender = recommender
        self.limits = limits or ExecutionLimits()
        self.timeout_policy = timeout_policy or TimeoutBudgetPolicy()

    def run(self, source: str, data: Mapping[str, Any], db: Optional[Any] = None) -> Dict[str, Any]:
        state = AnalysisState(source=source, entity_id=resolve_identity(source, data), raw_input=dict(data), final_status=FinalStatus.RUNNING)
        plan = self.planner.build_plan(
            source=source,
            data=data,
            evidence_available=db is not None,
            llm_available=llm_helper.is_enabled(),
        )
        state = state.update(plan=plan)

        for step in plan:
            if not can_execute_more_steps(state, self.limits):
                state = state.with_error(step.agent, step.action, "maximum_total_steps_exceeded")
                break
            state = self._execute_step(state, step, db)
            if state.final_status == FinalStatus.FAILED:
                break

        state = self._process_critic_actions(state, data, db)
        if state.final_status not in {FinalStatus.FAILED, FinalStatus.COMPLETED_WITH_WARNINGS}:
            state = state.update(final_status=FinalStatus.COMPLETED)
        return self._build_public_result(state)

    def _execute_step(self, state: AnalysisState, step: OrchestrationStep, db: Optional[Any]) -> AnalysisState:
        if self.timeout_policy.should_timeout(state, step):
            state, tick = state.next_tick()
            failed = step.with_status(StepStatus.FAILED, tick=tick, error="step_timeout", fallback="deterministic_fallback")
            state = state.with_completed_step(failed).with_error(step.agent, step.action, "step_timeout")
            if step.agent == "risk":
                fallback = self._build_fallback_result(state, "Risk step timed out; returned deterministic fallback analysis.")
                return state.update(risk_result=fallback, final_status=FinalStatus.COMPLETED_WITH_WARNINGS)
            return state

        state, start_tick = state.next_tick()
        running = step.with_status(StepStatus.RUNNING, tick=start_tick)
        try:
            output_summary, state = self._dispatch_step(state, running, db)
            state, end_tick = state.next_tick()
            completed = running.with_status(StepStatus.COMPLETED, tick=end_tick, output_summary=output_summary)
            return state.with_completed_step(completed)
        except Exception as exc:
            return self._handle_step_failure(state, running, db, exc)

    def _dispatch_step(self, state: AnalysisState, step: OrchestrationStep, db: Optional[Any]) -> tuple[Mapping[str, Any], AnalysisState]:
        action = step.action
        if action == "normalize-input":
            context = {"source": state.source, "entity_id": state.entity_id, "field_count": len(state.raw_input)}
            return context, state.update(extracted_context={**dict(state.extracted_context), **context})

        if action in {"extract-llm-context", "extract-deterministic-context"}:
            context = self._extract_context(state)
            return {"context_keys": sorted(context.keys()), "llm_used": bool(context)}, state.update(extracted_context={**dict(state.extracted_context), **context})

        if action in {"retrieve-cross-source-candidates", "retrieve-missing-evidence", "skip-cross-source-candidates"}:
            summary = self._evidence_provider_summary(state.source, db)
            return summary, state.update(evidence_summary=summary)

        if action == "compute-dynamic-risk":
            result = self._compute_risk(state, db)
            return {"risk_score": result.get("risk_score"), "risk_level": result.get("risk_level"), "confidence": result.get("confidence")}, state.update(risk_result=result)

        if action == "summarize-graph-context":
            graph_summary = dict((state.risk_result or {}).get("graph_summary", {}) or {})
            summary = self.graph_agent.summarize_for_trace(graph_summary)
            return summary, state.update(correlation_summary={**dict(state.correlation_summary), "graph": summary})

        if action == "consistency-review":
            review = self.critic.review(dict(state.risk_result or {}))
            return {"status": review.get("status"), "warnings": len(review.get("warnings", [])), "issues": len(review.get("issues", []))}, state.update(critic_findings=state.critic_findings + (dict(review),))

        if action == "generate-actions":
            recommendations = self.recommender.suggest(dict(state.risk_result or {}), source=state.source, original_doc=dict(state.raw_input))
            return {"recommendation_count": len(recommendations)}, state.update(recommendations=tuple(recommendations))

        return {"skipped": True, "reason": "unknown_action"}, state

    def _handle_step_failure(self, state: AnalysisState, step: OrchestrationStep, db: Optional[Any], exc: Exception) -> AnalysisState:
        error_text = f"{type(exc).__name__}: {exc}"
        state, tick = state.next_tick()
        failed = step.with_status(StepStatus.FAILED, tick=tick, error=error_text)
        state = state.with_completed_step(failed).with_error(step.agent, step.action, error_text)

        if step.agent == "risk" and state.retry_count < self.limits.max_retries:
            retry_state = state.update(retry_count=state.retry_count + 1)
            retry_step = step.with_status(StepStatus.PENDING, attempt=step.attempt + 1)
            try:
                result = self._compute_risk(retry_state, None)
                retry_state, retry_tick = retry_state.next_tick()
                completed = retry_step.with_status(
                    StepStatus.COMPLETED,
                    tick=retry_tick,
                    output_summary={"risk_score": result.get("risk_score"), "fallback_db": True},
                    fallback="null_evidence_provider",
                )
                return retry_state.with_completed_step(completed).update(risk_result=result, final_status=FinalStatus.COMPLETED_WITH_WARNINGS)
            except Exception as retry_exc:
                retry_state = retry_state.with_error("risk", "compute-dynamic-risk", f"{type(retry_exc).__name__}: {retry_exc}")
                fallback = self._build_fallback_result(retry_state, "Risk step failed after retry; returned deterministic fallback analysis.")
                return retry_state.update(risk_result=fallback, final_status=FinalStatus.COMPLETED_WITH_WARNINGS)

        if step.agent == "risk":
            fallback = self._build_fallback_result(state, "Risk step failed; returned deterministic fallback analysis.")
            return state.update(risk_result=fallback, final_status=FinalStatus.COMPLETED_WITH_WARNINGS)
        return state

    def _process_critic_actions(self, state: AnalysisState, data: Mapping[str, Any], db: Optional[Any]) -> AnalysisState:
        while state.critic_findings and can_execute_more_steps(state, self.limits):
            review = dict(state.critic_findings[-1])
            actions = _critic_actions(review)
            if not actions:
                return state
            action = actions[0]
            if action == "stop_with_warning":
                return state.update(final_status=FinalStatus.COMPLETED_WITH_WARNINGS)
            if action == "add_missing_evidence_step":
                if state.replan_count >= self.limits.max_replans:
                    return state.with_error("critic", action, "maximum_replans_exceeded")
                finding = {"action": action, "reason": "critic_request"}
                replanned = self.planner.build_plan(
                    source=state.source,
                    data=data,
                    evidence_available=db is not None,
                    llm_available=llm_helper.is_enabled(),
                    critic_findings=(finding,),
                    start_step=max((step.step for step in state.plan), default=0) + 1,
                )
                missing_step = next((step for step in replanned if step.action == "retrieve-missing-evidence"), None)
                state = state.update(plan=state.plan + ((missing_step,) if missing_step else ()), replan_count=state.replan_count + 1)
                if missing_step:
                    state = self._execute_step(state, missing_step, db)
                state = self._retry_risk_and_critic(state, db)
                continue
            if action in {"retry_current_step", "recompute_risk"}:
                next_state = self._retry_risk_and_critic(state, db)
                if next_state.retry_count == state.retry_count:
                    return next_state.with_error("critic", action, "maximum_retries_exceeded")
                state = next_state
                continue
            return state
        return state

    def _retry_risk_and_critic(self, state: AnalysisState, db: Optional[Any]) -> AnalysisState:
        if state.retry_count >= self.limits.max_retries or not can_execute_more_steps(state, self.limits):
            return state
        risk_step = OrchestrationStep(
            step=max((step.step for step in state.plan + state.completed_steps), default=0) + 1,
            agent="risk",
            action="compute-dynamic-risk",
            details={"reason": "critic_request"},
            attempt=state.retry_count + 2,
        )
        state = state.update(retry_count=state.retry_count + 1, plan=state.plan + (risk_step,))
        state = self._execute_step(state, risk_step, db)
        critic_step = OrchestrationStep(
            step=risk_step.step + 1,
            agent="critic",
            action="consistency-review",
            details={"reason": "post_retry"},
        )
        state = state.update(plan=state.plan + (critic_step,))
        return self._execute_step(state, critic_step, db)

    def _extract_context(self, state: AnalysisState) -> Dict[str, Any]:
        if state.source == "cve":
            description = _primary_description(state.raw_input)
            return {"llm_info": llm_helper.extract_cve_info(description) if description else {}}
        if state.source == "dread":
            combined = f"{state.raw_input.get('title', '')} {state.raw_input.get('content', '')}".strip().lower()
            return {"llm_cls": llm_helper.classify_dread(combined) if combined else {}}
        return {}

    def _compute_risk(self, state: AnalysisState, db: Optional[Any]) -> Dict[str, Any]:
        context = dict(state.extracted_context)
        if state.source == "cve":
            return self.risk_engine.evaluate_cve(data=dict(state.raw_input), db=db, llm_info=dict(context.get("llm_info", {}) or {}))
        if state.source == "urlhaus":
            return self.risk_engine.evaluate_urlhaus(data=dict(state.raw_input), db=db)
        if state.source == "dread":
            return self.risk_engine.evaluate_dread(data=dict(state.raw_input), db=db, llm_cls=dict(context.get("llm_cls", {}) or {}))
        raise ValueError(f"Unsupported source: {state.source}")

    def _evidence_provider_summary(self, source: str, db: Optional[Any]) -> Dict[str, Any]:
        if db is None:
            return {"available": False, "candidate_sources": []}
        methods = {
            "find_related_urlhaus": hasattr(db, "find_related_urlhaus"),
            "find_related_dread": hasattr(db, "find_related_dread"),
            "find_related_cves": hasattr(db, "find_related_cves"),
        }
        return {"available": any(methods.values()), "source": source, "methods": methods}

    def _build_public_result(self, state: AnalysisState) -> Dict[str, Any]:
        result = dict(state.risk_result or self._build_fallback_result(state, "No risk result was produced."))
        critic_review = dict(state.critic_findings[-1]) if state.critic_findings else {"status": "needs-review", "issues": [], "warnings": [], "summary": "Critic review was not completed."}
        recommendations = list(state.recommendations)
        agent_outputs = {
            "correlation": self.correlation_agent.summarize(result),
            "graph": self.graph_agent.summarize_for_trace(result.get("graph_summary", {}) or {}),
            "risk": self.risk_agent.summarize(result),
            "critic": critic_review,
        }
        trace = list(result.get("orchestration_trace", []))
        trace.insert(0, {"agent": "planner", "action": "draft-execution-plan", "status": "completed", "details": {"steps": len(state.plan), "source": state.source}})
        for step in state.completed_steps:
            trace.append(step.to_trace_dict())
        trace.append({"agent": "critic", "action": "review-analysis-artifacts", "status": critic_review.get("status", "completed"), "details": {"warnings": len(critic_review.get("warnings", [])), "issues": len(critic_review.get("issues", []))}})
        trace.append({"agent": "recommender", "action": "await-recommendation-stage", "status": "completed", "details": {"source": state.source}})

        result["execution_plan"] = [step.to_plan_dict() for step in state.plan]
        result["critic_review"] = critic_review
        result["agent_outputs"] = agent_outputs
        result["orchestration_trace"] = trace
        result["recommendations"] = recommendations
        return result

    def _build_fallback_result(self, state: AnalysisState, diagnosis: str) -> Dict[str, Any]:
        return {
            "entity_type": state.source,
            "entity_id": state.entity_id,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "confidence": 0.0,
            "diagnosis": diagnosis,
            "explanation": ["Analysis could not complete normally; deterministic fallback returned a non-actionable result."],
            "evidence": {"errors": [dict(item) for item in state.errors]},
            "feature_breakdown": {"final_score": 0.0},
            "graph_summary": {},
            "graph_edges": [],
            "counterfactuals": {},
            "source_contributions": {},
            "relation_summary": {},
            "orchestration_trace": [],
        }


def _primary_description(data: Mapping[str, Any]) -> str:
    descriptions = data.get("descriptions", []) or []
    for item in descriptions:
        if str(item.get("lang", "")).lower() == "en":
            return str(item.get("value", ""))
    return str(descriptions[0].get("value", "")) if descriptions else ""


def _critic_actions(review: Mapping[str, Any]) -> list[str]:
    raw_actions = review.get("actions") or review.get("requested_actions") or []
    if isinstance(raw_actions, str):
        raw_actions = [raw_actions]
    actions: list[str] = []
    for item in raw_actions:
        if isinstance(item, Mapping):
            action = str(item.get("type") or item.get("action") or "")
        else:
            action = str(item)
        if action in {"retry_current_step", "add_missing_evidence_step", "recompute_risk", "stop_with_warning"}:
            actions.append(action)
    return actions
