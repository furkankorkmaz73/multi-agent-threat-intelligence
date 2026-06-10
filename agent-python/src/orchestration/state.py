from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Dict, Mapping, Optional


class StepStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class FinalStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"


@dataclass(frozen=True)
class OrchestrationStep:
    step: int
    agent: str
    action: str
    status: StepStatus = StepStatus.PENDING
    details: Mapping[str, Any] = field(default_factory=dict)
    started_at_step: Optional[int] = None
    ended_at_step: Optional[int] = None
    duration_ms: int = 0
    input_summary: Mapping[str, Any] = field(default_factory=dict)
    output_summary: Mapping[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    fallback: Optional[str] = None
    attempt: int = 1

    def with_status(
        self,
        status: StepStatus,
        *,
        tick: Optional[int] = None,
        output_summary: Optional[Mapping[str, Any]] = None,
        error: Optional[str] = None,
        fallback: Optional[str] = None,
        attempt: Optional[int] = None,
    ) -> "OrchestrationStep":
        started = self.started_at_step
        ended = self.ended_at_step
        if status == StepStatus.RUNNING and tick is not None:
            started = tick
        if status in {StepStatus.COMPLETED, StepStatus.FAILED, StepStatus.SKIPPED} and tick is not None:
            ended = tick
        duration = 0
        if started is not None and ended is not None:
            duration = max(0, ended - started)
        return replace(
            self,
            status=status,
            ended_at_step=ended,
            started_at_step=started,
            duration_ms=duration,
            output_summary=dict(output_summary or self.output_summary),
            error=error if error is not None else self.error,
            fallback=fallback if fallback is not None else self.fallback,
            attempt=attempt if attempt is not None else self.attempt,
        )

    def to_plan_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "agent": self.agent,
            "action": self.action,
            "status": self.status.value,
            "details": dict(self.details),
        }

    def to_trace_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step,
            "agent": self.agent,
            "action": self.action,
            "status": self.status.value,
            "details": dict(self.details),
            "timing": {
                "started_at_step": self.started_at_step,
                "ended_at_step": self.ended_at_step,
                "duration_ms": self.duration_ms,
            },
            "input_summary": dict(self.input_summary),
            "output_summary": dict(self.output_summary),
            "error": self.error,
            "fallback": self.fallback,
            "attempt": self.attempt,
        }


@dataclass(frozen=True)
class AnalysisState:
    source: str
    entity_id: str
    raw_input: Mapping[str, Any]
    extracted_context: Mapping[str, Any] = field(default_factory=dict)
    plan: tuple[OrchestrationStep, ...] = field(default_factory=tuple)
    completed_steps: tuple[OrchestrationStep, ...] = field(default_factory=tuple)
    evidence_summary: Mapping[str, Any] = field(default_factory=dict)
    correlation_summary: Mapping[str, Any] = field(default_factory=dict)
    risk_result: Optional[Mapping[str, Any]] = None
    critic_findings: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    recommendations: tuple[str, ...] = field(default_factory=tuple)
    retry_count: int = 0
    replan_count: int = 0
    errors: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    execution_trace: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    final_status: FinalStatus = FinalStatus.PENDING
    tick: int = 0

    def update(self, **changes: Any) -> "AnalysisState":
        return replace(self, **changes)

    def next_tick(self) -> tuple["AnalysisState", int]:
        tick = self.tick + 1
        return replace(self, tick=tick), tick

    def with_completed_step(self, step: OrchestrationStep) -> "AnalysisState":
        return replace(self, completed_steps=self.completed_steps + (step,))

    def with_error(self, agent: str, action: str, error: str) -> "AnalysisState":
        return replace(
            self,
            errors=self.errors + ({"agent": agent, "action": action, "error": error},),
        )

    def with_trace(self, item: Mapping[str, Any]) -> "AnalysisState":
        return replace(self, execution_trace=self.execution_trace + (dict(item),))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "entity_id": self.entity_id,
            "raw_input": dict(self.raw_input),
            "extracted_context": dict(self.extracted_context),
            "plan": [step.to_plan_dict() for step in self.plan],
            "completed_steps": [step.to_trace_dict() for step in self.completed_steps],
            "evidence_summary": dict(self.evidence_summary),
            "correlation_summary": dict(self.correlation_summary),
            "risk_result": dict(self.risk_result or {}),
            "critic_findings": [dict(item) for item in self.critic_findings],
            "recommendations": list(self.recommendations),
            "retry_count": self.retry_count,
            "replan_count": self.replan_count,
            "errors": [dict(item) for item in self.errors],
            "execution_trace": [dict(item) for item in self.execution_trace],
            "final_status": self.final_status.value,
        }
