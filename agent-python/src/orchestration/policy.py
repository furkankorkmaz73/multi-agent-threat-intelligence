from __future__ import annotations

from dataclasses import dataclass, field

from orchestration.state import AnalysisState, OrchestrationStep


@dataclass(frozen=True)
class ExecutionLimits:
    max_retries: int = 1
    max_replans: int = 1
    max_total_steps: int = 16


@dataclass(frozen=True)
class TimeoutBudgetPolicy:
    timeout_actions: frozenset[str] = field(default_factory=frozenset)

    def should_timeout(self, state: AnalysisState, step: OrchestrationStep) -> bool:
        return step.action in self.timeout_actions


def can_execute_more_steps(state: AnalysisState, limits: ExecutionLimits) -> bool:
    return len(state.completed_steps) < max(1, limits.max_total_steps)
