from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Tuple, Type


class JobState(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    RETRY_SCHEDULED = "retry_scheduled"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


TERMINAL_STATES = {JobState.COMPLETED, JobState.COMPLETED_WITH_WARNINGS, JobState.DEAD_LETTER}

ALLOWED_TRANSITIONS = {
    JobState.PENDING: {JobState.RUNNING, JobState.FAILED, JobState.DEAD_LETTER},
    JobState.RUNNING: {
        JobState.COMPLETED,
        JobState.COMPLETED_WITH_WARNINGS,
        JobState.RETRY_SCHEDULED,
        JobState.FAILED,
        JobState.DEAD_LETTER,
    },
    JobState.RETRY_SCHEDULED: {JobState.RUNNING, JobState.DEAD_LETTER},
    JobState.FAILED: {JobState.DEAD_LETTER},
    JobState.COMPLETED: set(),
    JobState.COMPLETED_WITH_WARNINGS: set(),
    JobState.DEAD_LETTER: set(),
}


class InvalidJobTransition(ValueError):
    pass


Clock = Any


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_idempotency_key(source: str, entity_identifier: str, analysis_version: str) -> str:
    raw = f"{source}:{entity_identifier}:{analysis_version}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class TransitionRecord:
    from_state: JobState
    to_state: JobState
    timestamp: datetime
    reason: str = ""
    attempt_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "timestamp": self.timestamp.isoformat(),
            "reason": self.reason,
            "attempt_count": self.attempt_count,
        }


@dataclass(frozen=True)
class JobMetadata:
    job_id: str
    source: str
    entity_identifier: str
    analysis_version: str
    idempotency_key: str
    state: JobState = JobState.PENDING
    attempt_count: int = 0
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    last_error: Optional[str] = None
    retry_at: Optional[datetime] = None
    execution_summary: Mapping[str, Any] = field(default_factory=dict)
    transition_history: Tuple[TransitionRecord, ...] = field(default_factory=tuple)

    def transition(
        self,
        to_state: JobState,
        *,
        now: Optional[datetime] = None,
        reason: str = "",
        last_error: Optional[str] = None,
        retry_at: Optional[datetime] = None,
        execution_summary: Optional[Mapping[str, Any]] = None,
    ) -> "JobMetadata":
        now = now or utc_now()
        if to_state not in ALLOWED_TRANSITIONS[self.state]:
            raise InvalidJobTransition(f"Invalid job transition: {self.state.value} -> {to_state.value}")
        attempt_count = self.attempt_count + 1 if to_state == JobState.RUNNING else self.attempt_count
        completed_at = self.completed_at
        if to_state in TERMINAL_STATES or to_state == JobState.FAILED:
            completed_at = now
        record = TransitionRecord(
            from_state=self.state,
            to_state=to_state,
            timestamp=now,
            reason=reason,
            attempt_count=attempt_count,
        )
        return replace(
            self,
            state=to_state,
            attempt_count=attempt_count,
            updated_at=now,
            started_at=now if to_state == JobState.RUNNING else self.started_at,
            completed_at=completed_at,
            last_error=last_error if last_error is not None else self.last_error,
            retry_at=retry_at,
            execution_summary=dict(execution_summary or self.execution_summary),
            transition_history=self.transition_history + (record,),
        )

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    def to_dict(self) -> Dict[str, Any]:
        return {
            "job_id": self.job_id,
            "source": self.source,
            "entity_identifier": self.entity_identifier,
            "analysis_version": self.analysis_version,
            "idempotency_key": self.idempotency_key,
            "state": self.state.value,
            "attempt_count": self.attempt_count,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "last_error": self.last_error,
            "retry_at": self.retry_at.isoformat() if self.retry_at else None,
            "execution_summary": dict(self.execution_summary),
            "transition_history": [item.to_dict() for item in self.transition_history],
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "JobMetadata":
        history = tuple(
            TransitionRecord(
                from_state=JobState(item["from_state"]),
                to_state=JobState(item["to_state"]),
                timestamp=_parse_datetime(item.get("timestamp")) or utc_now(),
                reason=str(item.get("reason", "")),
                attempt_count=int(item.get("attempt_count", 0) or 0),
            )
            for item in payload.get("transition_history", []) or []
        )
        return cls(
            job_id=str(payload.get("job_id", "")),
            source=str(payload.get("source", "")),
            entity_identifier=str(payload.get("entity_identifier", "")),
            analysis_version=str(payload.get("analysis_version", "")),
            idempotency_key=str(payload.get("idempotency_key", "")),
            state=JobState(payload.get("state", JobState.PENDING.value)),
            attempt_count=int(payload.get("attempt_count", 0) or 0),
            created_at=_parse_datetime(payload.get("created_at")) or utc_now(),
            updated_at=_parse_datetime(payload.get("updated_at")) or utc_now(),
            started_at=_parse_datetime(payload.get("started_at")),
            completed_at=_parse_datetime(payload.get("completed_at")),
            last_error=payload.get("last_error"),
            retry_at=_parse_datetime(payload.get("retry_at")),
            execution_summary=dict(payload.get("execution_summary") or {}),
            transition_history=history,
        )


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay_seconds: int = 1
    max_delay_seconds: int = 60
    retryable_exceptions: Tuple[Type[BaseException], ...] = (RuntimeError, TimeoutError, ConnectionError)

    def is_retryable(self, exc: BaseException) -> bool:
        return isinstance(exc, self.retryable_exceptions)

    def backoff_delay(self, attempt_count: int) -> timedelta:
        exponent = max(attempt_count - 1, 0)
        seconds = min(self.base_delay_seconds * (2 ** exponent), self.max_delay_seconds)
        return timedelta(seconds=seconds)

    def should_retry(self, exc: BaseException, attempt_count: int) -> bool:
        return self.is_retryable(exc) and attempt_count < self.max_attempts

    def next_retry_at(self, now: datetime, attempt_count: int) -> datetime:
        return now + self.backoff_delay(attempt_count)


def new_job(source: str, entity_identifier: str, analysis_version: str, *, now: Optional[datetime] = None) -> JobMetadata:
    now = now or utc_now()
    key = generate_idempotency_key(source, entity_identifier, analysis_version)
    return JobMetadata(
        job_id=f"{source}:{entity_identifier}",
        source=source,
        entity_identifier=entity_identifier,
        analysis_version=analysis_version,
        idempotency_key=key,
        created_at=now,
        updated_at=now,
    )


def _parse_datetime(value: Any) -> Optional[datetime]:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None
