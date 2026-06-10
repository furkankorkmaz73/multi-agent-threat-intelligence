from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from config import APP_VERSION
from worker.job_lifecycle import JobMetadata, JobState, RetryPolicy, new_job
from worker.job_repository import JobRepository
from worker.observability import StructuredJobLogger, WorkerMetrics


Clock = Any


@dataclass
class JobExecutionOutcome:
    processed: bool
    job: Optional[JobMetadata]
    skipped_duplicate: bool = False


class WorkerJobExecutor:
    def __init__(
        self,
        *,
        repository: JobRepository,
        retry_policy: Optional[RetryPolicy] = None,
        event_logger: Optional[StructuredJobLogger] = None,
        metrics: Optional[WorkerMetrics] = None,
        clock: Optional[Clock] = None,
        analysis_version: str = APP_VERSION,
        force: bool = False,
    ) -> None:
        self.repository = repository
        self.retry_policy = retry_policy or RetryPolicy()
        self.event_logger = event_logger or StructuredJobLogger()
        self.metrics = metrics or WorkerMetrics()
        self.clock = clock or _SystemClock()
        self.analysis_version = analysis_version
        self.force = force

    def process_document(self, source: str, doc: Dict[str, Any], db: Any, thinker: Any, recommender: Any) -> JobExecutionOutcome:
        entity_id = resolve_entity_identifier(source, doc)
        job = new_job(source, entity_id, self.analysis_version, now=self.clock.now())
        claimed = self.repository.claim(job, now=self.clock.now(), force=self.force)
        if claimed is None:
            self.event_logger.emit("job_duplicate_skipped", job, reason="idempotency_key_already_processed")
            return JobExecutionOutcome(processed=False, job=None, skipped_duplicate=True)

        self.event_logger.emit("job_claimed", claimed)
        running = claimed.transition(JobState.RUNNING, now=self.clock.now(), reason="worker_start")
        self.repository.save(running)
        self.event_logger.emit("job_started", running)
        started_at = self.clock.now()

        try:
            analysis = thinker.analyze(source, doc, db=db)
            if analysis is None:
                raise RuntimeError("analysis returned no result")
            analysis["recommendations"] = recommender.suggest(analysis_result=analysis, source=source, original_doc=doc)
            analysis["source"] = source
            analysis["analyzed_at"] = self.clock.now()
            analysis["pipeline_version"] = self.analysis_version
            db.update_analysis(source, doc.get("_id", entity_id), analysis)
            final_state = JobState.COMPLETED_WITH_WARNINGS if _has_warnings(analysis) else JobState.COMPLETED
            completed = running.transition(
                final_state,
                now=self.clock.now(),
                reason="analysis_persisted",
                execution_summary=_execution_summary(analysis),
            )
            self.repository.save(completed)
            duration_ms = _duration_ms(started_at, self.clock.now())
            self.metrics.record_final_status(completed, duration_ms=duration_ms)
            self.event_logger.emit("job_completed", completed, duration_ms=duration_ms)
            return JobExecutionOutcome(processed=True, job=completed)
        except Exception as exc:
            return self._handle_failure(running, exc, started_at)

    def _handle_failure(self, running: JobMetadata, exc: Exception, started_at: datetime) -> JobExecutionOutcome:
        error_text = f"{type(exc).__name__}: {exc}"
        if self.retry_policy.should_retry(exc, running.attempt_count):
            retry_at = self.retry_policy.next_retry_at(self.clock.now(), running.attempt_count)
            retry_job = running.transition(
                JobState.RETRY_SCHEDULED,
                now=self.clock.now(),
                reason="retryable_failure",
                last_error=error_text,
                retry_at=retry_at,
                execution_summary={"error_type": type(exc).__name__},
            )
            self.repository.save(retry_job)
            self.metrics.record_retry(retry_job)
            self.event_logger.emit("retry_scheduled", retry_job, retry_at=retry_at.isoformat(), error=error_text)
            return JobExecutionOutcome(processed=False, job=retry_job)

        final_state = JobState.DEAD_LETTER if running.attempt_count >= self.retry_policy.max_attempts else JobState.FAILED
        failed = running.transition(
            final_state,
            now=self.clock.now(),
            reason="non_retryable_failure" if final_state == JobState.FAILED else "retry_exhausted",
            last_error=error_text,
            execution_summary={"error_type": type(exc).__name__},
        )
        self.repository.save(failed)
        duration_ms = _duration_ms(started_at, self.clock.now())
        self.metrics.record_final_status(failed, duration_ms=duration_ms)
        event = "dead_lettered" if final_state == JobState.DEAD_LETTER else "job_failed"
        self.event_logger.emit(event, failed, duration_ms=duration_ms, error=error_text)
        return JobExecutionOutcome(processed=False, job=failed)


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(timezone.utc)


def resolve_entity_identifier(source: str, doc: Dict[str, Any]) -> str:
    if source == "cve":
        return str(doc.get("_id") or "unknown-cve")
    if source == "urlhaus":
        return str(doc.get("urlhaus_id") or doc.get("url") or doc.get("_id") or "unknown-urlhaus")
    if source == "dread":
        return str(doc.get("_id") or doc.get("title") or doc.get("url") or "unknown-dread")
    return str(doc.get("_id") or "unknown")


def _has_warnings(analysis: Dict[str, Any]) -> bool:
    critic = analysis.get("critic_review", {}) or {}
    evidence = analysis.get("evidence", {}) or {}
    return bool(critic.get("warnings") or critic.get("issues") or evidence.get("errors"))


def _execution_summary(analysis: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "risk_score": analysis.get("risk_score"),
        "risk_level": analysis.get("risk_level"),
        "confidence": analysis.get("confidence"),
        "recommendation_count": len(analysis.get("recommendations", []) or []),
    }


def _duration_ms(start: datetime, end: datetime) -> int:
    return max(0, int((end - start).total_seconds() * 1000))
