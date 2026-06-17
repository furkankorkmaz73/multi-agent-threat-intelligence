from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional, Protocol

from worker.job_lifecycle import JobMetadata, JobState


class JobRepository(Protocol):
    def claim(self, job: JobMetadata, *, now: datetime, force: bool = False) -> Optional[JobMetadata]:
        ...

    def save(self, job: JobMetadata) -> None:
        ...

    def get(self, idempotency_key: str) -> Optional[JobMetadata]:
        ...


class InMemoryJobRepository:
    def __init__(self) -> None:
        self.jobs: Dict[str, JobMetadata] = {}

    def claim(self, job: JobMetadata, *, now: datetime, force: bool = False) -> Optional[JobMetadata]:
        existing = self.jobs.get(job.idempotency_key)
        if existing and not force:
            if existing.state == JobState.RETRY_SCHEDULED and existing.retry_at and existing.retry_at <= now:
                self.jobs[job.idempotency_key] = existing
                return existing
            if existing.state in {JobState.RUNNING, JobState.RETRY_SCHEDULED, JobState.COMPLETED, JobState.COMPLETED_WITH_WARNINGS, JobState.FAILED, JobState.DEAD_LETTER}:
                return None
        self.jobs[job.idempotency_key] = job
        return job

    def save(self, job: JobMetadata) -> None:
        self.jobs[job.idempotency_key] = job

    def get(self, idempotency_key: str) -> Optional[JobMetadata]:
        return self.jobs.get(idempotency_key)


class DatabaseJobRepositoryAdapter:
    def __init__(self, db: object, fallback: Optional[InMemoryJobRepository] = None) -> None:
        self.db = db
        self.fallback = fallback or InMemoryJobRepository()

    def claim(self, job: JobMetadata, *, now: datetime, force: bool = False) -> Optional[JobMetadata]:
        if hasattr(self.db, "claim_job_lifecycle"):
            payload = self.db.claim_job_lifecycle(job.source, job.entity_identifier, job.to_dict(), now=now, force=force)
            if not payload:
                return None
            claimed = JobMetadata.from_dict(payload)
            self.fallback.save(claimed)
            return claimed

        existing = self.get(job.idempotency_key)
        if existing and not force:
            if existing.state == JobState.RETRY_SCHEDULED and existing.retry_at and existing.retry_at <= now:
                return existing
            if existing.state in {JobState.RUNNING, JobState.RETRY_SCHEDULED, JobState.COMPLETED, JobState.COMPLETED_WITH_WARNINGS, JobState.FAILED, JobState.DEAD_LETTER}:
                return None
        self.save(job)
        return job

    def save(self, job: JobMetadata) -> None:
        if hasattr(self.db, "update_job_lifecycle"):
            self.db.update_job_lifecycle(job.source, job.entity_identifier, job.to_dict())
        self.fallback.save(job)

    def get(self, idempotency_key: str) -> Optional[JobMetadata]:
        existing = self.fallback.get(idempotency_key)
        if existing:
            return existing
        if hasattr(self.db, "get_job_lifecycle_by_idempotency"):
            payload = self.db.get_job_lifecycle_by_idempotency(idempotency_key)
            if payload:
                job = JobMetadata.from_dict(payload)
                self.fallback.save(job)
                return job
        return None


def build_job_repository(db: object) -> JobRepository:
    if hasattr(db, "update_job_lifecycle") and hasattr(db, "get_job_lifecycle_by_idempotency"):
        return DatabaseJobRepositoryAdapter(db)
    return InMemoryJobRepository()
