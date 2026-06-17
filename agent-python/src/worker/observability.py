from __future__ import annotations

import logging
from dataclasses import dataclass, field
from math import ceil
from typing import Any, Dict, List, Mapping

from worker.job_lifecycle import JobMetadata


class StructuredJobLogger:
    def __init__(self, logger: logging.Logger | None = None) -> None:
        self.logger = logger or logging.getLogger("worker.jobs")
        self.records: List[Dict[str, Any]] = []

    def emit(self, event: str, job: JobMetadata, **details: Any) -> Dict[str, Any]:
        record = {
            "event": event,
            "job_id": job.job_id,
            "source": job.source,
            "entity_identifier": job.entity_identifier,
            "attempt_count": job.attempt_count,
            "state": job.state.value,
            "idempotency_key": job.idempotency_key,
            "details": _sanitize(details),
        }
        self.records.append(record)
        self.logger.info("worker_job_event=%s", record)
        return record


@dataclass
class WorkerMetrics:
    processed_jobs: int = 0
    successful_jobs: int = 0
    failed_jobs: int = 0
    retries: int = 0
    dead_letter_jobs: int = 0
    processing_durations_ms: List[int] = field(default_factory=list)
    jobs_by_source_status: Dict[str, int] = field(default_factory=dict)

    def record_final_status(self, job: JobMetadata, duration_ms: int = 0) -> None:
        self.processed_jobs += 1
        self.processing_durations_ms.append(max(0, int(duration_ms)))
        key = f"{job.source}:{job.state.value}"
        self.jobs_by_source_status[key] = self.jobs_by_source_status.get(key, 0) + 1
        if job.state.value.startswith("completed"):
            self.successful_jobs += 1
        elif job.state.value == "dead_letter":
            self.dead_letter_jobs += 1
            self.failed_jobs += 1
        elif job.state.value == "failed":
            self.failed_jobs += 1

    def record_retry(self, job: JobMetadata) -> None:
        self.retries += 1
        key = f"{job.source}:{job.state.value}"
        self.jobs_by_source_status[key] = self.jobs_by_source_status.get(key, 0) + 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "processed_jobs": self.processed_jobs,
            "successful_jobs": self.successful_jobs,
            "failed_jobs": self.failed_jobs,
            "retries": self.retries,
            "dead_letter_jobs": self.dead_letter_jobs,
            "processing_durations_ms": list(self.processing_durations_ms),
            "jobs_by_source_status": dict(self.jobs_by_source_status),
        }


def _sanitize(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _sanitize(item) for key, item in value.items() if not _is_secret_key(str(key))}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize(item) for item in value]
    if isinstance(value, BaseException):
        return f"{type(value).__name__}: {value}"
    return value


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("secret", "token", "password", "api_key", "apikey", "authorization"))


def summarize_processing_metrics(
    *,
    processed_count: int,
    failed_count: int,
    elapsed_seconds: float,
    latency_ms: List[int] | List[float],
) -> Dict[str, Any]:
    processed = max(0, int(processed_count))
    failed = max(0, int(failed_count))
    elapsed = max(0.0, float(elapsed_seconds or 0.0))
    latencies = sorted(max(0.0, float(value)) for value in latency_ms)
    avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
    p95_latency = _percentile(latencies, 0.95)
    return {
        "processed": processed,
        "failed": failed,
        "elapsed_seconds": round(elapsed, 4),
        "docs_per_second": round(processed / elapsed, 4) if elapsed > 0 else 0.0,
        "avg_latency_ms": round(avg_latency, 4),
        "p95_latency_ms": round(p95_latency, 4),
    }


def _percentile(sorted_values: List[float], percentile: float) -> float:
    if not sorted_values:
        return 0.0
    rank = max(1, ceil(len(sorted_values) * percentile))
    return sorted_values[min(rank - 1, len(sorted_values) - 1)]
