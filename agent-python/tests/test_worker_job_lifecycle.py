from datetime import datetime, timedelta, timezone

import pytest

from main import process_source
from worker.executor import WorkerJobExecutor
from worker.job_lifecycle import InvalidJobTransition, JobState, RetryPolicy, generate_idempotency_key, new_job
from worker.job_repository import DatabaseJobRepositoryAdapter, InMemoryJobRepository
from worker.observability import StructuredJobLogger, WorkerMetrics


class FakeClock:
    def __init__(self):
        self.current = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
        self.sleep_calls = []

    def now(self):
        return self.current

    def advance(self, seconds):
        self.current += timedelta(seconds=seconds)

    def sleep(self, seconds):
        self.sleep_calls.append(seconds)


class FakeDB:
    def __init__(self, docs=None):
        self.docs = docs if docs is not None else [{"_id": "doc-1"}]
        self.updated = []

    def get_unprocessed(self, source, limit=10):
        return self.docs[:limit]

    def update_analysis(self, source, doc_id, analysis):
        self.updated.append((source, doc_id, analysis))


class FakeDiagnosticAgent:
    def __init__(self, failures=None):
        self.failures = list(failures or [])
        self.calls = 0

    def analyze(self, source, doc, db=None):
        self.calls += 1
        if self.failures:
            exc = self.failures.pop(0)
            raise exc
        return {
            "entity_type": source,
            "entity_id": doc["_id"],
            "risk_level": "MEDIUM",
            "risk_score": 5.0,
            "confidence": 0.75,
            "diagnosis": "ok",
            "explanation": [],
            "feature_breakdown": {},
            "graph_summary": {},
            "graph_edges": [],
        }


class FakeRecommenderAgent:
    def suggest(self, analysis_result, source, original_doc):
        return [f"review-{original_doc['_id']}"]


class LifecycleDB:
    def __init__(self):
        self.saved = {}

    def update_job_lifecycle(self, source, doc_id, job_lifecycle):
        self.saved[job_lifecycle["idempotency_key"]] = job_lifecycle

    def get_job_lifecycle_by_idempotency(self, idempotency_key):
        return self.saved.get(idempotency_key)


def test_valid_and_invalid_transitions():
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    job = new_job("cve", "CVE-2026-1", "v1", now=now)

    running = job.transition(JobState.RUNNING, now=now, reason="start")
    completed = running.transition(JobState.COMPLETED, now=now, reason="done")

    assert running.attempt_count == 1
    assert completed.is_terminal is True
    assert completed.transition_history[-1].to_state == JobState.COMPLETED
    with pytest.raises(InvalidJobTransition):
        completed.transition(JobState.RUNNING, now=now)


def test_idempotency_key_is_stable_and_versioned():
    first = generate_idempotency_key("cve", "CVE-2026-1", "0.4.0")
    second = generate_idempotency_key("cve", "CVE-2026-1", "0.4.0")
    changed = generate_idempotency_key("cve", "CVE-2026-1", "0.5.0")

    assert first == second
    assert first != changed


def test_successful_job_updates_analysis_logs_and_metrics():
    clock = FakeClock()
    repo = InMemoryJobRepository()
    logger = StructuredJobLogger()
    metrics = WorkerMetrics()
    db = FakeDB()

    outcome = WorkerJobExecutor(repository=repo, event_logger=logger, metrics=metrics, clock=clock).process_document(
        "cve",
        {"_id": "doc-1"},
        db,
        FakeDiagnosticAgent(),
        FakeRecommenderAgent(),
    )

    assert outcome.processed is True
    assert outcome.job.state == JobState.COMPLETED
    assert db.updated[0][2]["recommendations"] == ["review-doc-1"]
    assert logger.records[0]["event"] == "job_claimed"
    assert logger.records[-1]["event"] == "job_completed"
    assert metrics.successful_jobs == 1
    assert metrics.jobs_by_source_status["cve:completed"] == 1


def test_duplicate_idempotent_job_is_skipped_by_default():
    clock = FakeClock()
    repo = InMemoryJobRepository()
    db = FakeDB(docs=[{"_id": "doc-1"}, {"_id": "doc-1"}])
    logger = StructuredJobLogger()

    processed = process_source(
        "cve",
        db,
        FakeDiagnosticAgent(),
        FakeRecommenderAgent(),
        batch_size=10,
        job_repository=repo,
        event_logger=logger,
        clock=clock,
    )

    assert processed == 1
    assert len(db.updated) == 1
    assert any(record["event"] == "job_duplicate_skipped" for record in logger.records)


def test_database_repository_adapter_preserves_lifecycle_payloads():
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    db = LifecycleDB()
    repo = DatabaseJobRepositoryAdapter(db)
    job = new_job("cve", "CVE-2026-1", "v1", now=now)

    claimed = repo.claim(job, now=now)
    assert claimed is not None
    repo.save(claimed.transition(JobState.RUNNING, now=now))

    stored = repo.get(job.idempotency_key)
    assert stored.state == JobState.RUNNING
    assert db.saved[job.idempotency_key]["state"] == "running"


def test_force_mode_allows_reprocessing_same_version():
    clock = FakeClock()
    repo = InMemoryJobRepository()
    db = FakeDB(docs=[{"_id": "doc-1"}])

    first = process_source("cve", db, FakeDiagnosticAgent(), FakeRecommenderAgent(), 10, job_repository=repo, clock=clock)
    second = process_source("cve", db, FakeDiagnosticAgent(), FakeRecommenderAgent(), 10, job_repository=repo, clock=clock, force=True)

    assert first == 1
    assert second == 1
    assert len(db.updated) == 2


def test_transient_failure_then_success_uses_retry_schedule_without_sleeping():
    clock = FakeClock()
    repo = InMemoryJobRepository()
    logger = StructuredJobLogger()
    metrics = WorkerMetrics()
    db = FakeDB(docs=[{"_id": "doc-1"}])

    first = process_source(
        "cve",
        db,
        FakeDiagnosticAgent(failures=[RuntimeError("temporary")]),
        FakeRecommenderAgent(),
        10,
        job_repository=repo,
        event_logger=logger,
        metrics=metrics,
        clock=clock,
    )
    assert first == 0
    assert metrics.retries == 1
    assert not clock.sleep_calls

    second = process_source(
        "cve",
        db,
        FakeDiagnosticAgent(),
        FakeRecommenderAgent(),
        10,
        job_repository=repo,
        event_logger=logger,
        metrics=metrics,
        clock=clock,
    )
    assert second == 0

    clock.advance(1)
    third = process_source(
        "cve",
        db,
        FakeDiagnosticAgent(),
        FakeRecommenderAgent(),
        10,
        job_repository=repo,
        event_logger=logger,
        metrics=metrics,
        clock=clock,
    )

    assert third == 1
    assert db.updated


def test_permanent_failure_marks_failed_without_retry():
    clock = FakeClock()
    repo = InMemoryJobRepository()
    logger = StructuredJobLogger()
    metrics = WorkerMetrics()
    db = FakeDB()

    outcome = WorkerJobExecutor(repository=repo, event_logger=logger, metrics=metrics, clock=clock).process_document(
        "cve",
        {"_id": "doc-1"},
        db,
        FakeDiagnosticAgent(failures=[ValueError("bad payload")]),
        FakeRecommenderAgent(),
    )

    assert outcome.processed is False
    assert outcome.job.state == JobState.FAILED
    assert logger.records[-1]["event"] == "job_failed"
    assert metrics.failed_jobs == 1


def test_retry_exhaustion_dead_letters_job():
    clock = FakeClock()
    repo = InMemoryJobRepository()
    logger = StructuredJobLogger()
    metrics = WorkerMetrics()
    db = FakeDB()
    policy = RetryPolicy(max_attempts=1)

    outcome = WorkerJobExecutor(repository=repo, retry_policy=policy, event_logger=logger, metrics=metrics, clock=clock).process_document(
        "cve",
        {"_id": "doc-1"},
        db,
        FakeDiagnosticAgent(failures=[RuntimeError("still down")]),
        FakeRecommenderAgent(),
    )

    assert outcome.job.state == JobState.DEAD_LETTER
    assert logger.records[-1]["event"] == "dead_lettered"
    assert metrics.dead_letter_jobs == 1


def test_failed_job_can_transition_to_dead_letter():
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)
    failed = new_job("cve", "CVE-2026-1", "v1", now=now).transition(JobState.RUNNING, now=now).transition(JobState.FAILED, now=now)

    dead = failed.transition(JobState.DEAD_LETTER, now=now, reason="operator_dead_letter")

    assert dead.state == JobState.DEAD_LETTER


def test_backoff_is_deterministic_and_capped():
    policy = RetryPolicy(base_delay_seconds=2, max_delay_seconds=5)
    now = datetime(2026, 6, 10, tzinfo=timezone.utc)

    assert policy.backoff_delay(1) == timedelta(seconds=2)
    assert policy.backoff_delay(3) == timedelta(seconds=5)
    assert policy.next_retry_at(now, 2) == now + timedelta(seconds=4)


def test_structured_log_fields_omit_sensitive_details():
    logger = StructuredJobLogger()
    job = new_job("cve", "CVE-2026-1", "v1", now=datetime(2026, 6, 10, tzinfo=timezone.utc))

    record = logger.emit("job_claimed", job, api_key="secret", token="secret", safe="ok")

    assert record["source"] == "cve"
    assert record["entity_identifier"] == "CVE-2026-1"
    assert "api_key" not in record["details"]
    assert "token" not in record["details"]
    assert record["details"]["safe"] == "ok"


def test_existing_worker_behavior_still_updates_each_unique_doc():
    db = FakeDB(docs=[{"_id": "doc-1"}, {"_id": "doc-2"}])

    processed = process_source("cve", db, FakeDiagnosticAgent(), FakeRecommenderAgent(), batch_size=10)

    assert processed == 2
    assert len(db.updated) == 2
    assert db.updated[0][1] == "doc-1"
    assert db.updated[0][2]["recommendations"] == ["review-doc-1"]
