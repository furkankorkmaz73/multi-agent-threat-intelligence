from copy import deepcopy
from datetime import datetime, timedelta, timezone

from bson import ObjectId

from core.database import DatabaseManager
from worker.job_lifecycle import JobState, new_job


class FakeCursor(list):
    def limit(self, _n):
        return self


class FakeCollection:
    def __init__(self, total=0, processed=0, analyzed=0, avg_risk_score=0.0):
        self.created_indexes = []
        self.last_update = None
        self.total = total
        self.processed = processed
        self.analyzed = analyzed
        self.avg_risk_score = avg_risk_score

    def create_index(self, spec):
        self.created_indexes.append(spec)

    def update_one(self, flt, update, upsert=False):
        self.last_update = {"filter": flt, "update": update, "upsert": upsert}

    def count_documents(self, query):
        if query == {}:
            return self.total
        if query == {"processed": True}:
            return self.processed
        if query == {"analysis": {"$exists": True}}:
            return self.analyzed
        return self.analyzed

    def find(self, query, projection=None):
        if "analysis.risk_score" in query:
            return FakeCursor([{"analysis": {"risk_score": 8.0}} for _ in range(max(self.analyzed, 1))])
        return FakeCursor([])

    def aggregate(self, pipeline):
        if not self.analyzed:
            return []
        return [{"_id": None, "avg_risk_score": self.avg_risk_score}]


class FakeDBManager(DatabaseManager):
    def __init__(self):
        self.client = object()
        self.db = object()
        self.collections = {"cve": FakeCollection(), "urlhaus": FakeCollection(), "dread": FakeCollection()}
        self._ensure_indexes()


class MatchingCollection(FakeCollection):
    def __init__(self, docs):
        super().__init__(total=len(docs), processed=0, analyzed=0)
        self.docs = docs

    def update_one(self, flt, update, upsert=False):
        super().update_one(flt, update, upsert=upsert)
        for doc in self.docs:
            if self._matches(doc, flt):
                self._apply_update(doc, update)
                break

    def find_one_and_update(self, flt, update, return_document=None):
        self.last_update = {"filter": flt, "update": update, "return_document": return_document}
        for doc in self.docs:
            if self._matches(doc, flt):
                before = deepcopy(doc)
                self._apply_update(doc, update)
                return before
        return None

    def _apply_update(self, doc, update):
        for key, value in update.get("$set", {}).items():
            self._set_nested(doc, key, value)
        for key, value in update.get("$push", {}).items():
            entries = value.get("$each", [value]) if isinstance(value, dict) else [value]
            target = self._get_nested(doc, key)
            if target is None:
                self._set_nested(doc, key, [])
                target = self._get_nested(doc, key)
            target.extend(entries)
            if isinstance(value, dict) and "$slice" in value:
                self._set_nested(doc, key, target[value["$slice"] :])

    def _matches(self, doc, flt):
        if "$and" in flt:
            return all(self._matches(doc, clause) for clause in flt["$and"])
        if "$or" in flt:
            return any(self._matches(doc, clause) for clause in flt["$or"])
        return all(self._matches_field(doc, key, value) for key, value in flt.items())

    def _matches_field(self, doc, key, expected):
        actual = self._get_nested(doc, key)
        if isinstance(expected, dict):
            for operator, value in expected.items():
                if operator == "$exists":
                    exists = actual is not None
                    if exists is not bool(value):
                        return False
                elif operator == "$lte":
                    if actual is None or actual > value:
                        return False
                else:
                    return False
            return True
        return actual == expected

    def _get_nested(self, doc, key):
        current = doc
        for part in key.split("."):
            if not isinstance(current, dict) or part not in current:
                return None
            current = current[part]
        return current

    def _set_nested(self, doc, key, value):
        current = doc
        parts = key.split(".")
        for part in parts[:-1]:
            current = current.setdefault(part, {})
        current[parts[-1]] = value


def test_update_analysis_persists_history_and_meta():
    db = FakeDBManager()
    analysis = {
        "entity_id": "CVE-2026-9999",
        "risk_score": 8.7,
        "risk_level": "HIGH",
        "confidence": 0.91,
        "recommendations": ["patch"],
        "feature_breakdown": {
            "urlhaus_avg_semantic_score": 0.61,
            "dread_avg_semantic_score": 0.22,
        },
        "graph_summary": {"centrality_score": 0.44},
    }
    db.update_analysis("cve", "CVE-2026-9999", analysis)

    saved = db.collections["cve"].last_update
    assert saved is not None
    assert saved["filter"] == {"_id": "CVE-2026-9999"}

    set_payload = saved["update"]["$set"]
    push_payload = saved["update"]["$push"]["analysis_history"]

    assert set_payload["processed"] is True
    assert set_payload["analysis"]["persistence_meta"]["pipeline_version"]
    assert isinstance(set_payload["analysis_updated_at"], datetime)
    assert push_payload["$slice"] == -10
    history_entry = push_payload["$each"][0]
    assert history_entry["risk_score"] == 8.7
    assert history_entry["semantic_signal"] == 0.61
    assert history_entry["graph_centrality"] == 0.44


def test_update_job_lifecycle_persists_urlhaus_state_by_stable_identifier():
    db = FakeDBManager()
    mongo_id = ObjectId("64f000000000000000000001")
    db.collections["urlhaus"] = MatchingCollection(
        [{"_id": mongo_id, "urlhaus_id": "UH-E2E-9101", "url": "https://malware.invalid/e2e/CVE-2026-9101/payload.exe"}]
    )
    lifecycle = {
        "state": "completed",
        "attempt_count": 1,
        "idempotency_key": "stable-key",
        "transition_history": [{"from_state": "running", "to_state": "completed"}],
    }

    db.update_job_lifecycle("urlhaus", "UH-E2E-9101", lifecycle)

    saved = db.collections["urlhaus"].docs[0]
    assert saved["processed"] is True
    assert saved["job_lifecycle"]["state"] == "completed"
    assert saved["job_lifecycle"]["idempotency_key"] == "stable-key"
    assert saved["job_lifecycle_history"][-1]["state"] == "completed"


def test_update_job_lifecycle_only_successful_analysis_marks_processed():
    db = FakeDBManager()
    db.collections["cve"] = MatchingCollection([{"_id": "CVE-2026-9999", "processed": False}])

    for state, expected_processed in [
        ("completed", True),
        ("completed_with_warnings", True),
        ("failed", False),
        ("retry_scheduled", False),
        ("dead_letter", False),
    ]:
        db.update_job_lifecycle(
            "cve",
            "CVE-2026-9999",
            {
                "state": state,
                "attempt_count": 1,
                "idempotency_key": f"key-{state}",
            },
        )
        assert db.collections["cve"].docs[0]["processed"] is expected_processed


def test_claim_job_lifecycle_claims_unclaimed_document_once():
    now = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
    db = FakeDBManager()
    db.collections["cve"] = MatchingCollection([{"_id": "CVE-2026-9999", "processed": False}])
    job = new_job("cve", "CVE-2026-9999", "v1", now=now)

    first = db.claim_job_lifecycle("cve", "CVE-2026-9999", job.to_dict(), now=now)
    second = db.claim_job_lifecycle("cve", "CVE-2026-9999", job.to_dict(), now=now)

    assert first["idempotency_key"] == job.idempotency_key
    assert second is None
    assert db.collections["cve"].docs[0]["job_lifecycle"]["state"] == "pending"
    assert db.collections["cve"].docs[0]["processed"] is False


def test_claim_job_lifecycle_rejects_future_retry_and_allows_due_retry():
    now = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
    future_retry = (
        new_job("cve", "CVE-2026-9999", "v1", now=now)
        .transition(JobState.RUNNING, now=now)
        .transition(JobState.RETRY_SCHEDULED, now=now, retry_at=now + timedelta(minutes=5))
    )
    db = FakeDBManager()
    db.collections["cve"] = MatchingCollection([{"_id": "CVE-2026-9999", "processed": False, "job_lifecycle": future_retry.to_dict()}])

    assert db.claim_job_lifecycle("cve", "CVE-2026-9999", future_retry.to_dict(), now=now) is None

    due = future_retry.transition(JobState.RUNNING, now=now + timedelta(minutes=5))
    retry_scheduled = due.transition(JobState.RETRY_SCHEDULED, now=now + timedelta(minutes=5), retry_at=now)
    db.collections["cve"].docs[0]["job_lifecycle"] = retry_scheduled.to_dict()

    claimed = db.claim_job_lifecycle("cve", "CVE-2026-9999", retry_scheduled.to_dict(), now=now)

    assert claimed["state"] == "retry_scheduled"
    assert db.collections["cve"].docs[0]["job_lifecycle"]["state"] == "running"
    claim_history = db.collections["cve"].docs[0]["job_lifecycle_history"][-1]
    assert claim_history["state"] == "running"
    assert claim_history["attempt_count"] == retry_scheduled.attempt_count
    assert claim_history["updated_at"] == now
    assert claim_history["last_error"] == retry_scheduled.last_error
    assert db.collections["cve"].docs[0]["processed"] is False


def test_claim_job_lifecycle_rejects_completed_unless_forced():
    now = datetime(2026, 6, 10, 12, 0, 0, tzinfo=timezone.utc)
    completed = new_job("cve", "CVE-2026-9999", "v1", now=now).transition(JobState.RUNNING, now=now).transition(JobState.COMPLETED, now=now)
    replacement = new_job("cve", "CVE-2026-9999", "v1", now=now + timedelta(minutes=1))
    db = FakeDBManager()
    db.collections["cve"] = MatchingCollection([{"_id": "CVE-2026-9999", "processed": True, "job_lifecycle": completed.to_dict()}])

    assert db.claim_job_lifecycle("cve", "CVE-2026-9999", replacement.to_dict(), now=now) is None

    forced = db.claim_job_lifecycle("cve", "CVE-2026-9999", replacement.to_dict(), now=now, force=True)

    assert forced["state"] == "pending"
    assert forced["idempotency_key"] == replacement.idempotency_key
    assert db.collections["cve"].docs[0]["job_lifecycle"]["state"] == "pending"


def test_ensure_indexes_runs_for_all_sources():
    db = FakeDBManager()
    assert len(db.collections["cve"].created_indexes) >= 3
    assert len(db.collections["urlhaus"].created_indexes) >= 3
    assert len(db.collections["dread"].created_indexes) >= 3


def test_persist_analysis_result_uses_upsert_and_doc_resolution():
    db = FakeDBManager()
    original = {"url": "https://mal.example/test", "threat": "malware"}
    analysis = {
        "entity_id": "https://mal.example/test",
        "risk_score": 7.3,
        "risk_level": "HIGH",
        "confidence": 0.8,
        "recommendations": ["block domain"],
        "feature_breakdown": {},
        "graph_summary": {},
    }
    doc_id = db.persist_analysis_result("urlhaus", original, analysis)
    saved = db.collections["urlhaus"].last_update
    assert doc_id == "https://mal.example/test"
    assert saved["upsert"] is True
    assert saved["update"]["$set"]["processed"] is True
    assert saved["update"]["$set"]["analysis"]["persistence_meta"]["persist_mode"] == "api"


def test_status_overview_aggregates_source_counts():
    db = FakeDBManager()
    db.collections = {
        "cve": FakeCollection(total=10, processed=6, analyzed=5, avg_risk_score=4.25),
        "urlhaus": FakeCollection(total=4, processed=4, analyzed=4, avg_risk_score=6.5),
        "dread": FakeCollection(total=2, processed=1, analyzed=1, avg_risk_score=2.0),
    }
    overview = db.get_status_overview()
    assert overview["totals"]["total"] == 16
    assert overview["totals"]["analyzed"] == 10
    assert overview["sources"]["cve"]["analysis_coverage"] == 0.5
    assert overview["sources"]["cve"]["avg_risk_score"] == 4.25
