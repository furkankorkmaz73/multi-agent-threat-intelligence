from __future__ import annotations

import argparse
import json
import os
import signal
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pymongo

from config import APP_VERSION
from evaluation.runner import write_report_json


REPO_ROOT = Path(__file__).resolve().parents[3]
AGENT_GO_DIR = REPO_ROOT / "agent-go"
AGENT_PYTHON_DIR = REPO_ROOT / "agent-python"
DEFAULT_OUTPUT_DIR = Path("~/thesis-artifacts/e2e-system").expanduser()
DEFAULT_DB_NAME = "threat_intel_e2e"
DEFAULT_MONGO_URI = "mongodb://127.0.0.1:27017"
ANALYST_KEY = "e2e-analyst-key"
VIEWER_KEY = "e2e-viewer-key"
OPERATOR_KEY = "e2e-operator-key"
TERMINAL_JOB_STATES = {"completed", "completed_with_warnings", "failed", "dead_letter"}


@dataclass
class ProcessResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
        }


def run_e2e_system(
    *,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    mongo_uri: str = DEFAULT_MONGO_URI,
    db_name: str = DEFAULT_DB_NAME,
    generated_at: str | None = None,
    start_mongodb: bool = True,
    cleanup_database: bool = True,
    api_port: int | None = None,
) -> dict[str, Any]:
    if not db_name.startswith("threat_intel_e2e"):
        raise ValueError("E2E runner refuses to reset databases outside the threat_intel_e2e namespace")

    generated = generated_at or datetime.now(timezone.utc).isoformat()
    output = Path(output_dir).expanduser()
    output.mkdir(parents=True, exist_ok=True)
    process_log: list[dict[str, Any]] = []
    started_compose_mongo = False
    api_process: subprocess.Popen[str] | None = None
    api_log_path = output / "api_server.log"

    try:
        if not _mongo_ping(mongo_uri):
            if not start_mongodb:
                raise RuntimeError(f"MongoDB is unavailable at {mongo_uri}")
            started_compose_mongo = _start_compose_mongo(process_log)
            _wait_for_mongo(mongo_uri, timeout_seconds=45)

        client = pymongo.MongoClient(mongo_uri, serverSelectionTimeoutMS=2000, connectTimeoutMS=2000)
        client.admin.command("ping")
        if cleanup_database:
            client.drop_database(db_name)
        db = client[db_name]

        env = _e2e_env(mongo_uri, db_name)
        cve_fixture = AGENT_GO_DIR / "testdata" / "e2e" / "cve_fixture.json"
        urlhaus_fixture = AGENT_GO_DIR / "testdata" / "e2e" / "urlhaus_fixture.json"

        process_log.append(
            _run(
                ["go", "run", "./cmd/agent-go", "-source", "cve", "-fixture-file", str(cve_fixture), "-limit", "0"],
                cwd=AGENT_GO_DIR,
                env=env,
            ).to_dict()
        )
        process_log.append(
            _run(
                ["go", "run", "./cmd/agent-go", "-source", "urlhaus", "-fixture-file", str(urlhaus_fixture), "-limit", "0"],
                cwd=AGENT_GO_DIR,
                env=env,
            ).to_dict()
        )
        counts_after_ingest = _collection_counts(db)
        shape = _stored_shape_summary(db)

        process_log.append(
            _run(
                [sys.executable, "src/main.py", "--source", "all", "--run-once", "--batch-size", "10"],
                cwd=AGENT_PYTHON_DIR,
                env=env,
                timeout_seconds=120,
            ).to_dict()
        )
        counts_after_worker = _collection_counts(db)
        worker_snapshot = _worker_snapshot(db)
        analysis_history_before = _analysis_history_lengths(db)

        process_log.append(
            _run(
                [sys.executable, "src/main.py", "--source", "all", "--run-once", "--batch-size", "10"],
                cwd=AGENT_PYTHON_DIR,
                env=env,
                timeout_seconds=120,
            ).to_dict()
        )
        analysis_history_after = _analysis_history_lengths(db)
        duplicate_suppression = {
            "analysis_history_unchanged": analysis_history_before == analysis_history_after,
            "before": analysis_history_before,
            "after": analysis_history_after,
        }

        port = api_port or _free_port()
        api_process = _start_api(env, port=port, log_path=api_log_path)
        api_checks = _run_api_checks(port)

        database_snapshot = _database_snapshot(db)
        report = {
            "generated_at": generated,
            "environment": {
                "mongo_uri": _redact_uri(mongo_uri),
                "db_name": db_name,
                "started_compose_mongodb": started_compose_mongo,
                "api_port": port,
                "python_executable": sys.executable,
            },
            "component_versions": {"pipeline_version": APP_VERSION},
            "fixtures": {"cve_fixture": str(cve_fixture), "urlhaus_fixture": str(urlhaus_fixture), "dread_fixture": None},
            "ingestion": {"counts_after_ingest": counts_after_ingest, "stored_shape": shape},
            "worker": worker_snapshot,
            "duplicate_suppression": duplicate_suppression,
            "correlation_summary": _correlation_summary(db),
            "api_checks": api_checks,
            "database_snapshot": database_snapshot,
            "process_log": process_log,
            "limitations": [
                "E2E fixtures are deterministic integration fixtures, not real-world threat evidence.",
                "Dread ingestion is excluded because the Go Dread collector requires live Tor/dark-web access.",
                "Correlation decisions are reported from existing policy without threshold changes.",
            ],
        }
        report["validation"] = _validation_summary(report)
        report["status"] = "passed" if report["validation"]["valid"] else "failed"
        write_report_json(report, output / "e2e_system_report.json")
        write_report_json(api_checks, output / "e2e_http_responses.json")
        write_report_json(database_snapshot, output / "e2e_database_snapshot.json")
        write_report_json(process_log, output / "e2e_process_log.json")
        _assert_report_valid(report)
        return _stable(report)
    finally:
        if api_process is not None:
            _terminate_process(api_process)
        if started_compose_mongo:
            process_log.append(_run(["docker", "compose", "stop", "mongodb"], cwd=REPO_ROOT, env=os.environ.copy(), check=False).to_dict())


def _e2e_env(mongo_uri: str, db_name: str) -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "MONGO_URI": mongo_uri,
            "DB_NAME": db_name,
            "LLM_ENABLED": "0",
            "SEMANTIC_ALLOW_DOWNLOAD": "0",
            "API_AUTH_MODE": "api_key",
            "API_KEYS": f"{ANALYST_KEY}:analyst:e2e-analyst,{VIEWER_KEY}:viewer:e2e-viewer,{OPERATOR_KEY}:operator:e2e-operator",
            "MONGO_SERVER_SELECTION_TIMEOUT_MS": "2000",
            "MONGO_CONNECT_TIMEOUT_MS": "2000",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": "src",
        }
    )
    return env


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    timeout_seconds: int = 90,
    check: bool = True,
) -> ProcessResult:
    start = time.monotonic()
    completed = subprocess.run(
        list(command),
        cwd=str(cwd),
        env=dict(env),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout_seconds,
    )
    result = ProcessResult(
        command=list(command),
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        duration_ms=int((time.monotonic() - start) * 1000),
    )
    if check and completed.returncode != 0:
        raise RuntimeError(f"Command failed ({completed.returncode}): {' '.join(command)}\n{completed.stderr}\n{completed.stdout}")
    return result


def _mongo_ping(uri: str) -> bool:
    try:
        client = pymongo.MongoClient(uri, serverSelectionTimeoutMS=1200, connectTimeoutMS=1200)
        client.admin.command("ping")
        return True
    except Exception:
        return False


def _start_compose_mongo(process_log: list[dict[str, Any]]) -> bool:
    if shutil.which("docker") is None:
        raise RuntimeError("Docker is required to start disposable MongoDB, but the docker command is unavailable")
    probe = subprocess.run(["docker", "--version"], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if probe.returncode != 0:
        raise RuntimeError(f"Docker is required to start disposable MongoDB, but docker is not usable: {probe.stderr or probe.stdout}")
    result = _run(["docker", "compose", "up", "-d", "mongodb"], cwd=REPO_ROOT, env=os.environ.copy(), timeout_seconds=120)
    process_log.append(result.to_dict())
    return True


def _wait_for_mongo(uri: str, *, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _mongo_ping(uri):
            return
        time.sleep(1)
    raise RuntimeError(f"Timed out waiting for MongoDB at {uri}")


def _start_api(env: Mapping[str, str], *, port: int, log_path: Path) -> subprocess.Popen[str]:
    handle = log_path.open("w", encoding="utf-8")
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "api.app:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(AGENT_PYTHON_DIR),
        env=dict(env),
        text=True,
        stdout=handle,
        stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"API process exited early with code {process.returncode}; see {log_path}")
        try:
            response = _http_json(f"http://127.0.0.1:{port}/health")
            if response["status_code"] == 200:
                return process
        except Exception:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for API on port {port}; see {log_path}")


def _run_api_checks(port: int) -> dict[str, Any]:
    base = f"http://127.0.0.1:{port}"
    checks = {
        "health": _http_json(f"{base}/health"),
        "unauthorized_recent": _http_json(f"{base}/findings/recent?source=cve&limit=10"),
        "authorized_recent": _http_json(f"{base}/findings/recent?source=cve&limit=10", headers={"x-api-key": ANALYST_KEY}),
        "authorized_detail": _http_json(f"{base}/findings/detail?source=cve&entity_id=CVE-2026-9101", headers={"x-api-key": ANALYST_KEY}),
        "viewer_forbidden_status": _http_json(f"{base}/status/overview", headers={"x-api-key": VIEWER_KEY}),
        "operator_status": _http_json(f"{base}/status/overview", headers={"x-api-key": OPERATOR_KEY}),
    }
    checks["response_shape"] = {
        "recent_is_list": isinstance(checks["authorized_recent"].get("json"), list),
        "recent_count": len(checks["authorized_recent"].get("json") or []),
        "detail_keys": sorted((checks["authorized_detail"].get("json") or {}).keys()),
        "detail_has_risk_score": "risk_score" in (checks["authorized_detail"].get("json") or {}),
        "detail_has_evidence": "evidence" in (checks["authorized_detail"].get("json") or {}),
        "detail_has_evidence_summary": "evidence_summary" in (checks["authorized_detail"].get("json") or {}),
    }
    return checks


def _http_json(url: str, headers: Mapping[str, str] | None = None) -> dict[str, Any]:
    request = Request(url, headers=dict(headers or {}))
    try:
        with urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return {"status_code": response.status, "json": json.loads(body), "body": body[:1000]}
    except HTTPError as exc:
        body = exc.read().decode("utf-8")
        try:
            payload = json.loads(body)
        except Exception:
            payload = None
        return {"status_code": exc.code, "json": payload, "body": body[:1000]}
    except URLError as exc:
        return {"status_code": 0, "json": None, "body": str(exc)}


def _collection_counts(db: Any) -> dict[str, dict[str, int]]:
    result = {}
    for source, name in _collections().items():
        collection = db[name]
        result[source] = {
            "total": int(collection.count_documents({})),
            "processed": int(collection.count_documents({"processed": True})),
            "unprocessed": int(collection.count_documents({"processed": False})),
            "analyzed": int(collection.count_documents({"analysis": {"$exists": True}})),
        }
    return result


def _stored_shape_summary(db: Any) -> dict[str, Any]:
    cve = db["cve_intel"].find_one({"_id": "CVE-2026-9101"}) or {}
    urlhaus = db["urlhaus_intel"].find_one({"urlhaus_id": "UH-E2E-9101"}) or {}
    return {
        "cve_has_normalized_fields": bool(cve.get("normalized_fields")),
        "cve_has_cvss_metric_v31": bool(((cve.get("metrics") or {}).get("cvss_metric_v31") or [])),
        "urlhaus_has_normalized_fields": bool(urlhaus.get("normalized_fields")),
        "urlhaus_has_urlhaus_id": bool(urlhaus.get("urlhaus_id")),
    }


def _worker_snapshot(db: Any) -> dict[str, Any]:
    docs = []
    for source, collection_name in _collections().items():
        for doc in db[collection_name].find({}).sort([("_id", pymongo.ASCENDING)]):
            analysis = doc.get("analysis") or {}
            job = doc.get("job_lifecycle") or {}
            docs.append(
                {
                    "source": source,
                    "document_id": str(doc.get("_id")),
                    "processed": bool(doc.get("processed")),
                    "has_analysis": bool(analysis),
                    "risk_score": analysis.get("risk_score"),
                    "risk_level": analysis.get("risk_level"),
                    "confidence": analysis.get("confidence"),
                    "job_state": job.get("state"),
                    "idempotency_key_present": bool(job.get("idempotency_key")),
                    "transition_states": [item.get("state") for item in doc.get("job_lifecycle_history", [])],
                    "orchestration_trace_count": len(analysis.get("orchestration_trace") or []),
                    "execution_plan_count": len(analysis.get("execution_plan") or []),
                    "critic_status": (analysis.get("critic_review") or {}).get("status"),
                }
            )
    snapshot = {
        "records": docs,
        "processed_result_count": sum(1 for item in docs if item["has_analysis"]),
        "terminal_states": sorted({str(item["job_state"]) for item in docs if item.get("job_state")}),
    }
    snapshot["lifecycle_validation"] = _lifecycle_validation(docs)
    return snapshot


def _lifecycle_validation(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    violations = []
    for item in records:
        if not (item.get("processed") or item.get("has_analysis")):
            continue
        source = str(item.get("source"))
        document_id = str(item.get("document_id"))
        if item.get("job_state") not in TERMINAL_JOB_STATES:
            violations.append({"source": source, "document_id": document_id, "reason": "missing_terminal_job_state", "job_state": item.get("job_state")})
        if not item.get("idempotency_key_present"):
            violations.append({"source": source, "document_id": document_id, "reason": "missing_idempotency_key"})
        if not item.get("transition_states"):
            violations.append({"source": source, "document_id": document_id, "reason": "missing_lifecycle_transition_history"})
    return {
        "valid": not violations,
        "processed_record_count": sum(1 for item in records if item.get("processed") or item.get("has_analysis")),
        "violations": violations,
        "terminal_states_expected": sorted(TERMINAL_JOB_STATES),
    }


def _analysis_history_lengths(db: Any) -> dict[str, int]:
    lengths = {}
    for source, collection_name in _collections().items():
        for doc in db[collection_name].find({"analysis": {"$exists": True}}):
            lengths[f"{source}:{doc.get('_id')}"] = len(doc.get("analysis_history") or [])
    return dict(sorted(lengths.items()))


def _correlation_summary(db: Any) -> dict[str, Any]:
    doc = db["cve_intel"].find_one({"_id": "CVE-2026-9101"}) or {}
    analysis = doc.get("analysis") or {}
    evidence = analysis.get("evidence") or {}
    stats = evidence.get("urlhaus_match_stats") or {}
    return {
        "cve_id": "CVE-2026-9101",
        "related_urlhaus_count": evidence.get("related_urlhaus_count", 0),
        "candidate_urlhaus_count": evidence.get("candidate_urlhaus_count", 0),
        "accepted_match_count": stats.get("accepted_match_count", 0),
        "rejected_match_count": stats.get("rejected_match_count", 0),
        "manual_review_count": stats.get("manual_review_count", 0),
        "exact_cve_hits": stats.get("exact_cve_hits", 0),
        "shared_terms": stats.get("shared_terms", []),
    }


def _database_snapshot(db: Any) -> dict[str, Any]:
    snapshot = {"counts": _collection_counts(db), "documents": []}
    for source, collection_name in _collections().items():
        for doc in db[collection_name].find({}).sort([("_id", pymongo.ASCENDING)]):
            analysis = doc.get("analysis") or {}
            snapshot["documents"].append(
                {
                    "source": source,
                    "document_id": str(doc.get("_id")),
                    "entity_id": analysis.get("entity_id"),
                    "processed": bool(doc.get("processed")),
                    "has_analysis": bool(analysis),
                    "job_state": (doc.get("job_lifecycle") or {}).get("state"),
                    "idempotency_key_present": bool((doc.get("job_lifecycle") or {}).get("idempotency_key")),
                    "risk_score": analysis.get("risk_score"),
                    "risk_level": analysis.get("risk_level"),
                }
            )
    return snapshot


def _validation_summary(report: Mapping[str, Any]) -> dict[str, Any]:
    failures = []
    counts = report.get("ingestion", {}).get("counts_after_ingest", {})
    worker = report.get("worker", {})
    api_checks = report.get("api_checks", {})
    correlation = report.get("correlation_summary", {})

    for source in ("cve", "urlhaus"):
        source_counts = counts.get(source, {})
        if int(source_counts.get("total") or 0) < 2:
            failures.append({"check": f"{source}_ingested_count", "expected": ">=2", "actual": source_counts.get("total")})
    if int(worker.get("processed_result_count") or 0) < 4:
        failures.append({"check": "processed_result_count", "expected": ">=4", "actual": worker.get("processed_result_count")})
    lifecycle = worker.get("lifecycle_validation", {})
    if lifecycle.get("valid") is not True:
        failures.append({"check": "processed_record_lifecycle_persistence", "violations": lifecycle.get("violations", [])})
    if report.get("duplicate_suppression", {}).get("analysis_history_unchanged") is not True:
        failures.append({"check": "duplicate_suppression"})
    if int(correlation.get("accepted_match_count") or 0) < 1 or int(correlation.get("exact_cve_hits") or 0) < 1:
        failures.append({"check": "accepted_urlhaus_correlation", "correlation_summary": correlation})

    expected_statuses = {
        "health": 200,
        "unauthorized_recent": 401,
        "authorized_recent": 200,
        "authorized_detail": 200,
        "viewer_forbidden_status": 403,
        "operator_status": 200,
    }
    for name, expected in expected_statuses.items():
        actual = (api_checks.get(name) or {}).get("status_code")
        if actual != expected:
            failures.append({"check": f"api_{name}", "expected": expected, "actual": actual})
    shape = api_checks.get("response_shape") or {}
    if shape.get("detail_has_risk_score") is not True or not (shape.get("detail_has_evidence") or shape.get("detail_has_evidence_summary")):
        failures.append({"check": "api_detail_response_shape", "response_shape": shape})

    return {"valid": not failures, "failures": failures}


def _assert_report_valid(report: Mapping[str, Any]) -> None:
    validation = report.get("validation") or {}
    if validation.get("valid") is not True:
        raise RuntimeError(f"E2E validation failed: {json.dumps(validation.get('failures', []), sort_keys=True, default=str)}")


def _collections() -> dict[str, str]:
    return {"cve": "cve_intel", "urlhaus": "urlhaus_intel", "dread": "dread_intel"}


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _terminate_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.send_signal(signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _redact_uri(uri: str) -> str:
    if "@" not in uri:
        return uri
    scheme, rest = uri.split("://", 1)
    return f"{scheme}://***@{rest.split('@', 1)[1]}"


def _stable(payload: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(payload, sort_keys=True, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run production-like Go -> MongoDB -> Python worker -> FastAPI E2E scenario")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for E2E report artifacts")
    parser.add_argument("--mongo-uri", default=os.getenv("E2E_MONGO_URI", DEFAULT_MONGO_URI))
    parser.add_argument("--db-name", default=os.getenv("E2E_DB_NAME", DEFAULT_DB_NAME))
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--no-start-mongodb", action="store_true", help="Require an already-running MongoDB instance")
    parser.add_argument("--keep-database", action="store_true", help="Do not drop the E2E database before running")
    parser.add_argument("--api-port", type=int, default=None)
    args = parser.parse_args()
    try:
        report = run_e2e_system(
            output_dir=args.output_dir,
            mongo_uri=args.mongo_uri,
            db_name=args.db_name,
            generated_at=args.generated_at,
            start_mongodb=not args.no_start_mongodb,
            cleanup_database=not args.keep_database,
            api_port=args.api_port,
        )
    except Exception as exc:
        output = Path(args.output_dir).expanduser()
        output.mkdir(parents=True, exist_ok=True)
        report_path = output / "e2e_system_report.json"
        failure = {
            "generated_at": args.generated_at or datetime.now(timezone.utc).isoformat(),
            "status": "failed",
            "stage": "preflight_or_execution",
            "error": f"{type(exc).__name__}: {exc}",
            "environment": {"mongo_uri": _redact_uri(args.mongo_uri), "db_name": args.db_name},
            "limitations": ["E2E system execution requires a usable Docker/MongoDB runtime."],
        }
        if not report_path.exists():
            write_report_json(failure, report_path)
        print(json.dumps({"output": str(report_path), "status": "failed", "error": failure["error"]}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
    print(
        json.dumps(
            {
                "output": str(Path(args.output_dir).expanduser() / "e2e_system_report.json"),
                "processed_result_count": report["worker"]["processed_result_count"],
                "api_health_status": report["api_checks"]["health"]["status_code"],
                "duplicate_suppressed": report["duplicate_suppression"]["analysis_history_unchanged"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
