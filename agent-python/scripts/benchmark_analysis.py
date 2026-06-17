"""Bounded analysis benchmark for local demo performance checks.

Example:
    python scripts/benchmark_analysis.py --source cves --limit 100
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from agents.diagnostic import DiagnosticAgent
from agents.recommender import RecommenderAgent
from core.database import DatabaseManager
from worker.executor import WorkerJobExecutor
from worker.job_lifecycle import RetryPolicy
from worker.job_repository import build_job_repository
from worker.observability import StructuredJobLogger, WorkerMetrics, summarize_processing_metrics


SOURCE_ALIASES = {
    "cves": "cve",
    "cve": "cve",
    "urlhaus": "urlhaus",
    "dread": "dread",
}
MAX_LIMIT = 1000


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark bounded local analysis throughput.")
    parser.add_argument("--source", choices=["cves", "urlhaus", "dread"], required=True)
    parser.add_argument("--limit", type=int, default=50, help=f"Maximum documents to benchmark, capped at {MAX_LIMIT}.")
    parser.add_argument("--dry-run", "--no-persist", dest="dry_run", action="store_true", default=True, help="Analyze without persisting results. This is the default.")
    parser.add_argument("--persist", dest="dry_run", action="store_false", help="Persist analysis through the worker executor.")
    args = parser.parse_args()
    if args.limit <= 0:
        parser.error("--limit must be greater than zero")
    args.limit = min(args.limit, MAX_LIMIT)
    return args


def load_benchmark_docs(db: DatabaseManager, source: str, limit: int) -> list[dict[str, Any]]:
    return db.get_unprocessed(source, limit=limit)


def run_dry_analysis(source: str, doc: dict[str, Any], db: DatabaseManager, thinker: DiagnosticAgent, recommender: RecommenderAgent) -> None:
    analysis = thinker.analyze(source, doc, db=db)
    if analysis is None:
        raise RuntimeError("analysis returned no result")
    analysis["recommendations"] = recommender.suggest(analysis_result=analysis, source=source, original_doc=doc)


def run_persisted_analysis(
    source: str,
    doc: dict[str, Any],
    db: DatabaseManager,
    thinker: DiagnosticAgent,
    recommender: RecommenderAgent,
    executor: WorkerJobExecutor,
) -> bool:
    outcome = executor.process_document(source=source, doc=doc, db=db, thinker=thinker, recommender=recommender)
    return outcome.processed


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    source = SOURCE_ALIASES[args.source]
    db = DatabaseManager()
    thinker = DiagnosticAgent()
    recommender = RecommenderAgent()
    docs = load_benchmark_docs(db, source, args.limit)
    metrics = WorkerMetrics()
    executor = WorkerJobExecutor(
        repository=build_job_repository(db),
        retry_policy=RetryPolicy(),
        event_logger=StructuredJobLogger(),
        metrics=metrics,
        force=True,
    )

    processed = 0
    failed = 0
    skipped = 0
    latencies_ms: list[float] = []
    started = time.perf_counter()
    for doc in docs:
        item_started = time.perf_counter()
        try:
            if args.dry_run:
                run_dry_analysis(source, doc, db, thinker, recommender)
                processed += 1
            elif run_persisted_analysis(source, doc, db, thinker, recommender, executor):
                processed += 1
            else:
                skipped += 1
        except Exception:
            failed += 1
        finally:
            latencies_ms.append((time.perf_counter() - item_started) * 1000.0)

    elapsed = time.perf_counter() - started
    summary = summarize_processing_metrics(
        processed_count=processed,
        failed_count=failed,
        elapsed_seconds=elapsed,
        latency_ms=latencies_ms,
    )
    return {
        "source": args.source,
        "normalized_source": source,
        "requested_limit": args.limit,
        "loaded_count": len(docs),
        "processed_count": summary["processed"],
        "failed_count": summary["failed"],
        "skipped_count": skipped,
        "elapsed_seconds": summary["elapsed_seconds"],
        "docs_per_second": summary["docs_per_second"],
        "avg_latency_ms_per_doc": summary["avg_latency_ms"],
        "p95_latency_ms_per_doc": summary["p95_latency_ms"],
        "dry_run": args.dry_run,
    }


def main() -> int:
    args = parse_args()
    print(json.dumps(run_benchmark(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
