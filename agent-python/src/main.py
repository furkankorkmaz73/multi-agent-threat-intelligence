import argparse
import logging
import time
from datetime import datetime, timezone
from typing import Iterable, List

from agents.diagnostic import DiagnosticAgent
from agents.recommender import RecommenderAgent
from config import APP_VERSION, DEFAULT_ACTIVE_SLEEP, DEFAULT_BATCH_SIZE, DEFAULT_IDLE_SLEEP
from core.database import DatabaseManager


def setup_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Threat-Agent analysis worker")
    parser.add_argument(
        "--source",
        choices=["cve", "urlhaus", "dread", "all"],
        default="all",
        help="Which source to process",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help="Maximum number of pending records to fetch per cycle and per source",
    )
    parser.add_argument(
        "--idle-sleep",
        type=int,
        default=DEFAULT_IDLE_SLEEP,
        help="Sleep duration in seconds when no new records are found",
    )
    parser.add_argument(
        "--active-sleep",
        type=int,
        default=DEFAULT_ACTIVE_SLEEP,
        help="Sleep duration in seconds after a productive cycle",
    )
    parser.add_argument(
        "--run-once",
        action="store_true",
        help="Process pending records once and exit",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=0,
        help="Maximum number of cycles to run in loop mode. 0 means unlimited.",
    )
    return parser.parse_args()


def resolve_sources(source_arg: str) -> List[str]:
    if source_arg == "all":
        return ["cve", "urlhaus", "dread"]
    return [source_arg]


def process_source(
    source: str,
    db: DatabaseManager,
    thinker: DiagnosticAgent,
    recommender: RecommenderAgent,
    batch_size: int,
) -> int:
    pending = db.get_unprocessed(source, limit=batch_size)

    if not pending:
        logging.info("No pending records for source=%s", source)
        return 0

    logging.info("Pending records for source=%s: %d", source, len(pending))
    processed_count = 0

    for doc in pending:
        doc_id = doc.get("_id", "unknown-id")
        logging.info("Processing source=%s doc_id=%s", source, doc_id)

        try:
            analysis = thinker.analyze(source, doc, db=db)
            if analysis is None:
                logging.warning("Skipped source=%s doc_id=%s because no analysis was returned", source, doc_id)
                continue

            analysis["recommendations"] = recommender.suggest(
                analysis_result=analysis,
                source=source,
                original_doc=doc,
            )
            analysis["source"] = source
            analysis["analyzed_at"] = datetime.now(timezone.utc)
            analysis["pipeline_version"] = APP_VERSION

            db.update_analysis(source, doc_id, analysis)

            logging.info(
                "Completed source=%s doc_id=%s level=%s score=%s confidence=%s",
                source,
                doc_id,
                analysis.get("risk_level"),
                analysis.get("risk_score"),
                analysis.get("confidence"),
            )
            processed_count += 1

        except Exception as exc:
            logging.exception(
                "Failed processing source=%s doc_id=%s error=%s",
                source,
                doc_id,
                exc,
            )

    return processed_count


def process_cycle(
    sources: Iterable[str],
    db: DatabaseManager,
    thinker: DiagnosticAgent,
    recommender: RecommenderAgent,
    batch_size: int,
) -> int:
    total_processed = 0

    for source in sources:
        total_processed += process_source(
            source=source,
            db=db,
            thinker=thinker,
            recommender=recommender,
            batch_size=batch_size,
        )

    return total_processed


def run_agent_loop(
    sources: List[str],
    batch_size: int,
    idle_sleep: int,
    active_sleep: int,
    run_once: bool = False,
    max_cycles: int = 0,
) -> None:
    db = DatabaseManager()
    thinker = DiagnosticAgent()
    recommender = RecommenderAgent()

    logging.info("Threat-Agent Intelligence Core started")
    logging.info(
        "Configuration sources=%s batch_size=%s idle_sleep=%ss active_sleep=%ss run_once=%s max_cycles=%s",
        ",".join(sources),
        batch_size,
        idle_sleep,
        active_sleep,
        run_once,
        max_cycles,
    )

    cycle_index = 0

    while True:
        cycle_index += 1
        logging.info("Starting cycle=%s", cycle_index)

        processed = process_cycle(
            sources=sources,
            db=db,
            thinker=thinker,
            recommender=recommender,
            batch_size=batch_size,
        )

        logging.info("Finished cycle=%s processed=%s", cycle_index, processed)

        if run_once:
            logging.info("Run-once mode enabled. Exiting after cycle=%s", cycle_index)
            break

        if max_cycles > 0 and cycle_index >= max_cycles:
            logging.info("Reached max_cycles=%s. Exiting.", max_cycles)
            break

        if processed == 0:
            logging.info("No new records found. Sleeping for %s second(s).", idle_sleep)
            time.sleep(idle_sleep)
        else:
            logging.info("Processed %s record(s). Sleeping for %s second(s).", processed, active_sleep)
            time.sleep(active_sleep)


def main() -> None:
    setup_logging()
    args = parse_args()

    sources = resolve_sources(args.source)

    run_agent_loop(
        sources=sources,
        batch_size=args.batch_size,
        idle_sleep=args.idle_sleep,
        active_sleep=args.active_sleep,
        run_once=args.run_once,
        max_cycles=args.max_cycles,
    )


if __name__ == "__main__":
    main()