#!/usr/bin/env python
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


AGENT_PYTHON_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = AGENT_PYTHON_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from config import DB_NAME, MONGO_URI, get_settings
from enrichment.cve_enrichment import EnrichmentSummary, build_cve_enrichment, build_enrichment_update, update_summary
from enrichment.epss import load_epss_catalog
from enrichment.kev import load_kev_catalog
from pymongo import MongoClient, UpdateOne


DEFAULT_CACHE_DIR = AGENT_PYTHON_ROOT / ".cache" / "cve_enrichment"
DEFAULT_BATCH_SIZE = 500


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enrich Mongo CVE documents with FIRST EPSS and CISA KEV data.")
    parser.add_argument("--limit", type=int, default=0, help="Maximum CVE documents to scan. 0 means all CVEs.")
    parser.add_argument("--offline", action="store_true", help="Use cached EPSS/KEV files only.")
    parser.add_argument("--refresh", action="store_true", help="Fetch latest EPSS/KEV data before enriching.")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR), help="Directory for cached EPSS and KEV files.")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE, help="Mongo read/write batch size.")
    parser.add_argument("--timeout-seconds", type=float, default=30.0, help="Network timeout for EPSS/KEV refreshes.")
    args = parser.parse_args()
    if args.limit < 0:
        parser.error("--limit must be zero or greater")
    if args.batch_size <= 0:
        parser.error("--batch-size must be greater than zero")
    return args


def run(args: argparse.Namespace) -> dict[str, Any]:
    settings = get_settings()
    cache_dir = Path(args.cache_dir).expanduser().resolve()
    epss_catalog = load_epss_catalog(
        cache_dir=cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        timeout_seconds=args.timeout_seconds,
    )
    kev_catalog = load_kev_catalog(
        cache_dir=cache_dir,
        refresh=args.refresh,
        offline=args.offline,
        timeout_seconds=args.timeout_seconds,
    )

    client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=settings.database.server_selection_timeout_ms,
        connectTimeoutMS=settings.database.connect_timeout_ms,
    )
    client.admin.command("ping")
    collection = client[DB_NAME]["cve_intel"]

    summary = EnrichmentSummary()
    operations: list[UpdateOne] = []
    cursor = collection.find({}, {"_id": 1}, batch_size=args.batch_size).sort([("_id", 1)])
    if args.limit:
        cursor = cursor.limit(args.limit)

    for doc in cursor:
        cve_id = doc.get("_id")
        enrichment = build_cve_enrichment(cve_id, epss_catalog=epss_catalog, kev_catalog=kev_catalog)
        update_summary(summary, enrichment)
        operations.append(UpdateOne({"_id": cve_id}, build_enrichment_update(cve_id, epss_catalog=epss_catalog, kev_catalog=kev_catalog)))
        if len(operations) >= args.batch_size:
            summary.updated += _flush_updates(collection, operations)
            operations = []

    if operations:
        summary.updated += _flush_updates(collection, operations)

    return {
        **summary.to_dict(),
        "epss_catalog_available": epss_catalog.available,
        "kev_catalog_available": kev_catalog.available,
        "epss_cache_path": epss_catalog.cache_path,
        "kev_cache_path": kev_catalog.cache_path,
        "epss_error": epss_catalog.error,
        "kev_error": kev_catalog.error,
    }


def _flush_updates(collection: Any, operations: list[UpdateOne]) -> int:
    result = collection.bulk_write(operations, ordered=False)
    return int(getattr(result, "modified_count", 0) or 0)


def main() -> int:
    args = parse_args()
    print(json.dumps(run(args), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
