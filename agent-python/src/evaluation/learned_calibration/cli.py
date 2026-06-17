from __future__ import annotations

import argparse
import csv
import json
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil, floor, log2
from pathlib import Path
from random import Random
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping, Sequence

import pymongo
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from config import DB_NAME, MONGO_URI, get_settings

SETTINGS = get_settings()

from .data import read_analyzed_cves_from_mongo, strict_validation_errors
from .reports import export_from_documents

def main() -> None:
    parser = argparse.ArgumentParser(description="Export learned-calibration feasibility artifacts from analyzed CVE records.")
    parser.add_argument("--output-dir", default="../reports/thesis")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when no usable analyzed CVE rows are exported.")
    args = parser.parse_args()
    docs = read_analyzed_cves_from_mongo(limit=args.limit)
    result = export_from_documents(docs, args.output_dir)
    if args.strict:
        errors = strict_validation_errors(result["report"])
        if errors:
            print(json.dumps({"status": "failed", "errors": errors}, indent=2))
            raise SystemExit(2)
    print(json.dumps({"status": "written", **result["paths"], "analyzed_records_exported": result["report"]["analyzed_records_exported"]}, indent=2))

