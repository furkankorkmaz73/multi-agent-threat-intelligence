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

from .constants import *

def _get_nested(doc: Mapping[str, Any], path: str, default: Any = None) -> Any:
    current: Any = doc
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current

def _coalesce_nested(doc: Mapping[str, Any], *paths: str, default: Any = None) -> Any:
    for path in paths:
        value = _get_nested(doc, path, _MISSING)
        if value is _MISSING or value in (None, ""):
            continue
        return value
    return default

def _first_mapping(doc: Mapping[str, Any], *paths: str) -> Mapping[str, Any]:
    for path in paths:
        value = _get_nested(doc, path, _MISSING)
        if isinstance(value, Mapping):
            return value
    return {}

def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]

def _safe_int(value: Any) -> int:
    try:
        if value in ("", None):
            return 0
        return int(value)
    except (TypeError, ValueError):
        return 0

def _safe_float(value: Any) -> float:
    try:
        if value in ("", None):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0

def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "listed"}

def _format_metric(value: Any) -> str:
    if value is None:
        return "n/a"
    return str(value)

def _risk_bucket(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

def _confidence_bucket(confidence: float) -> str:
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"

def _accepted_external_count(row: Mapping[str, Any]) -> int:
    return _safe_int(row.get("accepted_urlhaus_count")) + _safe_int(row.get("accepted_dread_count"))

def _markdown_table(title: str, columns: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> list[str]:
    lines = [f"## {title}", "", "| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(column, "")) for column in columns) + " |")
    lines.append("")
    return lines

__all__ = [name for name in globals() if not name.startswith("__")]
