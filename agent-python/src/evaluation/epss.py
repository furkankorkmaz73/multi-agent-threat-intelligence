from __future__ import annotations

import csv
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Optional

from evaluation.datasets import EpssEntry, ParseResult, normalize_cve_id


EpssLoader = Callable[[], str]


def load_epss_csv(path: str | Path) -> str:
    return Path(path).read_text(encoding="utf-8")


def parse_epss_csv(text: str) -> ParseResult:
    lines = [line for line in str(text).splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return ParseResult(items={}, total_rows=0, valid_rows=0, duplicate_rows=0, malformed_rows=0)

    reader = csv.DictReader(StringIO("\n".join(lines)))
    entries: dict[str, EpssEntry] = {}
    duplicate_rows = 0
    malformed_rows = 0
    missing_required_rows = 0
    total_rows = 0
    for row in reader:
        total_rows += 1
        cve_id = normalize_cve_id(row.get("cve") or row.get("CVE"))
        if not cve_id:
            missing_required_rows += 1
            continue
        epss = _parse_probability(row.get("epss"))
        percentile = _parse_probability(row.get("percentile"))
        if epss is None or percentile is None:
            malformed_rows += 1
            continue
        entry = EpssEntry(cve_id=cve_id, epss=epss, percentile=percentile)
        existing = entries.get(cve_id)
        if existing is not None:
            duplicate_rows += 1
            if (entry.epss, entry.percentile) <= (existing.epss, existing.percentile):
                continue
        entries[cve_id] = entry
    return ParseResult(
        items=entries,
        total_rows=total_rows,
        valid_rows=len(entries),
        duplicate_rows=duplicate_rows,
        malformed_rows=malformed_rows,
        missing_required_rows=missing_required_rows,
    )


def load_epss_entries(path: Optional[str | Path] = None, *, loader: Optional[EpssLoader] = None) -> ParseResult:
    if loader is not None:
        return parse_epss_csv(loader())
    if path is None:
        raise ValueError("Either path or loader must be provided")
    return parse_epss_csv(load_epss_csv(path))


def _parse_probability(value: Any) -> Optional[float]:
    try:
        if value is None or value == "":
            return None
        return max(0.0, min(float(value), 1.0))
    except (TypeError, ValueError):
        return None
