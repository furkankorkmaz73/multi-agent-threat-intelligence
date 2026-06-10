from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from evaluation.datasets import KevEntry, ParseResult, normalize_cve_id


KevLoader = Callable[[], str | Mapping[str, Any]]


def load_kev_json(path: str | Path) -> Mapping[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def parse_kev_json(data: str | Mapping[str, Any]) -> ParseResult:
    payload = json.loads(data) if isinstance(data, str) else data
    rows = payload.get("vulnerabilities") if isinstance(payload, Mapping) else None
    if not isinstance(rows, list):
        return ParseResult(items={}, total_rows=0, valid_rows=0, duplicate_rows=0, malformed_rows=1)

    entries: dict[str, KevEntry] = {}
    duplicate_rows = 0
    malformed_rows = 0
    missing_required_rows = 0
    for row in rows:
        if not isinstance(row, Mapping):
            malformed_rows += 1
            continue
        cve_id = normalize_cve_id(row.get("cveID") or row.get("cve_id") or row.get("cve"))
        if not cve_id:
            missing_required_rows += 1
            continue
        if cve_id in entries:
            duplicate_rows += 1
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            date_added=_optional_str(row.get("dateAdded")),
            vendor_project=_optional_str(row.get("vendorProject")),
            product=_optional_str(row.get("product")),
            vulnerability_name=_optional_str(row.get("vulnerabilityName")),
            known_ransomware_campaign_use=_optional_str(row.get("knownRansomwareCampaignUse")),
            due_date=_optional_str(row.get("dueDate")),
            notes=_optional_str(row.get("notes")),
        )
    return ParseResult(
        items=entries,
        total_rows=len(rows),
        valid_rows=len(entries),
        duplicate_rows=duplicate_rows,
        malformed_rows=malformed_rows,
        missing_required_rows=missing_required_rows,
    )


def load_kev_entries(path: Optional[str | Path] = None, *, loader: Optional[KevLoader] = None) -> ParseResult:
    if loader is not None:
        return parse_kev_json(loader())
    if path is None:
        raise ValueError("Either path or loader must be provided")
    return parse_kev_json(load_kev_json(path))


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
