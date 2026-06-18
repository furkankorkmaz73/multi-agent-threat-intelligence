from __future__ import annotations

import csv
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_KEV_CACHE_FILENAME = "cisa_kev.json"
DEFAULT_KEV_CSV_CACHE_FILENAME = "cisa_kev.csv"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
Fetcher = Callable[[str, float], bytes | str]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    known_ransomware_campaign_use: str | None = None
    required_action: str | None = None
    notes: str | None = None
    source: str = "CISA"

    def to_enrichment(self, *, date_checked: str) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status_known": True,
            "listed": True,
            "source": self.source,
            "date_checked": date_checked,
        }
        optional_fields = {
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "date_added": self.date_added,
            "due_date": self.due_date,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
            "required_action": self.required_action,
            "notes": self.notes,
        }
        payload.update({key: value for key, value in optional_fields.items() if value is not None})
        return payload


@dataclass(frozen=True)
class KevParseResult:
    entries: Mapping[str, KevEntry]
    total_rows: int
    valid_rows: int
    duplicate_rows: int
    malformed_rows: int
    missing_required_rows: int = 0
    catalog_version: str | None = None
    date_released: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "valid_rows": self.valid_rows,
            "duplicate_rows": self.duplicate_rows,
            "malformed_rows": self.malformed_rows,
            "missing_required_rows": self.missing_required_rows,
            "catalog_version": self.catalog_version,
            "date_released": self.date_released,
        }


@dataclass(frozen=True)
class KevCatalog:
    entries: Mapping[str, KevEntry]
    available: bool = True
    source: str = "CISA"
    date_checked: str | None = None
    cache_path: str | None = None
    cache_hit: bool = False
    error: str | None = None
    parser_stats: Mapping[str, Any] | None = None

    def lookup(self, cve_id: Any, *, date_checked: str | None = None) -> dict[str, Any]:
        checked = date_checked or self.date_checked or _today()
        normalized = normalize_cve_id(cve_id)
        entry = self.entries.get(normalized or "") if self.available else None
        if entry is not None:
            return entry.to_enrichment(date_checked=checked)
        if self.available:
            return {"status_known": True, "listed": False, "source": self.source, "date_checked": checked}
        return {"status_known": False, "listed": False, "source": self.source, "date_checked": checked}


def normalize_cve_id(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if CVE_RE.fullmatch(text) else None


def parse_kev_json(data: str | Mapping[str, Any] | Sequence[Any]) -> KevParseResult:
    payload = json.loads(data) if isinstance(data, str) else data
    catalog_version: str | None = None
    date_released: str | None = None
    if isinstance(payload, Mapping):
        rows = payload.get("vulnerabilities")
        catalog_version = _optional_str(payload.get("catalogVersion"))
        date_released = _optional_str(payload.get("dateReleased"))
    else:
        rows = payload
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        return KevParseResult(entries={}, total_rows=0, valid_rows=0, duplicate_rows=0, malformed_rows=1)
    return _parse_rows(rows, catalog_version=catalog_version, date_released=date_released)


def parse_kev_csv(text: str) -> KevParseResult:
    rows = list(csv.DictReader(StringIO(str(text))))
    return _parse_rows(rows)


def load_kev_catalog(
    *,
    cache_dir: str | Path,
    refresh: bool = False,
    offline: bool = False,
    timeout_seconds: float = 30.0,
    fetcher: Fetcher | None = None,
    now: Clock | None = None,
) -> KevCatalog:
    cache_root = Path(cache_dir)
    json_cache_path = cache_root / DEFAULT_KEV_CACHE_FILENAME
    csv_cache_path = cache_root / DEFAULT_KEV_CSV_CACHE_FILENAME
    cache_path = _existing_cache_path(json_cache_path, csv_cache_path) or json_cache_path
    cache_hit = False
    checked = (now or _utc_now)().date().isoformat()
    try:
        if cache_path.exists() and (offline or not refresh):
            text = cache_path.read_text(encoding="utf-8")
            cache_hit = True
        elif offline:
            return KevCatalog(entries={}, available=False, date_checked=checked, cache_path=str(cache_path), error=f"KEV cache is unavailable: {cache_path}")
        else:
            payload = _download(CISA_KEV_URL, timeout_seconds=timeout_seconds, fetcher=fetcher)
            text = payload if isinstance(payload, str) else payload.decode("utf-8")
            json_cache_path.parent.mkdir(parents=True, exist_ok=True)
            json_cache_path.write_text(text, encoding="utf-8")
            cache_path = json_cache_path
            _write_cache_metadata(cache_path, text, downloaded_at=(now or _utc_now)().isoformat())
    except (OSError, URLError, ValueError) as exc:
        return KevCatalog(entries={}, available=False, date_checked=checked, cache_path=str(cache_path), error=f"{type(exc).__name__}: {exc}")

    parsed = parse_kev_json(text) if cache_path.suffix.lower() != ".csv" else parse_kev_csv(text)
    if parsed.valid_rows <= 0:
        return KevCatalog(
            entries={},
            available=False,
            date_checked=checked,
            cache_path=str(cache_path),
            cache_hit=cache_hit,
            error="KEV dataset contained no valid rows",
            parser_stats=parsed.to_dict(),
        )
    return KevCatalog(
        entries=parsed.entries,
        available=True,
        date_checked=checked,
        cache_path=str(cache_path),
        cache_hit=cache_hit,
        parser_stats=parsed.to_dict(),
    )


def _parse_rows(rows: Sequence[Any], *, catalog_version: str | None = None, date_released: str | None = None) -> KevParseResult:
    entries: dict[str, KevEntry] = {}
    duplicate_rows = 0
    malformed_rows = 0
    missing_required_rows = 0
    for row in rows:
        if not isinstance(row, Mapping):
            malformed_rows += 1
            continue
        cve_id = normalize_cve_id(_first_present(row, "cveID", "cve_id", "cve", "CVE"))
        if not cve_id:
            missing_required_rows += 1
            continue
        if cve_id in entries:
            duplicate_rows += 1
            continue
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor_project=_optional_str(_first_present(row, "vendorProject", "vendor_project")),
            product=_optional_str(row.get("product")),
            vulnerability_name=_optional_str(_first_present(row, "vulnerabilityName", "vulnerability_name")),
            date_added=_optional_str(_first_present(row, "dateAdded", "date_added")),
            due_date=_optional_str(_first_present(row, "dueDate", "due_date")),
            known_ransomware_campaign_use=_optional_str(_first_present(row, "knownRansomwareCampaignUse", "known_ransomware_campaign_use")),
            required_action=_optional_str(_first_present(row, "requiredAction", "required_action")),
            notes=_optional_str(row.get("notes")),
        )
    return KevParseResult(
        entries=entries,
        total_rows=len(rows),
        valid_rows=len(entries),
        duplicate_rows=duplicate_rows,
        malformed_rows=malformed_rows,
        missing_required_rows=missing_required_rows,
        catalog_version=catalog_version,
        date_released=date_released,
    )


def _existing_cache_path(json_cache_path: Path, csv_cache_path: Path) -> Path | None:
    if json_cache_path.exists():
        return json_cache_path
    if csv_cache_path.exists():
        return csv_cache_path
    return None


def _first_present(row: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _download(url: str, *, timeout_seconds: float, fetcher: Fetcher | None) -> bytes | str:
    if fetcher is not None:
        return fetcher(url, timeout_seconds)
    request = Request(url, headers={"User-Agent": "multi-agent-threat-intelligence/1.0"})
    with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - fixed official URL
        return response.read()


def _write_cache_metadata(cache_path: Path, text: str, *, downloaded_at: str) -> None:
    payload = {
        "source_name": "cisa_kev",
        "source_url": CISA_KEV_URL,
        "downloaded_at": downloaded_at,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    cache_path.with_name(f"{cache_path.name}.metadata.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _today() -> str:
    return _utc_now().date().isoformat()
