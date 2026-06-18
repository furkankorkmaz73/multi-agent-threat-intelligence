from __future__ import annotations

import csv
import gzip
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen


FIRST_EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
DEFAULT_EPSS_CACHE_FILENAME = "first_epss.csv"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)
Fetcher = Callable[[str, float], bytes | str]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class EpssEntry:
    cve_id: str
    probability: float
    percentile: float
    date: str | None = None
    source: str = "FIRST"

    def to_enrichment(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "available": True,
            "probability": self.probability,
            "percentile": self.percentile,
            "source": self.source,
        }
        if self.date:
            payload["date"] = self.date
        return payload


@dataclass(frozen=True)
class EpssParseResult:
    entries: Mapping[str, EpssEntry]
    total_rows: int
    valid_rows: int
    duplicate_rows: int
    malformed_rows: int
    missing_required_rows: int = 0
    source_date: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "valid_rows": self.valid_rows,
            "duplicate_rows": self.duplicate_rows,
            "malformed_rows": self.malformed_rows,
            "missing_required_rows": self.missing_required_rows,
            "source_date": self.source_date,
        }


@dataclass(frozen=True)
class EpssCatalog:
    entries: Mapping[str, EpssEntry]
    available: bool = True
    source: str = "FIRST"
    source_date: str | None = None
    cache_path: str | None = None
    cache_hit: bool = False
    error: str | None = None
    parser_stats: Mapping[str, Any] | None = None

    def lookup(self, cve_id: Any) -> dict[str, Any]:
        normalized = normalize_cve_id(cve_id)
        entry = self.entries.get(normalized or "") if self.available else None
        if entry is not None:
            return entry.to_enrichment()
        payload: dict[str, Any] = {"available": False, "source": self.source}
        if self.source_date:
            payload["date"] = self.source_date
        return payload


def normalize_cve_id(value: Any) -> str | None:
    text = str(value or "").strip().upper()
    return text if CVE_RE.fullmatch(text) else None


def parse_epss_csv(text: str) -> EpssParseResult:
    source_date = _source_date_from_comments(text)
    lines = [line for line in str(text).splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if not lines:
        return EpssParseResult(entries={}, total_rows=0, valid_rows=0, duplicate_rows=0, malformed_rows=0, source_date=source_date)

    entries: dict[str, EpssEntry] = {}
    duplicate_rows = 0
    malformed_rows = 0
    missing_required_rows = 0
    total_rows = 0
    reader = csv.DictReader(StringIO("\n".join(lines)))
    for row in reader:
        total_rows += 1
        parsed = _entry_from_row(row, fallback_date=source_date)
        if parsed == "missing":
            missing_required_rows += 1
            continue
        if parsed == "malformed":
            malformed_rows += 1
            continue
        assert isinstance(parsed, EpssEntry)
        if parsed.cve_id in entries:
            duplicate_rows += 1
        entries[parsed.cve_id] = parsed

    return EpssParseResult(
        entries=entries,
        total_rows=total_rows,
        valid_rows=len(entries),
        duplicate_rows=duplicate_rows,
        malformed_rows=malformed_rows,
        missing_required_rows=missing_required_rows,
        source_date=source_date,
    )


def parse_epss_api(data: str | Mapping[str, Any] | Sequence[Any]) -> EpssParseResult:
    payload = json.loads(data) if isinstance(data, str) else data
    if isinstance(payload, Mapping):
        rows = payload.get("data")
        if rows is None and any(key in payload for key in ("cve", "CVE", "epss", "percentile")):
            rows = [payload]
    else:
        rows = payload
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        return EpssParseResult(entries={}, total_rows=0, valid_rows=0, duplicate_rows=0, malformed_rows=1)

    entries: dict[str, EpssEntry] = {}
    duplicate_rows = 0
    malformed_rows = 0
    missing_required_rows = 0
    total_rows = 0
    source_date: str | None = None
    for row in rows:
        total_rows += 1
        if not isinstance(row, Mapping):
            malformed_rows += 1
            continue
        parsed = _entry_from_row(row)
        if parsed == "missing":
            missing_required_rows += 1
            continue
        if parsed == "malformed":
            malformed_rows += 1
            continue
        assert isinstance(parsed, EpssEntry)
        if source_date is None and parsed.date:
            source_date = parsed.date
        if parsed.cve_id in entries:
            duplicate_rows += 1
        entries[parsed.cve_id] = parsed

    return EpssParseResult(
        entries=entries,
        total_rows=total_rows,
        valid_rows=len(entries),
        duplicate_rows=duplicate_rows,
        malformed_rows=malformed_rows,
        missing_required_rows=missing_required_rows,
        source_date=source_date,
    )


def load_epss_catalog(
    *,
    cache_dir: str | Path,
    refresh: bool = False,
    offline: bool = False,
    timeout_seconds: float = 30.0,
    fetcher: Fetcher | None = None,
    now: Clock | None = None,
) -> EpssCatalog:
    cache_path = Path(cache_dir) / DEFAULT_EPSS_CACHE_FILENAME
    cache_hit = False
    try:
        if cache_path.exists() and (offline or not refresh):
            text = cache_path.read_text(encoding="utf-8")
            cache_hit = True
        elif offline:
            return EpssCatalog(entries={}, available=False, cache_path=str(cache_path), error=f"EPSS cache is unavailable: {cache_path}")
        else:
            payload = _download(FIRST_EPSS_CSV_URL, timeout_seconds=timeout_seconds, fetcher=fetcher)
            text = _decode_payload(payload)
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            cache_path.write_text(text, encoding="utf-8")
            _write_cache_metadata(cache_path, text, downloaded_at=(now or _utc_now)().isoformat())
    except (OSError, URLError, ValueError) as exc:
        return EpssCatalog(entries={}, available=False, cache_path=str(cache_path), error=f"{type(exc).__name__}: {exc}")

    parsed = parse_epss_csv(text)
    if parsed.valid_rows <= 0:
        return EpssCatalog(
            entries={},
            available=False,
            source_date=parsed.source_date,
            cache_path=str(cache_path),
            cache_hit=cache_hit,
            error="EPSS dataset contained no valid rows",
            parser_stats=parsed.to_dict(),
        )
    return EpssCatalog(
        entries=parsed.entries,
        available=True,
        source_date=parsed.source_date,
        cache_path=str(cache_path),
        cache_hit=cache_hit,
        parser_stats=parsed.to_dict(),
    )


def _entry_from_row(row: Mapping[str, Any], *, fallback_date: str | None = None) -> EpssEntry | str:
    cve_id = normalize_cve_id(_first_present(row, "cve", "CVE", "cve_id", "cveID"))
    if not cve_id:
        return "missing"
    probability = _parse_probability(_first_present(row, "epss", "EPSS", "probability", "epss_probability"))
    percentile = _parse_probability(_first_present(row, "percentile", "epss_percentile"))
    if probability is None or percentile is None:
        return "malformed"
    return EpssEntry(
        cve_id=cve_id,
        probability=probability,
        percentile=percentile,
        date=_normalize_date(_first_present(row, "date", "score_date") or fallback_date),
    )


def _first_present(row: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in row and row[key] not in (None, ""):
            return row[key]
    return None


def _parse_probability(value: Any) -> float | None:
    try:
        if value is None or value == "":
            return None
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    if parsed < 0.0 or parsed > 1.0:
        return None
    return parsed


def _source_date_from_comments(text: str) -> str | None:
    for line in str(text).splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("#"):
            break
        match = re.search(r"score_date:([^,\s]+)", stripped)
        if match:
            return _normalize_date(match.group(1))
    return None


def _normalize_date(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text[:10] if re.match(r"^\d{4}-\d{2}-\d{2}", text) else text


def _download(url: str, *, timeout_seconds: float, fetcher: Fetcher | None) -> bytes | str:
    if fetcher is not None:
        return fetcher(url, timeout_seconds)
    request = Request(url, headers={"User-Agent": "multi-agent-threat-intelligence/1.0"})
    with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - fixed official URL
        return response.read()


def _decode_payload(payload: bytes | str) -> str:
    if isinstance(payload, str):
        return payload
    data = gzip.decompress(payload) if payload.startswith(b"\x1f\x8b") else payload
    return data.decode("utf-8")


def _write_cache_metadata(cache_path: Path, text: str, *, downloaded_at: str) -> None:
    payload = {
        "source_name": "first_epss",
        "source_url": FIRST_EPSS_CSV_URL,
        "downloaded_at": downloaded_at,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    cache_path.with_name(f"{cache_path.name}.metadata.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
