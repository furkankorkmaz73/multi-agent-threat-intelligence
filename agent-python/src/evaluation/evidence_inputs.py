from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import sys
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence
from urllib.error import URLError
from urllib.request import Request, urlopen

from evaluation.real_data import DataFormatError, DataUnavailableError


URLHAUS_JSON_RECENT_URL = "https://urlhaus.abuse.ch/downloads/json_recent/"
URLHAUS_JSON_FULL_URL = "https://urlhaus.abuse.ch/downloads/json/"
DEFAULT_URLHAUS_CACHE_FILENAME = "urlhaus_json_recent.json"
DEFAULT_URLHAUS_FULL_CACHE_FILENAME = "urlhaus_full.json"
TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,}", re.I)

Fetcher = Callable[[str, float], bytes | str]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class EvidenceLoadResult:
    records: Sequence[dict[str, Any]]
    provenance: Mapping[str, Any]
    malformed_records: Sequence[dict[str, Any]]


class FileRelatedEvidenceProvider:
    def __init__(
        self,
        *,
        urlhaus_records: Iterable[Mapping[str, Any]] = (),
        dread_records: Iterable[Mapping[str, Any]] = (),
        cve_records: Iterable[Mapping[str, Any]] = (),
    ) -> None:
        self.urlhaus_records = [_normalize_urlhaus_record(row, index) for index, row in enumerate(urlhaus_records)]
        self.dread_records = [_normalize_dread_record(row, index) for index, row in enumerate(dread_records)]
        self.cve_records = [dict(row) for row in cve_records]

    def find_related_urlhaus(self, keywords: list[str], limit: int = 20) -> list[dict[str, Any]]:
        return _find_related(self.urlhaus_records, keywords, ("url", "threat", "tags", "normalized_fields.search_text"), limit)

    def find_related_dread(self, keywords: list[str], limit: int = 20) -> list[dict[str, Any]]:
        return _find_related(self.dread_records, keywords, ("title", "content", "category", "normalized_fields.search_text"), limit)

    def find_related_cves(self, keywords: list[str], limit: int = 20) -> list[dict[str, Any]]:
        return _find_related(self.cve_records, keywords, ("_id", "descriptions", "normalized_fields.search_text"), limit)


def load_urlhaus_records(
    *,
    path: str | Path | None = None,
    cache_dir: str | Path,
    refresh: bool = False,
    offline: bool = False,
    timeout_seconds: float = 60.0,
    fetcher: Fetcher | None = None,
    now: Clock | None = None,
    source_url: str = URLHAUS_JSON_RECENT_URL,
    cache_filename: str = DEFAULT_URLHAUS_CACHE_FILENAME,
) -> EvidenceLoadResult:
    cache_path = Path(path) if path is not None else Path(cache_dir) / cache_filename
    cache_hit = False
    downloaded_at: str | None = None
    if path is not None:
        raw = cache_path.read_bytes()
        text = _decode_download_payload(raw)
        cache_hit = True
    elif cache_path.exists() and (offline or not refresh):
        text = cache_path.read_text(encoding="utf-8")
        downloaded_at = _read_downloaded_at(cache_path, text)
        cache_hit = True
    else:
        if offline:
            raise DataUnavailableError(f"URLhaus cache is unavailable in offline mode: {cache_path}")
        payload = _download(source_url, timeout_seconds=timeout_seconds, fetcher=fetcher)
        text = _decode_download_payload(payload)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(text, encoding="utf-8")
        downloaded_at = (now or _utc_now)().isoformat()
        _write_cache_metadata(
            cache_path,
            text,
            downloaded_at=downloaded_at,
            source_url=source_url,
            source_name="urlhaus_json_full" if source_url == URLHAUS_JSON_FULL_URL else "urlhaus_json_recent",
        )

    records, stats, malformed = parse_urlhaus_json(text)
    provenance = _provenance(
        source_name="urlhaus_json_full" if source_url == URLHAUS_JSON_FULL_URL else "urlhaus_json_recent",
        source_url=source_url,
        path=cache_path,
        text=text,
        parser_stats=stats,
        downloaded_at=downloaded_at,
        cache_hit=cache_hit,
    )
    return EvidenceLoadResult(records=records, provenance=provenance, malformed_records=malformed)


def parse_urlhaus_json(data: str | Mapping[str, Any] | Sequence[Any]) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    payload = json.loads(data) if isinstance(data, str) else data
    if isinstance(payload, Mapping):
        rows: list[Any] = []
        for value in payload.values():
            if isinstance(value, list):
                rows.extend(value)
            elif isinstance(value, Mapping):
                rows.append(value)
    elif isinstance(payload, list):
        rows = list(payload)
    else:
        raise DataFormatError("URLhaus JSON must be a list or an object containing lists")
    return _parse_rows(rows, _normalize_urlhaus_record)


def load_dread_records(path: str | Path | None = None) -> EvidenceLoadResult:
    if path is None:
        return EvidenceLoadResult(
            records=[],
            provenance={
                "source_name": "dread_local_export",
                "source_url": None,
                "file_path": None,
                "row_count": 0,
                "parser_stats": {"total_rows": 0, "valid_rows": 0, "duplicate_rows": 0, "malformed_rows": 0, "missing_required_rows": 0},
                "available": False,
            },
            malformed_records=[],
        )
    export_path = Path(path)
    text = export_path.read_text(encoding="utf-8")
    records, stats, malformed = parse_dread_export(text)
    return EvidenceLoadResult(
        records=records,
        provenance=_provenance(
            source_name="dread_local_export",
            source_url=None,
            path=export_path,
            text=text,
            parser_stats=stats,
            downloaded_at=None,
            cache_hit=True,
        )
        | {"available": True},
        malformed_records=malformed,
    )


def parse_dread_export(text: str) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    stripped = text.strip()
    if not stripped:
        return [], {"total_rows": 0, "valid_rows": 0, "duplicate_rows": 0, "malformed_rows": 0, "missing_required_rows": 0}, []
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            if isinstance(payload, Mapping):
                rows = payload.get("records") or payload.get("items") or payload.get("rows") or payload.get("vulnerabilities")
                if rows is None:
                    rows = [payload]
            else:
                rows = payload
            if not isinstance(rows, list):
                raise DataFormatError("Dread JSON export must contain a list of records")
            return _parse_rows(rows, _normalize_dread_record)

    rows = []
    malformed = []
    for index, line in enumerate(stripped.splitlines()):
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            malformed.append({"index": index, "reason": "invalid_json_line"})
    parsed, stats, parsed_malformed = _parse_rows(rows, _normalize_dread_record)
    stats["total_rows"] += len(malformed)
    stats["malformed_rows"] += len(malformed)
    return parsed, stats, malformed + parsed_malformed


def build_file_evidence_provider(
    *,
    urlhaus_path: str | Path | None = None,
    dread_path: str | Path | None = None,
    cache_dir: str | Path,
    refresh_urlhaus: bool = False,
    offline: bool = False,
    timeout_seconds: float = 60.0,
) -> tuple[FileRelatedEvidenceProvider, dict[str, Any]]:
    cache_path = Path(cache_dir) / DEFAULT_URLHAUS_CACHE_FILENAME
    should_load_urlhaus = urlhaus_path is not None or refresh_urlhaus or cache_path.exists()
    if should_load_urlhaus:
        urlhaus = load_urlhaus_records(path=urlhaus_path, cache_dir=cache_dir, refresh=refresh_urlhaus, offline=offline, timeout_seconds=timeout_seconds)
    else:
        urlhaus = EvidenceLoadResult(
            records=[],
            provenance={
                "source_name": "urlhaus_json_recent",
                "source_url": URLHAUS_JSON_RECENT_URL,
                "file_path": None,
                "row_count": 0,
                "parser_stats": {"total_rows": 0, "valid_rows": 0, "duplicate_rows": 0, "malformed_rows": 0, "missing_required_rows": 0},
                "available": False,
            },
            malformed_records=[],
        )
    dread = load_dread_records(dread_path)
    provider = FileRelatedEvidenceProvider(urlhaus_records=urlhaus.records, dread_records=dread.records)
    return provider, {
        "urlhaus": {"provenance": dict(urlhaus.provenance), "malformed_records": [dict(item) for item in urlhaus.malformed_records]},
        "dread": {"provenance": dict(dread.provenance), "malformed_records": [dict(item) for item in dread.malformed_records]},
    }


def _parse_rows(rows: Sequence[Any], normalizer: Callable[[Mapping[str, Any], int], dict[str, Any] | None]) -> tuple[list[dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    records: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    seen: set[str] = set()
    stats = {"total_rows": len(rows), "valid_rows": 0, "duplicate_rows": 0, "malformed_rows": 0, "missing_required_rows": 0}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            stats["malformed_rows"] += 1
            malformed.append({"index": index, "reason": "row_not_object"})
            continue
        normalized = normalizer(row, index)
        if normalized is None:
            stats["missing_required_rows"] += 1
            malformed.append({"index": index, "reason": "missing_required_fields"})
            continue
        key = str(normalized.pop("_dedupe_key", None) or normalized.get("_id") or normalized.get("url") or normalized.get("title")).lower()
        if key in seen:
            stats["duplicate_rows"] += 1
            continue
        seen.add(key)
        records.append(normalized)
        stats["valid_rows"] += 1
    return records, stats, malformed


def _normalize_urlhaus_record(row: Mapping[str, Any], index: int) -> dict[str, Any] | None:
    url = _optional_str(row.get("url"))
    if not url:
        return None
    urlhaus_id = _optional_str(row.get("id") or row.get("urlhaus_id") or row.get("_id")) or f"urlhaus-{index}"
    tags = _normalize_tags(row.get("tags"))
    threat = _optional_str(row.get("threat")) or ""
    reference = _optional_str(row.get("urlhaus_reference") or row.get("urlhaus_link") or row.get("urlhausLink"))
    normalized = {
        "_dedupe_key": url,
        "_id": urlhaus_id,
        "urlhaus_id": urlhaus_id,
        "id": urlhaus_id,
        "date_added": _optional_str(row.get("date_added") or row.get("dateAdded") or row.get("dateadded")),
        "url": url,
        "url_status": _optional_str(row.get("url_status") or row.get("urlStatus")),
        "threat": threat,
        "tags": tags,
        "urlhaus_reference": reference,
        "urlhaus_link": reference,
        "reporter": _optional_str(row.get("reporter")),
    }
    normalized["normalized_fields"] = {
        "entity_type": "urlhaus",
        "aliases": sorted({urlhaus_id, url}),
        "keywords": sorted(set(_tokens(threat) + [str(tag).lower() for tag in tags])),
        "references": [item for item in (url, reference) if item],
        "search_text": _search_text(urlhaus_id, url, threat, reference or "", *tags),
    }
    return normalized


def _normalize_dread_record(row: Mapping[str, Any], index: int) -> dict[str, Any] | None:
    title = _optional_str(row.get("title"))
    content = _optional_str(row.get("content")) or ""
    if not title and not content:
        return None
    url = _optional_str(row.get("url"))
    created = _normalize_datetime_value(row.get("created_at") or row.get("createdAt") or row.get("published"))
    identifier = _optional_str(row.get("_id") or url or title) or f"dread-{index}"
    normalized = {
        "_dedupe_key": url or title or identifier,
        "_id": identifier,
        "title": title or identifier,
        "content": content,
        "author": _optional_str(row.get("author")),
        "category": _optional_str(row.get("category")),
        "source": _optional_str(row.get("source")) or "Dread",
        "url": url,
        "created_at": created,
        "published": created,
    }
    normalized["normalized_fields"] = {
        "entity_type": "dread",
        "aliases": sorted({item for item in (normalized["title"], url) if item}),
        "keywords": sorted(set(_tokens(" ".join(str(normalized.get(key) or "") for key in ("title", "content", "category", "author"))))),
        "references": [url] if url else [],
        "search_text": _search_text(normalized["title"], content, normalized.get("category") or "", normalized.get("author") or "", url or ""),
    }
    return normalized


def _find_related(records: Sequence[Mapping[str, Any]], keywords: Sequence[str], fields: Sequence[str], limit: int) -> list[dict[str, Any]]:
    terms = [str(term).strip().lower() for term in keywords if str(term).strip()][:20]
    if not terms:
        return []
    ranked = []
    for index, record in enumerate(records):
        haystack = " ".join(_field_values(record, fields)).lower()
        matched = [term for term in terms if term in haystack]
        if not matched:
            continue
        exact_cve = sum(1 for term in matched if term.startswith("cve-"))
        ranked.append((-exact_cve, -len(set(matched)), index, dict(record)))
    ranked.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in ranked[: max(0, int(limit))]]


def _field_values(record: Mapping[str, Any], fields: Sequence[str]) -> list[str]:
    values = []
    for field in fields:
        current: Any = record
        for part in field.split("."):
            if isinstance(current, Mapping):
                current = current.get(part)
            else:
                current = None
                break
        if isinstance(current, list):
            values.extend(str(item) for item in current)
        elif isinstance(current, Mapping):
            values.extend(str(item) for item in current.values())
        elif current is not None:
            values.append(str(current))
    return values


def _download(url: str, *, timeout_seconds: float, fetcher: Fetcher | None) -> bytes | str:
    if fetcher is not None:
        return fetcher(url, timeout_seconds)
    try:
        request = Request(url, headers={"User-Agent": "multi-agent-threat-intelligence-evidence-benchmark/1.0"})
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - official URLhaus URL is fixed
            return response.read()
    except URLError as exc:
        raise DataUnavailableError(f"Unable to download {url}: {exc}") from exc


def _decode_download_payload(payload: bytes | str) -> str:
    if isinstance(payload, str):
        return payload
    data = payload
    if data.startswith(b"PK\x03\x04"):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = [name for name in archive.namelist() if not name.endswith("/")]
            if not names:
                raise DataFormatError("Downloaded URLhaus ZIP did not contain a data file")
            data = archive.read(names[0])
    elif data.startswith(b"\x1f\x8b"):
        data = gzip.decompress(data)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DataFormatError("Downloaded URLhaus data is not UTF-8 text") from exc


def _normalize_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in re.split(r"[,|]", value) if item.strip()]
    return []


def _normalize_datetime_value(value: Any) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("$date") or value.get("date")
    text = _optional_str(value)
    return text


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _tokens(text: str) -> list[str]:
    return [match.group(0).lower() for match in TOKEN_RE.finditer(text or "")]


def _search_text(*parts: str) -> str:
    return " ".join(sorted(set(_tokens(" ".join(str(part or "") for part in parts)))))


def _provenance(
    *,
    source_name: str,
    source_url: str | None,
    path: Path,
    text: str,
    parser_stats: Mapping[str, int],
    downloaded_at: str | None,
    cache_hit: bool,
) -> dict[str, Any]:
    encoded = text.encode("utf-8")
    return {
        "source_name": source_name,
        "source_url": source_url,
        "downloaded_at": downloaded_at,
        "content_hash": hashlib.sha256(encoded).hexdigest(),
        "file_path": str(path),
        "byte_count": len(encoded),
        "row_count": int(parser_stats.get("valid_rows", 0)),
        "parser_stats": dict(parser_stats),
        "cache_hit": cache_hit,
        "available": True,
    }


def _metadata_path(cache_path: Path) -> Path:
    return cache_path.with_name(f"{cache_path.name}.metadata.json")


def _write_cache_metadata(
    cache_path: Path, text: str, *, downloaded_at: str, source_url: str, source_name: str
) -> None:
    _metadata_path(cache_path).write_text(
        json.dumps(
            {
                "source_name": source_name,
                "source_url": source_url,
                "downloaded_at": downloaded_at,
                "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


def _read_downloaded_at(cache_path: Path, text: str) -> str | None:
    path = _metadata_path(cache_path)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if payload.get("content_hash") != hashlib.sha256(text.encode("utf-8")).hexdigest():
        return None
    value = payload.get("downloaded_at")
    return str(value) if value else None


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def main() -> None:
    parser = argparse.ArgumentParser(description="Download/cache official URLhaus evidence for CVE evidence benchmarks")
    parser.add_argument("--urlhaus-file", default=None, help="Local official-format URLhaus JSON file")
    parser.add_argument("--cache-dir", required=True, help="Cache directory for URLhaus data")
    parser.add_argument("--refresh", action="store_true", help="Download official URLhaus data even if cached")
    parser.add_argument("--full", action="store_true", help="Use the official full URLhaus JSON ZIP instead of json_recent")
    parser.add_argument("--offline", action="store_true", help="Use local/cache input only")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    args = parser.parse_args()
    try:
        result = load_urlhaus_records(
            path=args.urlhaus_file,
            cache_dir=args.cache_dir,
            refresh=args.refresh,
            offline=args.offline,
            timeout_seconds=args.timeout_seconds,
            source_url=URLHAUS_JSON_FULL_URL if args.full else URLHAUS_JSON_RECENT_URL,
            cache_filename=DEFAULT_URLHAUS_FULL_CACHE_FILENAME if args.full else DEFAULT_URLHAUS_CACHE_FILENAME,
        )
    except (DataFormatError, DataUnavailableError) as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps(result.provenance, sort_keys=True))


if __name__ == "__main__":
    main()
