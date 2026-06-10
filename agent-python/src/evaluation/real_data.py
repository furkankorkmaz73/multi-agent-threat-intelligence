from __future__ import annotations

import gzip
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import URLError
from urllib.request import Request, urlopen

from evaluation.datasets import ParseResult
from evaluation.epss import parse_epss_csv
from evaluation.kev import parse_kev_json


CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"


class RealDataError(RuntimeError):
    pass


class DataUnavailableError(RealDataError):
    pass


class DataFormatError(RealDataError):
    pass


Fetcher = Callable[[str, float], bytes | str]
Parser = Callable[[str], ParseResult]
Clock = Callable[[], datetime]


@dataclass(frozen=True)
class DataSourceSpec:
    name: str
    url: str
    cache_filename: str
    parser: Parser
    compressed: bool = False


@dataclass(frozen=True)
class DatasetProvenance:
    source_name: str
    source_url: str
    downloaded_at: str | None
    content_hash: str
    file_path: str
    byte_count: int
    row_count: int
    parser_stats: Mapping[str, Any]
    cache_hit: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_url": self.source_url,
            "downloaded_at": self.downloaded_at,
            "content_hash": self.content_hash,
            "file_path": self.file_path,
            "byte_count": self.byte_count,
            "row_count": self.row_count,
            "parser_stats": dict(self.parser_stats),
            "cache_hit": self.cache_hit,
        }


@dataclass(frozen=True)
class CachedDataset:
    text: str
    parse_result: ParseResult
    provenance: DatasetProvenance


KEV_SOURCE = DataSourceSpec(
    name="cisa_kev",
    url=CISA_KEV_URL,
    cache_filename="cisa_kev.json",
    parser=lambda text: parse_kev_json(text),
)

EPSS_SOURCE = DataSourceSpec(
    name="first_epss",
    url=FIRST_EPSS_CSV_URL,
    cache_filename="first_epss.csv",
    parser=parse_epss_csv,
    compressed=True,
)


def load_cached_dataset(
    spec: DataSourceSpec,
    cache_dir: str | Path,
    *,
    refresh: bool = False,
    offline: bool = False,
    timeout_seconds: float = 30.0,
    fetcher: Fetcher | None = None,
    now: Clock | None = None,
) -> CachedDataset:
    cache_path = Path(cache_dir) / spec.cache_filename
    if cache_path.exists() and (offline or not refresh):
        text = cache_path.read_text(encoding="utf-8")
        return _build_cached_dataset(spec, cache_path, text, downloaded_at=_read_downloaded_at(cache_path, text), cache_hit=True)

    if offline:
        raise DataUnavailableError(f"{spec.name} cache is unavailable in offline mode: {cache_path}")

    payload = _download(spec.url, timeout_seconds=timeout_seconds, fetcher=fetcher)
    text = _decode_payload(payload, compressed=spec.compressed)
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(text, encoding="utf-8")
    timestamp = (now or _utc_now)().isoformat()
    _write_cache_metadata(cache_path, spec, text, downloaded_at=timestamp)
    return _build_cached_dataset(spec, cache_path, text, downloaded_at=timestamp, cache_hit=False)


def _build_cached_dataset(
    spec: DataSourceSpec,
    cache_path: Path,
    text: str,
    *,
    downloaded_at: str | None,
    cache_hit: bool,
) -> CachedDataset:
    parse_result = spec.parser(text)
    if parse_result.valid_rows <= 0:
        raise DataFormatError(f"{spec.name} dataset contained no valid rows")
    encoded = text.encode("utf-8")
    provenance = DatasetProvenance(
        source_name=spec.name,
        source_url=spec.url,
        downloaded_at=downloaded_at,
        content_hash=hashlib.sha256(encoded).hexdigest(),
        file_path=str(cache_path),
        byte_count=len(encoded),
        row_count=parse_result.valid_rows,
        parser_stats=parse_result.to_dict(),
        cache_hit=cache_hit,
    )
    return CachedDataset(text=text, parse_result=parse_result, provenance=provenance)


def _download(url: str, *, timeout_seconds: float, fetcher: Fetcher | None) -> bytes | str:
    if fetcher is not None:
        return fetcher(url, timeout_seconds)
    try:
        request = Request(url, headers={"User-Agent": "multi-agent-threat-intelligence-benchmark/1.0"})
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - official URLs are fixed by DataSourceSpec
            return response.read()
    except URLError as exc:
        raise DataUnavailableError(f"Unable to download {url}: {exc}") from exc


def _decode_payload(payload: bytes | str, *, compressed: bool) -> str:
    if isinstance(payload, str):
        return payload
    data = gzip.decompress(payload) if compressed or payload.startswith(b"\x1f\x8b") else payload
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DataFormatError("Downloaded dataset is not UTF-8 text") from exc


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _metadata_path(cache_path: Path) -> Path:
    return cache_path.with_name(f"{cache_path.name}.metadata.json")


def _write_cache_metadata(cache_path: Path, spec: DataSourceSpec, text: str, *, downloaded_at: str) -> None:
    payload = {
        "source_name": spec.name,
        "source_url": spec.url,
        "downloaded_at": downloaded_at,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }
    _metadata_path(cache_path).write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _read_downloaded_at(cache_path: Path, text: str) -> str | None:
    metadata_path = _metadata_path(cache_path)
    if not metadata_path.exists():
        return None
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    expected_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if payload.get("content_hash") != expected_hash:
        return None
    value = payload.get("downloaded_at")
    return str(value) if value else None
