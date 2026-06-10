from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from evaluation.datasets import normalize_cve_id
from evaluation.real_benchmark import CURATED_BENCHMARK
from evaluation.real_data import DataFormatError, DataUnavailableError


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_NVD_CACHE_FILENAME = "nvd_curated_cves.json"

Fetcher = Callable[[str, float], bytes | str]
Clock = Callable[[], datetime]
Sleeper = Callable[[float], None]


@dataclass(frozen=True)
class NvdCveProvenance:
    source_name: str
    source_url: str
    source_urls: Sequence[str]
    downloaded_at: str | None
    content_hash: str
    file_path: str
    byte_count: int
    requested_cves: Sequence[str]
    loaded_cves: Sequence[str]
    missing_cves: Sequence[str]
    parser_stats: Mapping[str, int]
    cache_hit: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_name": self.source_name,
            "source_url": self.source_url,
            "source_urls": list(self.source_urls),
            "downloaded_at": self.downloaded_at,
            "content_hash": self.content_hash,
            "file_path": self.file_path,
            "byte_count": self.byte_count,
            "requested_cves": list(self.requested_cves),
            "loaded_cves": list(self.loaded_cves),
            "missing_cves": list(self.missing_cves),
            "parser_stats": dict(self.parser_stats),
            "cache_hit": self.cache_hit,
        }


@dataclass(frozen=True)
class NvdCveLoadResult:
    records: Mapping[str, dict[str, Any]]
    provenance: NvdCveProvenance
    malformed_records: Sequence[dict[str, Any]]


def curated_cve_ids() -> list[str]:
    return [entry.cve_id for entry in CURATED_BENCHMARK]


def load_nvd_cves(
    *,
    cve_ids: Sequence[str] | None = None,
    cache_dir: str | Path,
    local_path: str | Path | None = None,
    refresh: bool = False,
    offline: bool = False,
    timeout_seconds: float = 30.0,
    fetcher: Fetcher | None = None,
    now: Clock | None = None,
) -> NvdCveLoadResult:
    requested = sorted({normalize_cve_id(item) for item in (cve_ids or curated_cve_ids()) if normalize_cve_id(item)})
    if not requested:
        raise ValueError("At least one valid CVE identifier is required")

    cache_path = Path(local_path) if local_path is not None else Path(cache_dir) / DEFAULT_NVD_CACHE_FILENAME
    cache_hit = False
    downloaded_at: str | None = None

    if local_path is not None:
        text = cache_path.read_text(encoding="utf-8")
        cache_hit = True
    elif cache_path.exists() and (offline or not refresh):
        text = cache_path.read_text(encoding="utf-8")
        downloaded_at = _read_downloaded_at(cache_path, text)
        cache_hit = True
    else:
        if offline:
            raise DataUnavailableError(f"NVD CVE cache is unavailable in offline mode: {cache_path}")
        payload = _download_curated_nvd(requested, timeout_seconds=timeout_seconds, fetcher=fetcher)
        text = json.dumps(payload, sort_keys=True)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(text, encoding="utf-8")
        downloaded_at = (now or _utc_now)().isoformat()
        _write_cache_metadata(cache_path, text, downloaded_at=downloaded_at)

    records, stats, malformed = parse_nvd_cve_records(text)
    selected = {cve_id: records[cve_id] for cve_id in requested if cve_id in records}
    missing = sorted(set(requested) - set(selected))
    if not selected and not malformed:
        raise DataFormatError("NVD CVE dataset contained no usable CVE records")
    encoded = text.encode("utf-8")
    provenance = NvdCveProvenance(
        source_name="nvd_cves",
        source_url=NVD_CVE_API_URL,
        source_urls=[_nvd_cve_url(cve_id) for cve_id in requested],
        downloaded_at=downloaded_at,
        content_hash=hashlib.sha256(encoded).hexdigest(),
        file_path=str(cache_path),
        byte_count=len(encoded),
        requested_cves=requested,
        loaded_cves=sorted(selected),
        missing_cves=missing,
        parser_stats=stats,
        cache_hit=cache_hit,
    )
    return NvdCveLoadResult(records=selected, provenance=provenance, malformed_records=malformed)


def download_nvd_candidate_pool(
    *,
    output_path: str | Path,
    severity_levels: Sequence[str] = ("CRITICAL", "HIGH", "MEDIUM"),
    results_per_page: int = 2000,
    max_pages_per_severity: int = 1,
    refresh: bool = False,
    timeout_seconds: float = 30.0,
    delay_seconds: float = 6.0,
    retry_attempts: int = 3,
    fetcher: Fetcher | None = None,
    sleeper: Sleeper | None = None,
    now: Clock | None = None,
) -> dict[str, Any]:
    path = Path(output_path)
    if path.exists() and not refresh:
        text = path.read_text(encoding="utf-8")
        records, stats, malformed = parse_nvd_cve_records(text)
        return _candidate_pool_summary(
            path=path,
            payload=json.loads(text),
            stats=stats,
            malformed=malformed,
            cache_hit=True,
            downloaded_at=_read_downloaded_at(path, text),
        )

    if results_per_page <= 0:
        raise ValueError("results_per_page must be positive")
    if max_pages_per_severity <= 0:
        raise ValueError("max_pages_per_severity must be positive")

    vulnerabilities: list[dict[str, Any]] = []
    seen: set[str] = set()
    source_urls: list[str] = []
    query_stats: dict[str, Any] = {}
    sleep = sleeper or time.sleep
    levels = [str(level).upper() for level in severity_levels]

    for severity_index, severity in enumerate(levels):
        start_index = 0
        pages: list[dict[str, int]] = []
        for page_index in range(max_pages_per_severity):
            url = _nvd_query_url(cvssV3Severity=severity, resultsPerPage=results_per_page, startIndex=start_index)
            source_urls.append(url)
            payload = _download_json_with_retries(
                url,
                timeout_seconds=timeout_seconds,
                fetcher=fetcher,
                retry_attempts=retry_attempts,
                delay_seconds=delay_seconds,
                sleeper=sleep,
            )
            rows = payload.get("vulnerabilities") if isinstance(payload, Mapping) else None
            if not isinstance(rows, list):
                raise DataFormatError(f"NVD candidate response missing vulnerabilities list: {url}")
            added = 0
            for row in rows:
                cve_payload = row.get("cve") if isinstance(row, Mapping) and isinstance(row.get("cve"), Mapping) else row
                cve_id = normalize_cve_id(cve_payload.get("id") if isinstance(cve_payload, Mapping) else None)
                if cve_id is None or cve_id in seen or not isinstance(row, Mapping):
                    continue
                seen.add(cve_id)
                vulnerabilities.append(dict(row))
                added += 1
            page_size = len(rows)
            total_results = int(payload.get("totalResults") or 0)
            pages.append({"start_index": start_index, "returned": page_size, "added": added, "total_results": total_results})
            if page_size == 0 or start_index + page_size >= total_results:
                break
            start_index += page_size
            if delay_seconds > 0 and (page_index + 1 < max_pages_per_severity):
                sleep(delay_seconds)
        query_stats[severity] = {"pages": pages, "added": sum(page["added"] for page in pages)}
        if delay_seconds > 0 and severity_index + 1 < len(levels):
            sleep(delay_seconds)

    downloaded_at = (now or _utc_now)().isoformat()
    payload = {
        "source": "nvd",
        "source_url": NVD_CVE_API_URL,
        "source_urls": source_urls,
        "downloaded_at": downloaded_at,
        "query": {
            "severity_levels": levels,
            "results_per_page": results_per_page,
            "max_pages_per_severity": max_pages_per_severity,
        },
        "query_stats": query_stats,
        "vulnerabilities": vulnerabilities,
    }
    text = json.dumps(payload, sort_keys=True)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    _write_cache_metadata(path, text, downloaded_at=downloaded_at)
    records, stats, malformed = parse_nvd_cve_records(text)
    return _candidate_pool_summary(path=path, payload=payload, stats=stats, malformed=malformed, cache_hit=False, downloaded_at=downloaded_at)


def parse_nvd_cve_records(data: str | Mapping[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, int], list[dict[str, Any]]]:
    payload = json.loads(data) if isinstance(data, str) else data
    rows = payload.get("vulnerabilities") if isinstance(payload, Mapping) else None
    if not isinstance(rows, list):
        raise DataFormatError("NVD CVE data must contain a vulnerabilities list")

    records: dict[str, dict[str, Any]] = {}
    malformed: list[dict[str, Any]] = []
    stats = {"total_rows": len(rows), "valid_rows": 0, "duplicate_rows": 0, "malformed_rows": 0, "missing_required_rows": 0}
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            stats["malformed_rows"] += 1
            malformed.append({"index": index, "reason": "row_not_object"})
            continue
        cve_payload = row.get("cve") if isinstance(row.get("cve"), Mapping) else row
        normalized = _normalize_official_nvd_cve(cve_payload)
        if normalized is None:
            stats["missing_required_rows"] += 1
            malformed.append({"index": index, "reason": "missing_required_cve_fields"})
            continue
        cve_id = normalized["_id"]
        if cve_id in records:
            stats["duplicate_rows"] += 1
            continue
        records[cve_id] = normalized
        stats["valid_rows"] += 1
    return records, stats, malformed


def _normalize_official_nvd_cve(cve: Mapping[str, Any]) -> dict[str, Any] | None:
    cve_id = normalize_cve_id(cve.get("id") or cve.get("_id") or cve.get("cveID") or cve.get("cve_id"))
    descriptions = cve.get("descriptions") if isinstance(cve.get("descriptions"), list) else []
    if cve_id is None or not descriptions:
        return None
    return {
        "_id": cve_id,
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified") or cve.get("last_modified"),
        "descriptions": [dict(item) for item in descriptions if isinstance(item, Mapping)],
        "metrics": _normalize_metrics(cve.get("metrics") if isinstance(cve.get("metrics"), Mapping) else {}),
        "processed": False,
        "source_metadata": {"source": "nvd", "source_ref": cve_id},
    }


def _normalize_metrics(metrics: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "cvss_metric_v40": [_normalize_metric(item) for item in metrics.get("cvssMetricV40", metrics.get("cvss_metric_v40", []))],
        "cvss_metric_v31": [_normalize_metric(item) for item in metrics.get("cvssMetricV31", metrics.get("cvss_metric_v31", []))],
        "cvss_metric_v30": [_normalize_metric(item) for item in metrics.get("cvssMetricV30", metrics.get("cvss_metric_v30", []))],
        "cvss_metric_v2": [_normalize_metric(item) for item in metrics.get("cvssMetricV2", metrics.get("cvss_metric_v2", []))],
    }


def _normalize_metric(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        return {}
    cvss_data = item.get("cvssData") or item.get("cvss_data") or {}
    if not isinstance(cvss_data, Mapping):
        cvss_data = {}
    out = dict(item)
    out.pop("cvssData", None)
    out["cvss_data"] = {
        "base_score": cvss_data.get("baseScore", cvss_data.get("base_score", 0.0)),
        "base_severity": cvss_data.get("baseSeverity", cvss_data.get("base_severity")),
    }
    return out


def _download_curated_nvd(cve_ids: Sequence[str], *, timeout_seconds: float, fetcher: Fetcher | None) -> dict[str, Any]:
    vulnerabilities: list[dict[str, Any]] = []
    for cve_id in cve_ids:
        payload = _download_json(_nvd_cve_url(cve_id), timeout_seconds=timeout_seconds, fetcher=fetcher)
        rows = payload.get("vulnerabilities") if isinstance(payload, Mapping) else None
        if isinstance(rows, list):
            vulnerabilities.extend(row for row in rows if isinstance(row, Mapping))
    return {"source": "nvd", "vulnerabilities": vulnerabilities}


def _download_json(url: str, *, timeout_seconds: float, fetcher: Fetcher | None) -> Mapping[str, Any]:
    if fetcher is not None:
        payload = fetcher(url, timeout_seconds)
    else:
        try:
            request = Request(url, headers={"User-Agent": "multi-agent-threat-intelligence-cve-export/1.0"})
            with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - official NVD URL is fixed
                payload = response.read()
        except HTTPError as exc:
            raise DataUnavailableError(f"Unable to download {url}: HTTP {exc.code} {exc.reason}") from exc
        except URLError as exc:
            raise DataUnavailableError(f"Unable to download {url}: {exc}") from exc
    text = payload.decode("utf-8") if isinstance(payload, bytes) else str(payload)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DataFormatError(f"NVD response was not valid JSON: {url}") from exc
    if not isinstance(parsed, Mapping):
        raise DataFormatError(f"NVD response was not a JSON object: {url}")
    return parsed


def _nvd_cve_url(cve_id: str) -> str:
    return f"{NVD_CVE_API_URL}?{urlencode({'cveId': cve_id})}"


def _nvd_query_url(**params: Any) -> str:
    return f"{NVD_CVE_API_URL}?{urlencode(params)}"


def _download_json_with_retries(
    url: str,
    *,
    timeout_seconds: float,
    fetcher: Fetcher | None,
    retry_attempts: int,
    delay_seconds: float,
    sleeper: Sleeper,
) -> Mapping[str, Any]:
    attempts = max(1, retry_attempts)
    last_error: DataUnavailableError | None = None
    for attempt in range(attempts):
        try:
            return _download_json(url, timeout_seconds=timeout_seconds, fetcher=fetcher)
        except DataUnavailableError as exc:
            last_error = exc
            if attempt + 1 >= attempts or not _is_retryable_download_error(exc):
                raise
            if delay_seconds > 0:
                sleeper(delay_seconds)
    assert last_error is not None
    raise last_error


def _is_retryable_download_error(exc: DataUnavailableError) -> bool:
    message = str(exc)
    return any(marker in message for marker in ("HTTP 429", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504", "timed out"))


def _candidate_pool_summary(
    *,
    path: Path,
    payload: Mapping[str, Any],
    stats: Mapping[str, int],
    malformed: Sequence[Mapping[str, Any]],
    cache_hit: bool,
    downloaded_at: str | None,
) -> dict[str, Any]:
    rows = payload.get("vulnerabilities") if isinstance(payload.get("vulnerabilities"), list) else []
    text = json.dumps(payload, sort_keys=True)
    return {
        "source_name": "nvd_candidate_pool",
        "source_url": NVD_CVE_API_URL,
        "source_urls": list(payload.get("source_urls") or []),
        "downloaded_at": downloaded_at,
        "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "file_path": str(path),
        "byte_count": len(text.encode("utf-8")),
        "raw_row_count": len(rows),
        "valid_cve_count": stats.get("valid_rows", 0),
        "duplicate_rows": stats.get("duplicate_rows", 0),
        "malformed_rows": stats.get("malformed_rows", 0) + stats.get("missing_required_rows", 0),
        "malformed_records": [dict(item) for item in malformed],
        "cache_hit": cache_hit,
        "query": dict(payload.get("query") or {}),
        "query_stats": dict(payload.get("query_stats") or {}),
    }


def _metadata_path(cache_path: Path) -> Path:
    return cache_path.with_name(f"{cache_path.name}.metadata.json")


def _write_cache_metadata(cache_path: Path, text: str, *, downloaded_at: str) -> None:
    _metadata_path(cache_path).write_text(
        json.dumps({"downloaded_at": downloaded_at, "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest()}, indent=2, sort_keys=True),
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
    parser = argparse.ArgumentParser(description="Download an official NVD CVE candidate pool for balanced benchmark selection")
    parser.add_argument("--candidate-pool-output", required=True, help="Output path for official-format NVD candidate JSON")
    parser.add_argument("--severity", action="append", dest="severity_levels", default=None, help="CVSS v3 severity query to include; repeatable")
    parser.add_argument("--results-per-page", type=int, default=2000, help="NVD resultsPerPage value")
    parser.add_argument("--max-pages-per-severity", type=int, default=1, help="Maximum pages to request for each severity")
    parser.add_argument("--refresh", action="store_true", help="Refresh even when the output file already exists")
    parser.add_argument("--timeout-seconds", type=float, default=30.0, help="NVD request timeout")
    parser.add_argument("--delay-seconds", type=float, default=6.0, help="Delay between NVD requests")
    parser.add_argument("--retry-attempts", type=int, default=3, help="Retry attempts for transient NVD failures")
    args = parser.parse_args()
    try:
        summary = download_nvd_candidate_pool(
            output_path=args.candidate_pool_output,
            severity_levels=args.severity_levels or ("CRITICAL", "HIGH", "MEDIUM"),
            results_per_page=args.results_per_page,
            max_pages_per_severity=args.max_pages_per_severity,
            refresh=args.refresh,
            timeout_seconds=args.timeout_seconds,
            delay_seconds=args.delay_seconds,
            retry_attempts=args.retry_attempts,
        )
    except (DataFormatError, DataUnavailableError, ValueError) as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
    print(json.dumps(summary, sort_keys=True))


if __name__ == "__main__":
    main()
