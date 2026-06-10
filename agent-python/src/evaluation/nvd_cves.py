from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from evaluation.datasets import normalize_cve_id
from evaluation.real_benchmark import CURATED_BENCHMARK
from evaluation.real_data import DataFormatError, DataUnavailableError


NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_NVD_CACHE_FILENAME = "nvd_curated_cves.json"

Fetcher = Callable[[str, float], bytes | str]
Clock = Callable[[], datetime]


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
