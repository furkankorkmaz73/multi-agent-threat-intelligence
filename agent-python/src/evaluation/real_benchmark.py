from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from evaluation.datasets import EvaluationRecord, join_external_signals, normalize_cve_id, records_from_model_results
from evaluation.real_data import (
    EPSS_SOURCE,
    KEV_SOURCE,
    CachedDataset,
    DataFormatError,
    DataSourceSpec,
    DatasetProvenance,
    RealDataError,
    load_cached_dataset,
)
from evaluation.runner import evaluate_baselines, load_model_results_json, write_report_json


DEFAULT_CACHE_DIR = Path(".cache/real_benchmark")
DEFAULT_OUTPUT_DIR = Path("reports/real_benchmark")
DEFAULT_GENERATED_AT = None


@dataclass(frozen=True)
class BenchmarkCve:
    cve_id: str
    bucket: str
    rationale: str

    def __post_init__(self) -> None:
        normalized = normalize_cve_id(self.cve_id)
        if normalized is None:
            raise ValueError(f"Invalid benchmark CVE identifier: {self.cve_id}")
        object.__setattr__(self, "cve_id", normalized)

    def to_dict(self) -> dict[str, str]:
        return {"cve_id": self.cve_id, "bucket": self.bucket, "rationale": self.rationale}


CURATED_BENCHMARK_VERSION = "real-cve-benchmark-v1"
PILOT_BENCHMARK_VERSION = CURATED_BENCHMARK_VERSION


PILOT_BENCHMARK: tuple[BenchmarkCve, ...] = (
    BenchmarkCve("CVE-2021-44228", "known_exploited_kev", "Apache Log4j remote code execution widely tracked by KEV."),
    BenchmarkCve("CVE-2023-34362", "known_exploited_kev", "MOVEit Transfer SQL injection and exploitation campaign case."),
    BenchmarkCve("CVE-2019-19781", "known_exploited_kev", "Citrix ADC/Gateway path traversal exploited at scale."),
    BenchmarkCve("CVE-2023-3519", "known_exploited_kev", "Citrix NetScaler ADC/Gateway code execution with KEV coverage."),
    BenchmarkCve("CVE-2022-30190", "known_exploited_kev", "Microsoft Support Diagnostic Tool exploitation case."),
    BenchmarkCve("CVE-2023-23752", "high_epss_candidate", "Joomla access issue selected for EPSS-driven comparison."),
    BenchmarkCve("CVE-2023-29489", "high_epss_candidate", "cPanel XSS case selected for EPSS-driven comparison."),
    BenchmarkCve("CVE-2020-0796", "high_cvss_control", "SMBv3 compression bug selected as high-CVSS control."),
    BenchmarkCve("CVE-2014-0160", "older_control", "Heartbleed selected as older vulnerability control."),
    BenchmarkCve("CVE-2017-0144", "older_known_exploited", "EternalBlue selected as older known-exploited control."),
)
CURATED_BENCHMARK: tuple[BenchmarkCve, ...] = PILOT_BENCHMARK


def validate_benchmark_definition(entries: Sequence[BenchmarkCve] = CURATED_BENCHMARK) -> dict[str, Any]:
    seen: set[str] = set()
    buckets: dict[str, int] = {}
    for entry in entries:
        if entry.cve_id in seen:
            raise ValueError(f"Duplicate benchmark CVE: {entry.cve_id}")
        seen.add(entry.cve_id)
        buckets[entry.bucket] = buckets.get(entry.bucket, 0) + 1
    return {"version": CURATED_BENCHMARK_VERSION, "record_count": len(entries), "buckets": buckets}


def run_real_benchmark(
    *,
    model_results_path: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    refresh: bool = False,
    offline: bool = False,
    timeout_seconds: float = 30.0,
    generated_at: str | None = DEFAULT_GENERATED_AT,
    kev_path: str | Path | None = None,
    epss_path: str | Path | None = None,
    benchmark: Sequence[BenchmarkCve] = CURATED_BENCHMARK,
) -> dict[str, Any]:
    validation = validate_benchmark_definition(benchmark)
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    model_rows = load_model_results_json(model_results_path)
    model_records, model_stats = records_from_model_results(model_rows)
    benchmark_ids = {entry.cve_id for entry in benchmark}
    model_by_cve = {record.cve_id: record for record in model_records if record.cve_id in benchmark_ids}
    missing_model_results = sorted(benchmark_ids - set(model_by_cve))

    kev_dataset = _load_dataset(KEV_SOURCE, cache_dir, refresh=refresh, offline=offline, timeout_seconds=timeout_seconds, local_path=kev_path)
    epss_dataset = _load_dataset(EPSS_SOURCE, cache_dir, refresh=refresh, offline=offline, timeout_seconds=timeout_seconds, local_path=epss_path)

    joined = join_external_signals(
        [model_by_cve[cve_id] for cve_id in sorted(model_by_cve)],
        kev_dataset.parse_result.items,
        epss_dataset.parse_result.items,
    )
    baseline_results = evaluate_baselines(joined, k_values=(1, 3, 5, 10))
    record_rows = _build_record_rows(benchmark, joined, kev_dataset, epss_dataset, missing_model_results)
    coverage = _coverage(record_rows, missing_model_results)
    report = {
        "generated_at": generated,
        "benchmark": validation,
        "official_sources": {
            "cisa_kev": KEV_SOURCE.url,
            "first_epss": EPSS_SOURCE.url,
        },
        "provenance": {
            "cisa_kev": kev_dataset.provenance.to_dict(),
            "first_epss": epss_dataset.provenance.to_dict(),
        },
        "model_results": {
            "path": str(model_results_path),
            "parse": model_stats,
            "matched_count": len(joined),
            "missing_model_results": missing_model_results,
        },
        "coverage": coverage,
        "metric_config": {"k_values": [1, 3, 5, 10], "label": "kev_or_exploitation_evidence"},
        "baselines": baseline_results,
        "records": record_rows,
    }
    write_benchmark_artifacts(report, output_dir)
    return _stable_json(report)


def write_benchmark_artifacts(report: Mapping[str, Any], output_dir: str | Path) -> dict[str, str]:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    summary_path = path / "benchmark_summary.json"
    records_path = path / "benchmark_records.csv"
    metrics_path = path / "baseline_metrics.csv"
    write_report_json(report, summary_path)
    _write_records_csv(report.get("records", []), records_path)
    _write_metrics_csv(report.get("baselines", {}), metrics_path)
    return {
        "benchmark_summary": str(summary_path),
        "benchmark_records": str(records_path),
        "baseline_metrics": str(metrics_path),
    }


def _load_dataset(
    spec: DataSourceSpec,
    cache_dir: str | Path,
    *,
    refresh: bool,
    offline: bool,
    timeout_seconds: float,
    local_path: str | Path | None,
) -> CachedDataset:
    if local_path is None:
        return load_cached_dataset(spec, cache_dir, refresh=refresh, offline=offline, timeout_seconds=timeout_seconds)
    text = Path(local_path).read_text(encoding="utf-8")
    parse_result = spec.parser(text)
    if parse_result.valid_rows <= 0:
        raise DataFormatError(f"{spec.name} local dataset contained no valid rows: {local_path}")
    encoded = text.encode("utf-8")
    provenance = DatasetProvenance(
        source_name=spec.name,
        source_url=spec.url,
        downloaded_at=None,
        content_hash=hashlib.sha256(encoded).hexdigest(),
        file_path=str(local_path),
        byte_count=len(encoded),
        row_count=parse_result.valid_rows,
        parser_stats=parse_result.to_dict(),
        cache_hit=True,
    )
    return CachedDataset(text=text, parse_result=parse_result, provenance=provenance)


def _build_record_rows(
    benchmark: Sequence[BenchmarkCve],
    joined_records: Iterable[EvaluationRecord],
    kev_dataset: CachedDataset,
    epss_dataset: CachedDataset,
    missing_model_results: Sequence[str],
) -> list[dict[str, Any]]:
    joined_by_cve = {record.cve_id: record for record in joined_records}
    missing = set(missing_model_results)
    rows: list[dict[str, Any]] = []
    for entry in benchmark:
        record = joined_by_cve.get(entry.cve_id)
        kev = entry.cve_id in kev_dataset.parse_result.items
        epss = epss_dataset.parse_result.items.get(entry.cve_id)
        rows.append(
            {
                "cve_id": entry.cve_id,
                "bucket": entry.bucket,
                "rationale": entry.rationale,
                "has_model_result": entry.cve_id not in missing,
                "missing_model_result": entry.cve_id in missing,
                "model_risk_score": record.model_risk_score if record else None,
                "model_confidence": record.model_confidence if record else None,
                "cvss_score": record.cvss_score if record else None,
                "epss_score": epss.epss if epss else None,
                "epss_percentile": epss.percentile if epss else None,
                "is_kev": kev,
                "exploited_label": bool(record.exploited_label) if record else kev,
            }
        )
    return sorted(rows, key=lambda row: row["cve_id"])


def _coverage(record_rows: Sequence[Mapping[str, Any]], missing_model_results: Sequence[str]) -> dict[str, Any]:
    return {
        "benchmark_count": len(record_rows),
        "model_result_count": sum(1 for row in record_rows if row.get("has_model_result")),
        "missing_model_result_count": len(missing_model_results),
        "missing_model_results": list(missing_model_results),
        "kev_count": sum(1 for row in record_rows if row.get("is_kev")),
        "epss_available_count": sum(1 for row in record_rows if row.get("epss_score") is not None),
        "missing_epss_count": sum(1 for row in record_rows if row.get("epss_score") is None),
    }


def _write_records_csv(rows: Iterable[Mapping[str, Any]], path: Path) -> None:
    fields = [
        "cve_id",
        "bucket",
        "has_model_result",
        "missing_model_result",
        "model_risk_score",
        "model_confidence",
        "cvss_score",
        "epss_score",
        "epss_percentile",
        "is_kev",
        "exploited_label",
        "rationale",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _write_metrics_csv(baselines: Mapping[str, Any], path: Path) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["strategy", "metric", "value"])
        writer.writeheader()
        for strategy in sorted(baselines):
            metrics = baselines[strategy].get("metrics", {}) or {}
            for metric in sorted(metrics):
                writer.writerow({"strategy": strategy, "metric": metric, "value": metrics[metric]})


def _stable_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run curated real-CVE KEV/EPSS benchmark")
    parser.add_argument("--model-results", required=True, help="JSON export containing analyzed CVE model results")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for benchmark artifacts")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR), help="Directory for cached official datasets")
    parser.add_argument("--refresh", action="store_true", help="Download official KEV and EPSS data before running")
    parser.add_argument("--offline", action="store_true", help="Use cached/local data only")
    parser.add_argument("--timeout-seconds", type=float, default=30.0, help="Download timeout for official datasets")
    parser.add_argument("--generated-at", default=None, help="Optional fixed timestamp for deterministic output")
    parser.add_argument("--kev-file", default=None, help="Optional local official-format KEV JSON file")
    parser.add_argument("--epss-file", default=None, help="Optional local official-format EPSS CSV file")
    args = parser.parse_args()
    try:
        report = run_real_benchmark(
            model_results_path=args.model_results,
            output_dir=args.output_dir,
            cache_dir=args.cache_dir,
            refresh=args.refresh,
            offline=args.offline,
            timeout_seconds=args.timeout_seconds,
            generated_at=args.generated_at,
            kev_path=args.kev_file,
            epss_path=args.epss_file,
        )
    except RealDataError as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
    print(
        json.dumps(
            {
                "output_dir": args.output_dir,
                "benchmark_count": report["coverage"]["benchmark_count"],
                "model_result_count": report["coverage"]["model_result_count"],
                "missing_model_result_count": report["coverage"]["missing_model_result_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
