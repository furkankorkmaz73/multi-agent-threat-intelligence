from __future__ import annotations

import argparse
import csv
import json
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping, Sequence

from agents import llm_helper
from agents.diagnostic import DiagnosticAgent
import analysis.risk_engine as risk_engine_module
from analysis.features.cve_temporal import calculate_age_days as calculate_cve_age_days
from config import APP_VERSION
from evaluation.evidence_inputs import build_file_evidence_provider
from evaluation.nvd_cves import curated_cve_ids, load_nvd_cves
from evaluation.real_benchmark import run_real_benchmark
from evaluation.real_data import RealDataError
from evaluation.runner import write_report_json


DEFAULT_OUTPUT_DIR = Path("reports/real_benchmark/model_export")
DEFAULT_CACHE_DIR = Path(".cache/real_benchmark")


@dataclass(frozen=True)
class ExportPaths:
    model_results_json: Path
    model_results_csv: Path
    analysis_failures_json: Path
    run_metadata_json: Path

    @classmethod
    def in_dir(cls, output_dir: str | Path) -> "ExportPaths":
        path = Path(output_dir)
        return cls(
            model_results_json=path / "model_results.json",
            model_results_csv=path / "model_results.csv",
            analysis_failures_json=path / "analysis_failures.json",
            run_metadata_json=path / "run_metadata.json",
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "model_results_json": str(self.model_results_json),
            "model_results_csv": str(self.model_results_csv),
            "analysis_failures_json": str(self.analysis_failures_json),
            "run_metadata_json": str(self.run_metadata_json),
        }


def run_model_export(
    *,
    cve_source_path: str | Path | None = None,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    cache_dir: str | Path = DEFAULT_CACHE_DIR,
    refresh: bool = False,
    offline: bool = False,
    timeout_seconds: float = 30.0,
    generated_at: str | None = None,
    reference_time: str | None = None,
    cve_ids: Sequence[str] | None = None,
    benchmark_definition_path: str | Path | None = None,
    run_benchmark: bool = False,
    benchmark_output_dir: str | Path | None = None,
    benchmark_cache_dir: str | Path | None = None,
    kev_path: str | Path | None = None,
    epss_path: str | Path | None = None,
    urlhaus_evidence_path: str | Path | None = None,
    dread_evidence_path: str | Path | None = None,
    refresh_urlhaus_evidence: bool = False,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    reference = _parse_reference_time(reference_time or generated)
    requested = list(cve_ids or _cve_ids_from_definition(benchmark_definition_path) or curated_cve_ids())
    cve_load = load_nvd_cves(
        cve_ids=requested,
        cache_dir=cache_dir,
        local_path=cve_source_path,
        refresh=refresh,
        offline=offline,
        timeout_seconds=timeout_seconds,
    )
    diagnostic = DiagnosticAgent()
    evidence_provider = None
    evidence_inputs: dict[str, Any] = {}
    if urlhaus_evidence_path is not None or dread_evidence_path is not None or refresh_urlhaus_evidence:
        evidence_provider, evidence_inputs = build_file_evidence_provider(
            urlhaus_path=urlhaus_evidence_path,
            dread_path=dread_evidence_path,
            cache_dir=cache_dir,
            refresh_urlhaus=refresh_urlhaus_evidence,
            offline=offline,
            timeout_seconds=timeout_seconds,
        )
    records: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = [
        {"cve_id": cve_id, "status": "missing_cve_metadata", "reason": "not_found_in_nvd_source"}
        for cve_id in cve_load.provenance.missing_cves
    ]
    for malformed in cve_load.malformed_records:
        failures.append({"cve_id": None, "status": "malformed_nvd_record", **dict(malformed)})

    with _deterministic_analysis_context(reference):
        for cve_id in cve_load.provenance.loaded_cves:
            doc = dict(cve_load.records[cve_id])
            try:
                analysis = diagnostic.analyze("cve", doc, db=evidence_provider)
                if analysis is None:
                    raise RuntimeError("analysis returned no result")
                records.append(_model_record(doc, analysis, generated_at=generated))
            except Exception as exc:
                failures.append({"cve_id": cve_id, "status": "analysis_failed", "reason": f"{type(exc).__name__}: {exc}"})

    paths = ExportPaths.in_dir(output_dir)
    _write_export_artifacts(paths, records, failures, cve_load.provenance.to_dict(), evidence_inputs=evidence_inputs, generated_at=generated)
    report = {
        "generated_at": generated,
        "analysis_version": APP_VERSION,
        "paths": paths.to_dict(),
        "coverage": {
            "requested_count": len(requested),
            "loaded_cve_count": len(cve_load.provenance.loaded_cves),
            "model_result_count": len(records),
            "failure_count": len(failures),
            "missing_cves": list(cve_load.provenance.missing_cves),
        },
        "nvd_provenance": cve_load.provenance.to_dict(),
        "evidence_inputs": evidence_inputs,
        "records": records,
        "failures": failures,
    }
    if run_benchmark:
        benchmark_dir = benchmark_output_dir or Path(output_dir) / "benchmark"
        benchmark_report = run_real_benchmark(
            model_results_path=paths.model_results_json,
            output_dir=benchmark_dir,
            cache_dir=benchmark_cache_dir or cache_dir,
            offline=offline,
            refresh=refresh,
            timeout_seconds=timeout_seconds,
            generated_at=generated,
            kev_path=kev_path,
            epss_path=epss_path,
        )
        report["benchmark"] = {
            "output_dir": str(benchmark_dir),
            "coverage": benchmark_report["coverage"],
            "artifact_paths": {
                "benchmark_summary": str(Path(benchmark_dir) / "benchmark_summary.json"),
                "benchmark_records": str(Path(benchmark_dir) / "benchmark_records.csv"),
                "baseline_metrics": str(Path(benchmark_dir) / "baseline_metrics.csv"),
            },
        }
    return _stable_json(report)


def _model_record(doc: Mapping[str, Any], analysis: Mapping[str, Any], *, generated_at: str) -> dict[str, Any]:
    evidence = dict(analysis.get("evidence") or {})
    orchestration_trace = list(analysis.get("orchestration_trace", []) or [])
    execution_plan = list(analysis.get("execution_plan", []) or [])
    return {
        "cve_id": str(analysis.get("entity_id") or doc.get("_id")),
        "entity_id": str(analysis.get("entity_id") or doc.get("_id")),
        "risk_score": analysis.get("risk_score"),
        "confidence": analysis.get("confidence"),
        "risk_level": analysis.get("risk_level"),
        "cvss_score": evidence.get("cvss_score", 0.0),
        "evidence": evidence,
        "confidence_breakdown": dict(analysis.get("confidence_breakdown") or {}),
        "evidence_summary": {
            "related_urlhaus_count": evidence.get("related_urlhaus_count", 0),
            "related_dread_count": evidence.get("related_dread_count", 0),
            "candidate_urlhaus_count": evidence.get("candidate_urlhaus_count", 0),
            "candidate_dread_count": evidence.get("candidate_dread_count", 0),
            "age_days": evidence.get("age_days"),
            "cvss_version": evidence.get("cvss_version"),
        },
        "feature_breakdown": dict(analysis.get("feature_breakdown") or {}),
        "graph_summary": dict(analysis.get("graph_summary") or {}),
        "orchestration_summary": {
            "trace_count": len(orchestration_trace),
            "plan_count": len(execution_plan),
            "critic_status": (analysis.get("critic_review") or {}).get("status"),
        },
        "analysis_version": APP_VERSION,
        "generated_at": generated_at,
    }


def _write_export_artifacts(
    paths: ExportPaths,
    records: Sequence[Mapping[str, Any]],
    failures: Sequence[Mapping[str, Any]],
    nvd_provenance: Mapping[str, Any],
    *,
    evidence_inputs: Mapping[str, Any] | None = None,
    generated_at: str,
) -> None:
    paths.model_results_json.parent.mkdir(parents=True, exist_ok=True)
    write_report_json(
        {
            "generated_at": generated_at,
            "analysis_version": APP_VERSION,
            "record_count": len(records),
            "records": list(records),
        },
        paths.model_results_json,
    )
    _write_model_csv(records, paths.model_results_csv)
    write_report_json({"generated_at": generated_at, "failure_count": len(failures), "failures": list(failures)}, paths.analysis_failures_json)
    write_report_json(
        {
            "generated_at": generated_at,
            "analysis_version": APP_VERSION,
            "nvd_provenance": dict(nvd_provenance),
            "evidence_inputs": dict(evidence_inputs or {}),
            "record_count": len(records),
            "failure_count": len(failures),
        },
        paths.run_metadata_json,
    )


def _write_model_csv(records: Sequence[Mapping[str, Any]], path: Path) -> None:
    fields = [
        "cve_id",
        "risk_score",
        "confidence",
        "risk_level",
        "cvss_score",
        "related_urlhaus_count",
        "related_dread_count",
        "age_days",
        "trace_count",
        "plan_count",
        "analysis_version",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for record in records:
            evidence_summary = dict(record.get("evidence_summary") or {})
            orchestration_summary = dict(record.get("orchestration_summary") or {})
            writer.writerow(
                {
                    "cve_id": record.get("cve_id"),
                    "risk_score": record.get("risk_score"),
                    "confidence": record.get("confidence"),
                    "risk_level": record.get("risk_level"),
                    "cvss_score": record.get("cvss_score"),
                    "related_urlhaus_count": evidence_summary.get("related_urlhaus_count"),
                    "related_dread_count": evidence_summary.get("related_dread_count"),
                    "age_days": evidence_summary.get("age_days"),
                    "trace_count": orchestration_summary.get("trace_count"),
                    "plan_count": orchestration_summary.get("plan_count"),
                    "analysis_version": record.get("analysis_version"),
                }
            )


@contextmanager
def _deterministic_analysis_context(reference_time: datetime) -> Iterator[None]:
    original_client = llm_helper.client
    original_age_calculator = risk_engine_module.calculate_age_days
    llm_helper.client = None
    risk_engine_module.calculate_age_days = lambda value: calculate_cve_age_days(value, reference_time=reference_time)
    try:
        yield
    finally:
        llm_helper.client = original_client
        risk_engine_module.calculate_age_days = original_age_calculator


def _parse_reference_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _stable_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def _cve_ids_from_definition(path: str | Path | None) -> list[str]:
    if path is None:
        return []
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return [str(row.get("cve_id")) for row in payload.get("records", []) if row.get("cve_id")]


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate model-result exports for the curated real-CVE benchmark")
    parser.add_argument("--cve-file", default=None, help="Local official-format NVD JSON file")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for model export artifacts")
    parser.add_argument("--cache-dir", default=str(DEFAULT_CACHE_DIR), help="Directory for cached NVD data")
    parser.add_argument("--refresh", action="store_true", help="Download official NVD CVE data before running")
    parser.add_argument("--offline", action="store_true", help="Use cached/local NVD data only")
    parser.add_argument("--timeout-seconds", type=float, default=30.0, help="Download timeout for official NVD requests")
    parser.add_argument("--generated-at", default=None, help="Optional fixed timestamp for deterministic output")
    parser.add_argument("--reference-time", default=None, help="Optional fixed temporal-scoring reference timestamp")
    parser.add_argument("--benchmark-definition", default=None, help="Optional balanced benchmark definition JSON to choose CVEs")
    parser.add_argument("--run-benchmark", action="store_true", help="Run the KEV/EPSS benchmark after exporting model results")
    parser.add_argument("--benchmark-output-dir", default=None, help="Directory for chained benchmark artifacts")
    parser.add_argument("--benchmark-cache-dir", default=None, help="Cache directory for KEV/EPSS benchmark data")
    parser.add_argument("--kev-file", default=None, help="Optional local official-format KEV JSON file for chained benchmark")
    parser.add_argument("--epss-file", default=None, help="Optional local official-format EPSS CSV file for chained benchmark")
    parser.add_argument("--urlhaus-evidence-file", default=None, help="Optional local official-format URLhaus JSON evidence file")
    parser.add_argument("--dread-evidence-file", default=None, help="Optional local Dread JSON/JSONL export")
    parser.add_argument("--refresh-urlhaus-evidence", action="store_true", help="Refresh official URLhaus evidence when no local file is provided")
    args = parser.parse_args()
    try:
        report = run_model_export(
            cve_source_path=args.cve_file,
            output_dir=args.output_dir,
            cache_dir=args.cache_dir,
            refresh=args.refresh,
            offline=args.offline,
            timeout_seconds=args.timeout_seconds,
            generated_at=args.generated_at,
            reference_time=args.reference_time,
            benchmark_definition_path=args.benchmark_definition,
            run_benchmark=args.run_benchmark,
            benchmark_output_dir=args.benchmark_output_dir,
            benchmark_cache_dir=args.benchmark_cache_dir,
            kev_path=args.kev_file,
            epss_path=args.epss_file,
            urlhaus_evidence_path=args.urlhaus_evidence_file,
            dread_evidence_path=args.dread_evidence_file,
            refresh_urlhaus_evidence=args.refresh_urlhaus_evidence,
        )
    except RealDataError as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "model_result_count": report["coverage"]["model_result_count"],
                "failure_count": report["coverage"]["failure_count"],
                "missing_cves": report["coverage"]["missing_cves"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
