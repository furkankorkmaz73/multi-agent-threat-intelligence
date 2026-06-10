from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Callable, Iterable, Mapping, Sequence

from evaluation.baselines import RankingStrategy, default_ranking_strategies, model_risk_score, rank_records
from evaluation.datasets import EvaluationRecord, join_external_signals, normalize_cve_id, records_from_model_results, safe_float
from evaluation.epss import load_epss_entries
from evaluation.kev import load_kev_entries
from evaluation.metrics import evaluate_ranking, spearman_rank_correlation
from evaluation.nvd_cves import parse_nvd_cve_records
from evaluation.real_benchmark import BenchmarkCve, write_benchmark_artifacts
from evaluation.runner import load_model_results_json, write_report_json


BALANCED_BENCHMARK_VERSION = "balanced-real-cve-benchmark-v1"
DEFAULT_OUTPUT_DIR = Path("reports/real_benchmark/balanced")
DEFAULT_K_VALUES = (5, 10, 20, 50)


@dataclass(frozen=True)
class BalancedBenchmarkConfig:
    kev_positive_quota: int = 25
    high_epss_non_kev_quota: int = 10
    high_cvss_low_epss_non_kev_quota: int = 10
    medium_severity_control_quota: int = 10
    older_control_quota: int = 5
    high_epss_threshold: float = 0.75
    low_epss_threshold: float = 0.20
    high_cvss_threshold: float = 9.0
    medium_cvss_min: float = 4.0
    medium_cvss_max: float = 7.0
    older_year_cutoff: int = 2018
    minimum_correlation_subset: int = 5

    def quotas(self) -> dict[str, int]:
        return {
            "kev_positive": self.kev_positive_quota,
            "high_epss_non_kev": self.high_epss_non_kev_quota,
            "high_cvss_low_epss_non_kev": self.high_cvss_low_epss_non_kev_quota,
            "medium_severity_control": self.medium_severity_control_quota,
            "older_control": self.older_control_quota,
        }


@dataclass(frozen=True)
class Candidate:
    cve_id: str
    cvss_score: float
    epss_score: float | None
    epss_percentile: float | None
    is_kev: bool
    published: str | None

    def to_definition_row(self, bucket: str, rationale: str) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "bucket": bucket,
            "rationale": rationale,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "is_kev": self.is_kev,
            "published": self.published,
        }


def build_balanced_benchmark_definition(
    *,
    nvd_path: str | Path,
    kev_path: str | Path,
    epss_path: str | Path,
    output_path: str | Path | None = None,
    generated_at: str | None = None,
    config: BalancedBenchmarkConfig | None = None,
) -> dict[str, Any]:
    cfg = config or BalancedBenchmarkConfig()
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    nvd_records, nvd_stats, malformed = parse_nvd_cve_records(Path(nvd_path).read_text(encoding="utf-8"))
    kev = load_kev_entries(path=kev_path)
    epss = load_epss_entries(path=epss_path)
    candidates = _candidate_rows(nvd_records, kev.items, epss.items)
    selected, warnings = _select_balanced(candidates, cfg)
    definition = {
        "version": BALANCED_BENCHMARK_VERSION,
        "generated_at": generated,
        "selection_policy": {
            "quotas": cfg.quotas(),
            "high_epss_threshold": cfg.high_epss_threshold,
            "low_epss_threshold": cfg.low_epss_threshold,
            "high_cvss_threshold": cfg.high_cvss_threshold,
            "medium_cvss_range": [cfg.medium_cvss_min, cfg.medium_cvss_max],
            "older_year_cutoff": cfg.older_year_cutoff,
            "tie_breaking": "bucket-specific score tuple followed by ascending CVE ID",
        },
        "source_stats": {
            "nvd_parse": nvd_stats,
            "nvd_malformed_records": malformed,
            "kev_parse": kev.to_dict(),
            "epss_parse": epss.to_dict(),
        },
        "record_count": len(selected),
        "bucket_counts": _count_by(selected, "bucket"),
        "kev_count": sum(1 for row in selected if row["is_kev"]),
        "non_kev_count": sum(1 for row in selected if not row["is_kev"]),
        "warnings": warnings,
        "records": selected,
    }
    if output_path is not None:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        write_report_json(definition, output_path)
    return _stable_json(definition)


def run_balanced_benchmark(
    *,
    benchmark_definition_path: str | Path,
    model_results_path: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    generated_at: str | None = None,
    k_values: Iterable[int] = DEFAULT_K_VALUES,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    definition = json.loads(Path(benchmark_definition_path).read_text(encoding="utf-8"))
    benchmark = [BenchmarkCve(row["cve_id"], row["bucket"], row.get("rationale", "")) for row in definition.get("records", [])]
    model_rows = load_model_results_json(model_results_path)
    model_records, model_stats = records_from_model_results(model_rows)
    model_by_cve = {record.cve_id: record for record in model_records}
    definition_rows = {row["cve_id"]: row for row in definition.get("records", [])}
    selected_model_records = [model_by_cve[cve.cve_id] for cve in benchmark if cve.cve_id in model_by_cve]
    joined = _join_definition_signals(selected_model_records, definition_rows)
    missing_model_results = sorted({cve.cve_id for cve in benchmark} - set(model_by_cve))
    k_list = [int(k) for k in k_values]
    baselines = _evaluate_strategies(joined, default_ranking_strategies(), k_values=k_list)
    ablations = build_ablation_report(joined, k_values=k_list)
    record_rows = _record_rows(benchmark, joined, definition_rows, missing_model_results)
    diagnostics = build_diagnostics(record_rows, joined)
    case_candidates = build_case_candidates(record_rows)
    report = {
        "generated_at": generated,
        "benchmark": {
            "version": definition.get("version"),
            "record_count": len(benchmark),
            "bucket_counts": _count_by([cve.to_dict() for cve in benchmark], "bucket"),
        },
        "model_results": {
            "path": str(model_results_path),
            "parse": model_stats,
            "matched_count": len(joined),
            "missing_model_results": missing_model_results,
        },
        "metric_config": {"k_values": k_list, "label": "kev_or_exploitation_evidence"},
        "baselines": baselines,
        "ablations": ablations,
        "diagnostics": diagnostics,
        "case_candidates": case_candidates,
        "records": record_rows,
    }
    write_balanced_artifacts(report, definition, output_dir)
    return _stable_json(report)


def build_ablation_report(records: Sequence[EvaluationRecord], *, k_values: Sequence[int]) -> dict[str, Any]:
    variants = ablation_variants()
    supported = {}
    unsupported = {}
    for name, metadata in variants.items():
        if metadata["status"] != "exact":
            unsupported[name] = {"status": metadata["status"], "reason": metadata["reason"]}
            continue
        missing = _missing_required_component_records(records, metadata.get("required", ()))
        if missing:
            unsupported[name] = {
                "status": "unsupported",
                "reason": f"Missing required exported component fields for {len(missing)} record(s): {', '.join(metadata.get('required', ())) }",
                "missing_cve_ids": missing,
            }
            continue
        score_fn = metadata["score_fn"]
        ranked = rank_records(records, score_fn)
        supported[name] = {
            "status": "exact",
            "ranking": [record.cve_id for record in ranked],
            "metrics": evaluate_ranking(ranked, records, k_values=k_values),
            "spearman_vs_full_model": spearman_rank_correlation(records, score_fn, model_risk_score),
        }
    return {"supported": supported, "unsupported": unsupported}


def ablation_variants() -> dict[str, dict[str, Any]]:
    return {
        "full_model": {"status": "exact", "reason": "", "required": (), "score_fn": lambda record: record.model_risk_score},
        "without_temporal": {
            "status": "exact",
            "reason": "Uses exported raw_score_before_clamp, recentness_bonus, and age_penalty components.",
            "required": ("raw_score_before_clamp", "recentness_bonus", "age_penalty"),
            "score_fn": lambda record: _without_temporal(record),
        },
        "without_correlation": {
            "status": "exact",
            "reason": "Removes exported URLhaus and Dread correlation bonus components.",
            "required": ("raw_score_before_clamp", "urlhaus_correlation_bonus", "dread_correlation_bonus"),
            "score_fn": lambda record: _without_correlation(record),
        },
        "without_graph": {
            "status": "exact",
            "reason": "Removes exported graph_bonus from raw_score_before_clamp.",
            "required": ("raw_score_before_clamp", "graph_bonus"),
            "score_fn": lambda record: _without_graph(record),
        },
        "confidence_weighted_full_model": {
            "status": "exact",
            "reason": "Uses exported model risk score multiplied by exported confidence.",
            "required": (),
            "score_fn": lambda record: round(record.model_risk_score * record.model_confidence, 6),
        },
        "without_external_evidence": {
            "status": "unsupported",
            "reason": "External evidence changes accepted matches, temporal penalty caps, graph context, and confidence; exact removal requires recomputation.",
        },
    }


def _missing_required_component_records(records: Sequence[EvaluationRecord], required: Sequence[str]) -> list[str]:
    if not required:
        return []
    missing = []
    for record in records:
        breakdown = dict(record.feature_breakdown or {})
        if any(field not in breakdown for field in required):
            missing.append(record.cve_id)
    return missing


def write_balanced_artifacts(report: Mapping[str, Any], definition: Mapping[str, Any], output_dir: str | Path) -> dict[str, str]:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    files = {
        "balanced_benchmark_definition": path / "balanced_benchmark_definition.json",
        "benchmark_summary": path / "benchmark_summary.json",
        "benchmark_records": path / "benchmark_records.csv",
        "baseline_metrics": path / "baseline_metrics.csv",
        "ablation_metrics": path / "ablation_metrics.csv",
        "ablation_records": path / "ablation_records.csv",
        "benchmark_diagnostics": path / "benchmark_diagnostics.json",
        "case_candidates": path / "case_candidates.json",
    }
    write_report_json(definition, files["balanced_benchmark_definition"])
    write_report_json(report, files["benchmark_summary"])
    _write_records_csv(report.get("records", []), files["benchmark_records"])
    _write_metric_csv(report.get("baselines", {}), files["baseline_metrics"])
    _write_ablation_metric_csv(report.get("ablations", {}), files["ablation_metrics"])
    _write_ablation_records_csv(report.get("records", []), report.get("ablations", {}), files["ablation_records"])
    write_report_json(report.get("diagnostics", {}), files["benchmark_diagnostics"])
    write_report_json(report.get("case_candidates", {}), files["case_candidates"])
    return {name: str(file_path) for name, file_path in files.items()}


def build_diagnostics(record_rows: Sequence[Mapping[str, Any]], model_records: Sequence[EvaluationRecord]) -> dict[str, Any]:
    kev_count = sum(1 for row in record_rows if row.get("is_kev"))
    total = len(record_rows)
    warnings = []
    ratio = kev_count / total if total else 0.0
    if total < 50:
        warnings.append("benchmark_size_below_requested_minimum")
    if ratio < 0.25 or ratio > 0.75:
        warnings.append("kev_class_imbalance_may_make_metrics_misleading")
    missing_model = sum(1 for row in record_rows if row.get("missing_model_result"))
    if missing_model:
        warnings.append("missing_model_results_reduce_model_metric_coverage")
    correlation_subset = [row for row in record_rows if _has_correlation_evidence(row)]
    if len(correlation_subset) < 5:
        warnings.append("correlation_aware_subset_too_small_for_reliable_ablation_validation")
    return {
        "record_count": total,
        "kev_count": kev_count,
        "non_kev_count": total - kev_count,
        "bucket_counts": _count_by(record_rows, "bucket"),
        "epss_distribution": _distribution(row.get("epss_score") for row in record_rows),
        "cvss_distribution": _distribution(row.get("cvss_score") for row in record_rows),
        "model_score_distribution": _distribution(record.model_risk_score for record in model_records),
        "missing_data": {
            "missing_model_results": missing_model,
            "missing_epss": sum(1 for row in record_rows if row.get("epss_score") is None),
            "missing_cvss": sum(1 for row in record_rows if row.get("cvss_score") in {None, 0}),
        },
        "correlation_subset": {
            "count": len(correlation_subset),
            "status": "validated" if len(correlation_subset) >= 5 else "insufficient_real_evidence",
            "cve_ids": [row["cve_id"] for row in correlation_subset],
        },
        "warnings": warnings,
    }


def build_case_candidates(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    available = [row for row in rows if row.get("has_model_result")]
    return {
        "strongest_model_vs_cvss_disagreement": _max_by(available, lambda row: abs(_score01(row.get("model_risk_score")) - _score01(row.get("cvss_score")))),
        "strongest_model_vs_epss_disagreement": _max_by(available, lambda row: abs(_score01(row.get("model_risk_score")) - safe_float(row.get("epss_score")))),
        "old_but_actively_exploited_case": _min_by([row for row in available if row.get("is_kev")], lambda row: str(row.get("published") or "9999")),
        "high_cvss_low_exploitation_signal_case": _max_by(
            [row for row in available if not row.get("is_kev") and safe_float(row.get("cvss_score")) >= 9.0 and safe_float(row.get("epss_score")) <= 0.2],
            lambda row: safe_float(row.get("cvss_score")),
        ),
        "high_epss_low_model_score_case": _max_by(
            [row for row in available if safe_float(row.get("epss_score")) >= 0.75],
            lambda row: safe_float(row.get("epss_score")) - _score01(row.get("model_risk_score")),
        ),
        "representative_kev_case": _representative([row for row in available if row.get("is_kev")]),
        "representative_non_kev_case": _representative([row for row in available if not row.get("is_kev")]),
    }


def _candidate_rows(nvd_records: Mapping[str, Mapping[str, Any]], kev_entries: Mapping[str, Any], epss_entries: Mapping[str, Any]) -> list[Candidate]:
    rows = []
    for cve_id, record in nvd_records.items():
        cvss = _extract_cvss(record)
        epss = epss_entries.get(cve_id)
        rows.append(
            Candidate(
                cve_id=cve_id,
                cvss_score=cvss,
                epss_score=epss.epss if epss else None,
                epss_percentile=epss.percentile if epss else None,
                is_kev=cve_id in kev_entries,
                published=record.get("published"),
            )
        )
    return rows


def _select_balanced(candidates: Sequence[Candidate], config: BalancedBenchmarkConfig) -> tuple[list[dict[str, Any]], list[str]]:
    selected: list[dict[str, Any]] = []
    selected_ids: set[str] = set()
    warnings = []

    def take(bucket: str, quota: int, rows: Sequence[Candidate], sort_key: Callable[[Candidate], tuple], rationale: str) -> None:
        nonlocal selected
        available = [row for row in rows if row.cve_id not in selected_ids]
        ranked = sorted(available, key=sort_key)
        if len(ranked) < quota:
            warnings.append(f"quota_underfilled:{bucket}:{len(ranked)}/{quota}")
        for candidate in ranked[:quota]:
            selected_ids.add(candidate.cve_id)
            selected.append(candidate.to_definition_row(bucket, rationale))

    take(
        "kev_positive",
        config.kev_positive_quota,
        [row for row in candidates if row.is_kev],
        lambda row: (-(row.epss_score or 0.0), -row.cvss_score, row.cve_id),
        "Selected from CISA KEV positives, ranked by EPSS then CVSS.",
    )
    take(
        "high_epss_non_kev",
        config.high_epss_non_kev_quota,
        [row for row in candidates if not row.is_kev and (row.epss_score or 0.0) >= config.high_epss_threshold],
        lambda row: (-(row.epss_score or 0.0), -row.cvss_score, row.cve_id),
        "Selected from non-KEV CVEs with high EPSS.",
    )
    take(
        "high_cvss_low_epss_non_kev",
        config.high_cvss_low_epss_non_kev_quota,
        [
            row
            for row in candidates
            if not row.is_kev and row.cvss_score >= config.high_cvss_threshold and (row.epss_score or 0.0) <= config.low_epss_threshold
        ],
        lambda row: (-row.cvss_score, row.epss_score or 0.0, row.cve_id),
        "Selected from non-KEV high-CVSS CVEs with lower EPSS.",
    )
    take(
        "medium_severity_control",
        config.medium_severity_control_quota,
        [row for row in candidates if not row.is_kev and config.medium_cvss_min <= row.cvss_score < config.medium_cvss_max],
        lambda row: (abs(row.cvss_score - 5.5), row.epss_score or 0.0, row.cve_id),
        "Selected as medium-severity non-KEV controls.",
    )
    take(
        "older_control",
        config.older_control_quota,
        [row for row in candidates if not row.is_kev and _published_year(row.published) < config.older_year_cutoff],
        lambda row: (str(row.published or ""), -(row.epss_score or 0.0), row.cve_id),
        "Selected as older non-KEV controls.",
    )
    return sorted(selected, key=lambda row: row["cve_id"]), warnings


def _join_definition_signals(records: Sequence[EvaluationRecord], definition_rows: Mapping[str, Mapping[str, Any]]) -> list[EvaluationRecord]:
    joined = []
    for record in records:
        row = definition_rows.get(record.cve_id, {})
        joined.append(
            EvaluationRecord(
                cve_id=record.cve_id,
                model_risk_score=record.model_risk_score,
                model_confidence=record.model_confidence,
                cvss_score=safe_float(row.get("cvss_score"), record.cvss_score),
                epss_score=row.get("epss_score"),
                epss_percentile=row.get("epss_percentile"),
                is_kev=bool(row.get("is_kev")),
                exploitation_evidence=record.exploitation_evidence,
                feature_breakdown=record.feature_breakdown,
            )
        )
    return joined


def _evaluate_strategies(records: Sequence[EvaluationRecord], strategies: Sequence[RankingStrategy], *, k_values: Sequence[int]) -> dict[str, Any]:
    result = {}
    for strategy in strategies:
        ranked = strategy.rank(records)
        result[strategy.name] = {
            "ranking": [record.cve_id for record in ranked],
            "metrics": evaluate_ranking(ranked, records, k_values=k_values),
            "spearman_vs_model_risk": spearman_rank_correlation(records, strategy.score, model_risk_score),
        }
    return result


def _record_rows(
    benchmark: Sequence[BenchmarkCve],
    joined: Sequence[EvaluationRecord],
    definition_rows: Mapping[str, Mapping[str, Any]],
    missing_model_results: Sequence[str],
) -> list[dict[str, Any]]:
    joined_by_cve = {record.cve_id: record for record in joined}
    missing = set(missing_model_results)
    rows = []
    for entry in benchmark:
        definition = dict(definition_rows.get(entry.cve_id, {}))
        record = joined_by_cve.get(entry.cve_id)
        feature_breakdown = dict(record.feature_breakdown) if record else {}
        evidence = dict(feature_breakdown.get("evidence", {}) or {})
        rows.append(
            {
                **definition,
                "has_model_result": entry.cve_id not in missing,
                "missing_model_result": entry.cve_id in missing,
                "model_risk_score": record.model_risk_score if record else None,
                "model_confidence": record.model_confidence if record else None,
                "feature_breakdown": feature_breakdown,
                "related_urlhaus_count": evidence.get("related_urlhaus_count"),
                "related_dread_count": evidence.get("related_dread_count"),
            }
        )
    return sorted(rows, key=lambda row: row["cve_id"])


def _without_temporal(record: EvaluationRecord) -> float:
    breakdown = record.feature_breakdown
    return _bound_score(safe_float(breakdown.get("raw_score_before_clamp"), record.model_risk_score) - safe_float(breakdown.get("recentness_bonus")) + safe_float(breakdown.get("age_penalty")))


def _without_correlation(record: EvaluationRecord) -> float:
    breakdown = record.feature_breakdown
    return _bound_score(
        safe_float(breakdown.get("raw_score_before_clamp"), record.model_risk_score)
        - safe_float(breakdown.get("urlhaus_correlation_bonus"))
        - safe_float(breakdown.get("dread_correlation_bonus"))
    )


def _without_graph(record: EvaluationRecord) -> float:
    breakdown = record.feature_breakdown
    return _bound_score(safe_float(breakdown.get("raw_score_before_clamp"), record.model_risk_score) - safe_float(breakdown.get("graph_bonus")))


def _extract_cvss(record: Mapping[str, Any]) -> float:
    metrics = record.get("metrics", {}) or {}
    for key in ("cvss_metric_v40", "cvss_metric_v31", "cvss_metric_v30", "cvss_metric_v2"):
        values = metrics.get(key) or []
        if values:
            return safe_float((values[0].get("cvss_data") or {}).get("base_score"))
    return 0.0


def _published_year(value: Any) -> int:
    try:
        return int(str(value)[:4])
    except (TypeError, ValueError):
        return 9999


def _bound_score(value: Any) -> float:
    return max(0.0, min(round(safe_float(value), 6), 10.0))


def _distribution(values: Iterable[Any]) -> dict[str, Any]:
    rows = sorted(safe_float(value) for value in values if value is not None)
    if not rows:
        return {"count": 0}
    return {
        "count": len(rows),
        "min": rows[0],
        "p25": rows[int((len(rows) - 1) * 0.25)],
        "median": rows[int((len(rows) - 1) * 0.50)],
        "p75": rows[int((len(rows) - 1) * 0.75)],
        "max": rows[-1],
        "mean": round(mean(rows), 6),
    }


def _count_by(rows: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _has_correlation_evidence(row: Mapping[str, Any]) -> bool:
    breakdown = dict(row.get("feature_breakdown") or {})
    return bool(safe_float(breakdown.get("urlhaus_correlation_bonus")) > 0 or safe_float(breakdown.get("dread_correlation_bonus")) > 0)


def _write_records_csv(rows: Iterable[Mapping[str, Any]], path: Path) -> None:
    fields = [
        "cve_id",
        "bucket",
        "is_kev",
        "cvss_score",
        "epss_score",
        "epss_percentile",
        "model_risk_score",
        "model_confidence",
        "has_model_result",
        "missing_model_result",
        "published",
        "rationale",
    ]
    _write_csv(rows, path, fields)


def _write_metric_csv(baselines: Mapping[str, Any], path: Path) -> None:
    rows = []
    for strategy in sorted(baselines):
        metrics = baselines[strategy].get("metrics", {}) or {}
        rows.extend({"strategy": strategy, "metric": metric, "value": metrics[metric]} for metric in sorted(metrics))
    _write_csv(rows, path, ["strategy", "metric", "value"])


def _write_ablation_metric_csv(ablations: Mapping[str, Any], path: Path) -> None:
    rows = []
    for name, payload in sorted((ablations.get("supported") or {}).items()):
        for metric, value in sorted((payload.get("metrics") or {}).items()):
            rows.append({"variant": name, "status": payload.get("status"), "metric": metric, "value": value, "reason": ""})
    for name, payload in sorted((ablations.get("unsupported") or {}).items()):
        rows.append({"variant": name, "status": payload.get("status"), "metric": "", "value": "", "reason": payload.get("reason")})
    _write_csv(rows, path, ["variant", "status", "metric", "value", "reason"])


def _write_ablation_records_csv(rows: Sequence[Mapping[str, Any]], ablations: Mapping[str, Any], path: Path) -> None:
    rankings = {name: {cve_id: index + 1 for index, cve_id in enumerate(payload.get("ranking", []))} for name, payload in (ablations.get("supported") or {}).items()}
    out = []
    for row in rows:
        out.append({"cve_id": row.get("cve_id"), **{f"{name}_rank": ranking.get(row.get("cve_id")) for name, ranking in rankings.items()}})
    _write_csv(out, path, sorted({key for item in out for key in item} or {"cve_id"}))


def _write_csv(rows: Iterable[Mapping[str, Any]], path: Path, fields: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _max_by(rows: Sequence[Mapping[str, Any]], key: Callable[[Mapping[str, Any]], Any]) -> Mapping[str, Any] | None:
    return dict(max(rows, key=lambda row: (key(row), row.get("cve_id", "")))) if rows else None


def _min_by(rows: Sequence[Mapping[str, Any]], key: Callable[[Mapping[str, Any]], Any]) -> Mapping[str, Any] | None:
    return dict(min(rows, key=lambda row: (key(row), row.get("cve_id", "")))) if rows else None


def _representative(rows: Sequence[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    if not rows:
        return None
    ranked = sorted(rows, key=lambda row: (safe_float(row.get("model_risk_score")), row.get("cve_id", "")))
    return dict(ranked[len(ranked) // 2])


def _score01(value: Any) -> float:
    return safe_float(value) / 10.0


def _stable_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build/evaluate a balanced real-CVE benchmark")
    parser.add_argument("--nvd-file", required=True, help="Official-format NVD JSON file with candidate CVEs")
    parser.add_argument("--kev-file", required=True, help="Official-format CISA KEV JSON file")
    parser.add_argument("--epss-file", required=True, help="Official-format FIRST EPSS CSV file")
    parser.add_argument("--model-results", required=True, help="Model-result JSON export for selected CVEs")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory for balanced benchmark artifacts")
    parser.add_argument("--generated-at", default=None, help="Optional fixed timestamp for deterministic output")
    args = parser.parse_args()
    output_dir = Path(args.output_dir)
    definition_path = output_dir / "balanced_benchmark_definition.json"
    build_balanced_benchmark_definition(
        nvd_path=args.nvd_file,
        kev_path=args.kev_file,
        epss_path=args.epss_file,
        output_path=definition_path,
        generated_at=args.generated_at,
    )
    report = run_balanced_benchmark(
        benchmark_definition_path=definition_path,
        model_results_path=args.model_results,
        output_dir=output_dir,
        generated_at=args.generated_at,
    )
    print(json.dumps({"output_dir": str(output_dir), "record_count": report["benchmark"]["record_count"], "matched_count": report["model_results"]["matched_count"]}, sort_keys=True))


if __name__ == "__main__":
    main()
