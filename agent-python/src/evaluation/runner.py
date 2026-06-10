from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from evaluation.ablation import AblationVariant, evaluate_ablations
from evaluation.baselines import (
    RankingStrategy,
    cvss_score,
    default_ranking_strategies,
    model_risk_score,
)
from evaluation.datasets import (
    EvaluationRecord,
    dataset_metadata,
    join_external_signals,
    records_from_model_results,
)
from evaluation.epss import load_epss_entries
from evaluation.kev import load_kev_entries
from evaluation.metrics import evaluate_ranking, spearman_rank_correlation


ModelResultsLoader = Callable[[], Iterable[Mapping[str, Any]]]


def load_model_results_json(path: str | Path) -> list[Mapping[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return payload
    if isinstance(payload, Mapping):
        rows = payload.get("records") or payload.get("rows") or payload.get("items")
        if isinstance(rows, list):
            return rows
    raise ValueError("Model results JSON must contain a list or a records/rows/items list")


def build_evaluation_report(
    *,
    model_results: Optional[Iterable[Mapping[str, Any]]] = None,
    model_loader: Optional[ModelResultsLoader] = None,
    kev_path: Optional[str | Path] = None,
    kev_loader: Optional[Callable[[], Any]] = None,
    epss_path: Optional[str | Path] = None,
    epss_loader: Optional[Callable[[], str]] = None,
    k_values: Iterable[int] = (10,),
    strategies: Optional[Iterable[RankingStrategy]] = None,
    ablations: Optional[Iterable[AblationVariant]] = None,
    generated_at: Optional[str] = None,
) -> dict:
    raw_rows = list(model_loader() if model_loader is not None else (model_results or []))
    model_records, model_stats = records_from_model_results(raw_rows)
    kev_result = load_kev_entries(path=kev_path, loader=kev_loader) if (kev_path is not None or kev_loader is not None) else None
    epss_result = load_epss_entries(path=epss_path, loader=epss_loader) if (epss_path is not None or epss_loader is not None) else None

    kev_entries = kev_result.items if kev_result else {}
    epss_entries = epss_result.items if epss_result else {}
    records = join_external_signals(model_records, kev_entries, epss_entries)
    k_list = [int(k) for k in k_values]
    baseline_results = evaluate_baselines(records, k_values=k_list, strategies=strategies)
    report = {
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "dataset": dataset_metadata(
            records,
            model_stats=model_stats,
            kev_stats=kev_result.to_dict() if kev_result else {},
            epss_stats=epss_result.to_dict() if epss_result else {},
        ),
        "metric_config": {"k_values": k_list, "label": "kev_or_exploitation_evidence"},
        "baselines": baseline_results,
        "records": [record.to_dict() for record in records],
    }
    if ablations is not None:
        report["ablations"] = evaluate_ablations(records, ablations, k_values=k_list)
    return report


def evaluate_baselines(
    records: Iterable[EvaluationRecord],
    *,
    k_values: Iterable[int],
    strategies: Optional[Iterable[RankingStrategy]] = None,
) -> dict:
    rows = list(records)
    configured = list(strategies or default_ranking_strategies())
    results = {}
    for strategy in configured:
        ranked = strategy.rank(rows)
        results[strategy.name] = {
            "ranking": [record.cve_id for record in ranked],
            "metrics": evaluate_ranking(ranked, rows, k_values=k_values),
            "spearman_vs_model_risk": spearman_rank_correlation(rows, strategy.score, model_risk_score),
            "spearman_vs_cvss": spearman_rank_correlation(rows, strategy.score, cvss_score),
        }
    return results


def write_report_json(report: Mapping[str, Any], path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
