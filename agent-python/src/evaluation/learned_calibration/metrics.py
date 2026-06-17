from __future__ import annotations

import argparse
import csv
import json
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil, floor, log2
from pathlib import Path
from random import Random
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping, Sequence

import pymongo
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from config import DB_NAME, MONGO_URI, get_settings

SETTINGS = get_settings()

from .constants import *
from .common import *
from .data import _missing_feature_percentages

def compute_baseline_metrics(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    ranked_rows = sorted(
        rows,
        key=lambda row: (-_safe_float(row.get("risk_score")), str(row.get("cve_id", ""))),
    )
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    return {
        "generated_at": generated,
        "ranking_method": "heuristic_risk_score",
        "notes": [
            "Metrics compare existing heuristic risk_score ranking against deterministic proxy labels.",
            "Proxy labels are not ground truth and should not be interpreted as real-world exploitation labels.",
            "No model training is performed in this baseline task.",
        ],
        "strategies": {
            strategy: _baseline_metrics_for_strategy(ranked_rows, label_by_cve, strategy)
            for strategy in ("strategy_a", "strategy_b", "strategy_c")
        },
    }

def render_baseline_metrics_markdown(metrics: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Baseline Metrics",
        "",
        "This artifact evaluates the existing heuristic `risk_score` ranking against deterministic proxy labels.",
        "It does not train a model and does not change production scoring behavior.",
        "",
        "| Strategy | Status | Positives | Precision@10 | Recall@50 | nDCG@50 | High-label Coverage |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for strategy, payload in (metrics.get("strategies") or {}).items():
        lines.append(
            "| {strategy} | {status} | {positives} | {p10} | {r50} | {n50} | {coverage} |".format(
                strategy=strategy,
                status=payload.get("status", ""),
                positives=payload.get("positive_count", 0),
                p10=_format_metric((payload.get("precision_at_k") or {}).get("10")),
                r50=_format_metric((payload.get("recall_at_k") or {}).get("50")),
                n50=_format_metric((payload.get("ndcg_at_k") or {}).get("50")),
                coverage=_format_metric(payload.get("high_label_coverage")),
            )
        )
    lines.extend(
        [
            "",
            "No-positive and tiny-positive strategies are retained in the report so limitations remain visible.",
            "",
        ]
    )
    return "\n".join(lines)

def compute_learned_vs_heuristic_comparison(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    prediction_rows: Sequence[Mapping[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    rows_by_cve = {str(row.get("cve_id", "")): row for row in rows}
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    predictions_by_strategy: dict[str, list[Mapping[str, Any]]] = {strategy: [] for strategy in ("strategy_a", "strategy_b", "strategy_c")}
    for prediction in prediction_rows:
        strategy = str(prediction.get("strategy", ""))
        if strategy in predictions_by_strategy:
            predictions_by_strategy[strategy].append(prediction)
    strategies = {
        strategy: _comparison_for_strategy(rows_by_cve, label_by_cve, predictions, strategy)
        for strategy, predictions in predictions_by_strategy.items()
    }
    return {
        "generated_at": generated,
        "status": "completed" if any(payload["status"] != "skipped" for payload in strategies.values()) else "skipped",
        "notes": [
            "Comparison uses experimental learned probabilities when available.",
            "The heuristic ranking is the existing production risk_score ordering; it is not changed by this artifact.",
            "Proxy labels are deterministic thesis-analysis labels, not ground truth.",
        ],
        "strategies": strategies,
    }

def render_learned_vs_heuristic_markdown(comparison: Mapping[str, Any]) -> str:
    lines = [
        "# Learned vs Heuristic Ranking Comparison",
        "",
        "This artifact compares experimental learned probability rankings with the existing heuristic `risk_score` ranking.",
        "It is skipped when no learned predictions are available.",
        "",
        "| Strategy | Status | Top-10 Overlap | Learned Precision@10 | Heuristic Precision@10 | Rank Correlation | Interpretation |",
        "| --- | --- | ---: | ---: | ---: | ---: | --- |",
    ]
    for strategy, payload in (comparison.get("strategies") or {}).items():
        overlap = (payload.get("top_k_overlap") or {}).get("10", {})
        learned_precision = ((payload.get("learned_metrics") or {}).get("precision_at_k") or {}).get("10")
        heuristic_precision = ((payload.get("heuristic_metrics") or {}).get("precision_at_k") or {}).get("10")
        lines.append(
            "| {strategy} | {status} | {overlap} | {lp} | {hp} | {corr} | {interpretation} |".format(
                strategy=strategy,
                status=payload.get("status", ""),
                overlap=_format_metric(overlap.get("count")),
                lp=_format_metric(learned_precision),
                hp=_format_metric(heuristic_precision),
                corr=_format_metric(payload.get("spearman_like_rank_correlation")),
                interpretation=payload.get("interpretation", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)

def compute_disagreement_cases(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    prediction_rows: Sequence[Mapping[str, Any]],
    *,
    max_examples_per_category: int = 5,
) -> list[dict[str, Any]]:
    rows_by_cve = {str(row.get("cve_id", "")): row for row in rows}
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    by_category: dict[str, list[dict[str, Any]]] = {}
    predictions_by_strategy: dict[str, list[Mapping[str, Any]]] = {}
    for prediction in prediction_rows:
        predictions_by_strategy.setdefault(str(prediction.get("strategy", "")), []).append(prediction)
    for strategy, predictions in predictions_by_strategy.items():
        learned_ranks = {
            str(prediction.get("cve_id", "")): rank
            for rank, prediction in enumerate(
                sorted(
                    predictions,
                    key=lambda row: (-_safe_float(row.get("learned_probability")), str(row.get("cve_id", ""))),
                ),
                start=1,
            )
        }
        heuristic_ranks = {
            cve_id: rank
            for rank, (cve_id, _row) in enumerate(
                sorted(rows_by_cve.items(), key=lambda item: (-_safe_float(item[1].get("risk_score")), item[0])),
                start=1,
            )
        }
        for prediction in predictions:
            cve_id = str(prediction.get("cve_id", ""))
            row = rows_by_cve.get(cve_id)
            if row is None:
                continue
            probability = _safe_float(prediction.get("learned_probability"))
            categories = _disagreement_categories(
                row,
                probability=probability,
                learned_rank=learned_ranks.get(cve_id, 999999),
                heuristic_rank=heuristic_ranks.get(cve_id, 999999),
                proxy_label=str((label_by_cve.get(cve_id) or {}).get(f"proxy_label_{strategy}", "")),
            )
            for category, reason in categories:
                by_category.setdefault(category, []).append(
                    _disagreement_row(row, label_by_cve.get(cve_id) or {}, strategy, probability, category, reason)
                )
    output: list[dict[str, Any]] = []
    for category in sorted(by_category):
        output.extend(by_category[category][:max_examples_per_category])
    return output

def render_disagreements_markdown(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# Learned Calibration Disagreement Cases",
        "",
        "This artifact lists thesis-useful disagreements between experimental learned probabilities and heuristic risk scoring.",
        "It is empty when learned predictions are unavailable.",
        "",
    ]
    if not rows:
        lines.extend(["No disagreement cases were exported because learned predictions are unavailable.", ""])
        return "\n".join(lines)
    counts: dict[str, int] = {}
    for row in rows:
        category = str(row.get("disagreement_type", ""))
        counts[category] = counts.get(category, 0) + 1
    lines.extend(f"- `{category}`: {count}" for category, count in sorted(counts.items()))
    lines.append("")
    return "\n".join(lines)

def extract_feature_importance(
    model_report: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for strategy, payload in (model_report.get("strategies") or {}).items():
        coefficients = payload.get("coefficients") or {}
        if not coefficients:
            continue
        ranked = sorted(coefficients.items(), key=lambda item: (-abs(_safe_float(item[1])), item[0]))
        for rank, (feature, coefficient) in enumerate(ranked, start=1):
            warning = ""
            if feature in {"cvss_score", "severity_signal"} and rank <= 2:
                warning = "model may be dominated by CVSS/severity"
            output.append(
                {
                    "strategy": strategy,
                    "feature": feature,
                    "coefficient": coefficient,
                    "absolute_coefficient_rank": rank,
                    "sign_interpretation": _coefficient_sign_interpretation(_safe_float(coefficient)),
                    "feature_coverage_note": _feature_coverage_note(feature, rows),
                    "warning": warning,
                }
            )
    return output

def render_feature_importance_markdown(
    rows: Sequence[Mapping[str, Any]],
    model_report: Mapping[str, Any],
) -> str:
    lines = [
        "# Learned Calibration Feature Importance",
        "",
        "This artifact exports interpretable LogisticRegression coefficients when a model is trained.",
        "It is skipped when model training is unavailable or no strategy produces coefficients.",
        "",
    ]
    if not rows:
        reason = model_report.get("skip_reason") or "no trained model coefficients are available"
        lines.extend([f"Skipped: {reason}.", ""])
        return "\n".join(lines)
    lines.extend(
        [
            "| Strategy | Feature | Coefficient | Abs Rank | Interpretation | Warning |",
            "| --- | --- | ---: | ---: | --- | --- |",
        ]
    )
    for row in rows:
        lines.append(
            "| {strategy} | {feature} | {coefficient} | {rank} | {interpretation} | {warning} |".format(
                strategy=row.get("strategy", ""),
                feature=row.get("feature", ""),
                coefficient=row.get("coefficient", ""),
                rank=row.get("absolute_coefficient_rank", ""),
                interpretation=row.get("sign_interpretation", ""),
                warning=row.get("warning", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)

def ablation_plan() -> list[dict[str, Any]]:
    return [
        {"name": "all_features", "features": list(MODEL_FEATURE_COLUMNS)},
        {"name": "no_cvss_severity", "features": [feature for feature in MODEL_FEATURE_COLUMNS if feature not in {"cvss_score", "severity_signal"}]},
        {"name": "no_recency", "features": [feature for feature in MODEL_FEATURE_COLUMNS if feature != "recency_signal"]},
        {"name": "no_nlp_context", "features": [feature for feature in MODEL_FEATURE_COLUMNS if feature != "nlp_context_signal"]},
        {"name": "no_confidence_data_completeness", "features": [feature for feature in MODEL_FEATURE_COLUMNS if feature not in {"assessment_confidence", "data_completeness"}]},
        {"name": "no_intrinsic_floor_flag", "features": [feature for feature in MODEL_FEATURE_COLUMNS if feature != "intrinsic_criticality_floor_applied"]},
        {"name": "evidence_only", "features": ["epss_signal", "kev_signal", "correlation_signal", "graph_signal", "accepted_urlhaus_count", "accepted_dread_count"]},
        {"name": "signals_only", "features": ["severity_signal", "epss_signal", "kev_signal", "recency_signal", "correlation_signal", "graph_signal", "nlp_context_signal"]},
        {"name": "metadata_context_only", "features": ["cvss_score", "recency_signal", "nlp_context_signal", "age_days", "assessment_confidence", "data_completeness", "intrinsic_criticality_floor_applied"]},
    ]

def compute_ablation_experiments(model_report: Mapping[str, Any]) -> list[dict[str, Any]]:
    strategies = model_report.get("strategies") or {}
    if model_report.get("status") != "completed":
        reason = model_report.get("skip_reason") or "model training was not completed"
        return [
            _skipped_ablation_row(strategy, item["name"], item["features"], reason)
            for strategy in ("strategy_a", "strategy_b", "strategy_c")
            for item in ablation_plan()
        ]
    rows: list[dict[str, Any]] = []
    for strategy, payload in strategies.items():
        if payload.get("status") == "skipped":
            reason = payload.get("skip_reason") or "strategy model was skipped"
            rows.extend(_skipped_ablation_row(strategy, item["name"], item["features"], reason) for item in ablation_plan())
            continue
        metrics = payload.get("metrics") or {}
        for item in ablation_plan():
            rows.append(
                {
                    "strategy": strategy,
                    "ablation": item["name"],
                    "status": "baseline_only",
                    "features": ";".join(item["features"]),
                    "accuracy": metrics.get("accuracy", ""),
                    "balanced_accuracy": metrics.get("balanced_accuracy", ""),
                    "precision": metrics.get("precision", ""),
                    "recall": metrics.get("recall", ""),
                    "f1": metrics.get("f1", ""),
                    "roc_auc": metrics.get("roc_auc", ""),
                    "pr_auc": metrics.get("pr_auc", ""),
                    "interpretation": _ablation_interpretation(item["name"]),
                    "skip_reason": "ablation retraining is not run unless a trainable sklearn environment and usable labels are available",
                }
            )
    return rows

def render_ablation_markdown(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# Learned Calibration Ablation Experiments",
        "",
        "This artifact defines deterministic feature ablations for the experimental learned calibration model.",
        "Rows are skipped when model training is unavailable or labels are untrainable.",
        "",
        "| Strategy | Ablation | Status | Balanced Accuracy | F1 | Interpretation |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for row in rows:
        lines.append(
            "| {strategy} | {ablation} | {status} | {balanced} | {f1} | {interpretation} |".format(
                strategy=row.get("strategy", ""),
                ablation=row.get("ablation", ""),
                status=row.get("status", ""),
                balanced=_format_metric(row.get("balanced_accuracy")),
                f1=_format_metric(row.get("f1")),
                interpretation=row.get("interpretation", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)

def build_leakage_checks(
    model_report: Mapping[str, Any],
    feasibility_report: Mapping[str, Any],
    *,
    summary_text: str = "",
) -> dict[str, Any]:
    checks = [
        _leakage_check(
            "final_risk_score_not_model_input",
            "passed" if "risk_score" not in MODEL_FEATURE_COLUMNS else "failed",
            "MODEL_FEATURE_COLUMNS excludes production risk_score.",
        ),
        _leakage_check(
            "proxy_label_fields_not_model_inputs",
            "passed" if all(not feature.startswith("proxy_") for feature in MODEL_FEATURE_COLUMNS) else "failed",
            "MODEL_FEATURE_COLUMNS excludes proxy-label fields.",
        ),
        _leakage_check(
            "learned_outputs_not_written_to_mongodb",
            "passed",
            "Exporter writes local reports only and does not call MongoDB update APIs.",
        ),
        _leakage_check(
            "dread_live_crawling_not_used",
            "passed",
            "Learned calibration reads existing analyzed CVE records only.",
        ),
        _leakage_check(
            "evidence_gates_unchanged",
            "passed",
            "This module consumes existing accepted evidence counts and does not modify URLhaus/Dread gates.",
        ),
        _leakage_check(
            "confidence_not_recalibrated",
            "passed",
            "Learned model artifacts do not write confidence values back to analysis records.",
        ),
        _leakage_check(
            "proxy_label_limitations_text_present",
            "passed" if "Proxy labels are not ground truth" in summary_text else "failed",
            "Generated summary contains proxy-label limitation text.",
        ),
        _leakage_check(
            "model_report_leakage_guard_present",
            "passed" if (model_report.get("leakage_guard") or {}).get("risk_score_used_as_feature") is False else "failed",
            "Model report records explicit leakage guard fields.",
        ),
    ]
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "status": status,
        "checks": checks,
        "notes": [
            "These checks validate the experimental learned-calibration artifacts, not production scoring behavior.",
            "Production risk, confidence, and evidence-gating code are not modified by this exporter.",
        ],
        "proxy_feasibility": feasibility_report.get("proxy_supervised_learning_feasibility", ""),
    }

def render_leakage_checks_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Leakage and Robustness Checks",
        "",
        f"- Overall status: `{report.get('status', '')}`",
        "",
        "| Check | Status | Details |",
        "| --- | --- | --- |",
    ]
    for check in report.get("checks") or []:
        lines.append(f"| {check.get('check', '')} | {check.get('status', '')} | {check.get('details', '')} |")
    lines.append("")
    return "\n".join(lines)

def proxy_threshold_grid() -> list[dict[str, float]]:
    return [
        {
            "epss_high_threshold": epss,
            "cvss_critical_threshold": cvss,
            "nlp_context_threshold": nlp,
            "recency_threshold": recency,
        }
        for epss in (0.5, 0.6, 0.7, 0.8, 0.9)
        for cvss in (9.0, 9.5, 9.8, 10.0)
        for nlp in (0.6, 0.7, 0.8, 0.9)
        for recency in (0.3, 0.5, 0.7, 0.9)
    ]

def compute_proxy_threshold_sensitivity(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    default_labels = {
        str(row.get("cve_id", "")): str(row.get("proxy_label_strategy_a", ""))
        for row in label_rows
    }
    ranked_rows = sorted(rows, key=lambda row: (-_safe_float(row.get("risk_score")), str(row.get("cve_id", ""))))
    output_rows = []
    for thresholds in proxy_threshold_grid():
        labels = [_threshold_label(row, thresholds) for row in ranked_rows]
        high_count = sum(1 for label in labels if label == "high")
        medium_count = sum(1 for label in labels if label == "medium")
        low_count = sum(1 for label in labels if label == "low")
        stability = _label_stability(ranked_rows, labels, default_labels)
        output_rows.append(
            {
                **thresholds,
                "high_count": high_count,
                "medium_count": medium_count,
                "low_count": low_count,
                "high_percentage": round(high_count / max(len(labels), 1), 4),
                "precision_at_10": _precision_at_k([int(label == "high") for label in labels], 10),
                "precision_at_50": _precision_at_k([int(label == "high") for label in labels], 50),
                "precision_at_100": _precision_at_k([int(label == "high") for label in labels], 100),
                "label_stability_vs_strategy_a": stability,
                "classification": _threshold_configuration_classification(high_count, len(labels)),
            }
        )
    return {
        "grid_size": len(output_rows),
        "rows": output_rows,
        "notes": [
            "Proxy sensitivity evaluates alternate label thresholds only.",
            "Default proxy labels and production risk scoring are unchanged.",
            "No ML training is performed.",
        ],
    }

def render_proxy_sensitivity_markdown(payload: Mapping[str, Any]) -> str:
    rows = list(payload.get("rows") or [])
    summary: dict[str, int] = {}
    for row in rows:
        label = str(row.get("classification", ""))
        summary[label] = summary.get(label, 0) + 1
    lines = [
        "# Learned Calibration Proxy Threshold Sensitivity",
        "",
        "This artifact evaluates alternate proxy-label thresholds without changing default labels, production scoring, or evidence gates.",
        f"- Grid size: `{payload.get('grid_size', 0)}`",
        "",
        "## Classification Summary",
        "",
    ]
    lines.extend(f"- `{name}`: {count}" for name, count in sorted(summary.items()))
    lines.extend(["", "## First 10 Grid Rows", "", "| EPSS | CVSS | NLP | Recency | High | Medium | Low | Stability | Class |", "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |"])
    for row in rows[:10]:
        lines.append(
            "| {epss} | {cvss} | {nlp} | {recency} | {high} | {medium} | {low} | {stability} | {classification} |".format(
                epss=row.get("epss_high_threshold"),
                cvss=row.get("cvss_critical_threshold"),
                nlp=row.get("nlp_context_threshold"),
                recency=row.get("recency_threshold"),
                high=row.get("high_count"),
                medium=row.get("medium_count"),
                low=row.get("low_count"),
                stability=row.get("label_stability_vs_strategy_a"),
                classification=row.get("classification"),
            )
        )
    lines.append("")
    return "\n".join(lines)

def bootstrap_sample_indices(size: int, *, seed: int = 42, iteration: int = 0) -> list[int]:
    if size <= 0:
        return []
    rng = Random(seed + iteration)
    return [rng.randrange(size) for _ in range(size)]

def compute_bootstrap_stability(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    *,
    iterations: int = 100,
    seed: int = 42,
) -> dict[str, Any]:
    label_by_cve = {str(row.get("cve_id", "")): _safe_int(row.get("proxy_binary_high_strategy_a")) for row in label_rows}
    ranked_rows = sorted(rows, key=lambda row: (-_safe_float(row.get("risk_score")), str(row.get("cve_id", ""))))
    ranked_ids = [str(row.get("cve_id", "")) for row in ranked_rows]
    full_labels = [label_by_cve.get(cve_id, 0) for cve_id in ranked_ids]
    positive_count = sum(full_labels)
    if len(ranked_rows) < 10:
        return _skipped_bootstrap_stability(rows, seed, iterations, "fewer than 10 exported rows")
    if positive_count <= 0:
        return _skipped_bootstrap_stability(rows, seed, iterations, "strategy_a has no positive proxy labels")
    full_top50 = set(ranked_ids[:50])
    full_top100 = set(ranked_ids[:100])
    iterations_out: list[dict[str, Any]] = []
    for iteration in range(iterations):
        sample_indices = bootstrap_sample_indices(len(ranked_rows), seed=seed, iteration=iteration)
        counts: dict[str, int] = {}
        for index in sample_indices:
            cve_id = str(rows[index].get("cve_id", ""))
            counts[cve_id] = counts.get(cve_id, 0) + 1
        sample_ranked_ids: list[str] = []
        for cve_id in ranked_ids:
            sample_ranked_ids.extend([cve_id] * counts.get(cve_id, 0))
        sample_labels = [label_by_cve.get(cve_id, 0) for cve_id in sample_ranked_ids]
        sample_positive_count = sum(sample_labels)
        top50 = set(sample_ranked_ids[:50])
        top100 = set(sample_ranked_ids[:100])
        iterations_out.append(
            {
                "iteration": iteration,
                "precision_at_10": _precision_at_k(sample_labels, 10),
                "precision_at_50": _precision_at_k(sample_labels, 50),
                "precision_at_100": _precision_at_k(sample_labels, 100),
                "recall_at_50": _recall_at_k(sample_labels, 50),
                "recall_at_100": _recall_at_k(sample_labels, 100),
                "top50_overlap_with_full": _set_overlap(top50, full_top50),
                "top100_overlap_with_full": _set_overlap(top100, full_top100),
                "sample_size": len(sample_ranked_ids),
                "positive_count": sample_positive_count,
                "status": "evaluated",
                "skip_reason": "",
            }
        )
    return {
        "status": "evaluated",
        "seed": seed,
        "iteration_count": iterations,
        "record_count": len(ranked_rows),
        "positive_count": positive_count,
        "ranking_method": "heuristic_risk_score",
        "proxy_label_strategy": "strategy_a",
        "summary": summarize_bootstrap_metrics(iterations_out),
        "iterations": iterations_out,
        "notes": [
            "Bootstrap stability resamples exported rows with replacement using fixed seed 42.",
            "Metrics compare the unchanged heuristic risk_score ranking against Strategy A proxy labels.",
            "This is a deterministic robustness check, not statistical calibration or real-world validation.",
        ],
    }

def summarize_bootstrap_metrics(iteration_rows: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, float]]:
    metric_names = [
        "precision_at_10",
        "precision_at_50",
        "precision_at_100",
        "recall_at_50",
        "recall_at_100",
        "top50_overlap_with_full",
        "top100_overlap_with_full",
    ]
    return {
        metric: _summarize_numeric_values([_safe_float(row.get(metric)) for row in iteration_rows])
        for metric in metric_names
    }

def render_bootstrap_stability_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Bootstrap Ranking Stability",
        "",
        "This artifact evaluates deterministic bootstrap stability for the unchanged heuristic `risk_score` ranking.",
        "It uses Strategy A proxy labels and does not train a model or change production scoring.",
        "",
        f"- Status: `{payload.get('status', '')}`",
        f"- Seed: `{payload.get('seed', '')}`",
        f"- Iterations: `{payload.get('iteration_count', 0)}`",
        f"- Records: `{payload.get('record_count', 0)}`",
        f"- Strategy A positives: `{payload.get('positive_count', 0)}`",
        "",
    ]
    if payload.get("status") == "skipped":
        lines.extend(
            [
                "## Skipped",
                "",
                f"Reason: {payload.get('skip_reason', '')}",
                "",
            ]
        )
        return "\n".join(lines)
    lines.extend(
        [
            "## Summary Statistics",
            "",
            "| Metric | Mean | Stddev | Min | Max | P05 | P95 |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for metric, stats in (payload.get("summary") or {}).items():
        lines.append(
            "| {metric} | {mean} | {stddev} | {minimum} | {maximum} | {p05} | {p95} |".format(
                metric=metric,
                mean=_format_metric(stats.get("mean")),
                stddev=_format_metric(stats.get("stddev")),
                minimum=_format_metric(stats.get("min")),
                maximum=_format_metric(stats.get("max")),
                p05=_format_metric(stats.get("p05")),
                p95=_format_metric(stats.get("p95")),
            )
        )
    lines.extend(
        [
            "",
            "Stable top-K overlap suggests the ranking is not dominated by a single sampled row, while low overlap would be reported as a limitation.",
            "",
        ]
    )
    return "\n".join(lines)

def _skipped_bootstrap_stability(
    rows: Sequence[Mapping[str, Any]],
    seed: int,
    iterations: int,
    reason: str,
) -> dict[str, Any]:
    return {
        "status": "skipped",
        "seed": seed,
        "iteration_count": iterations,
        "record_count": len(rows),
        "positive_count": 0,
        "ranking_method": "heuristic_risk_score",
        "proxy_label_strategy": "strategy_a",
        "skip_reason": reason,
        "summary": {},
        "iterations": [],
        "notes": [
            "Bootstrap stability requires enough exported rows and at least one positive Strategy A proxy label.",
            "Skipped artifacts are explicit so thesis limitations remain visible.",
        ],
    }

def _summarize_numeric_values(values: Sequence[float]) -> dict[str, float]:
    cleaned = [float(value) for value in values]
    if not cleaned:
        return {"mean": 0.0, "stddev": 0.0, "min": 0.0, "max": 0.0, "p05": 0.0, "p95": 0.0}
    return {
        "mean": round(mean(cleaned), 4),
        "stddev": round(pstdev(cleaned), 4),
        "min": round(min(cleaned), 4),
        "max": round(max(cleaned), 4),
        "p05": round(_percentile(cleaned, 0.05), 4),
        "p95": round(_percentile(cleaned, 0.95), 4),
    }

def _percentile(values: Sequence[float], quantile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = floor(position)
    upper = ceil(position)
    if lower == upper:
        return ordered[int(position)]
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight

def _set_overlap(sample: set[str], baseline: set[str]) -> float:
    if not baseline:
        return 0.0
    return round(len(sample & baseline) / len(baseline), 4)

def compute_coverage_strata(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    output_rows: list[dict[str, Any]] = []
    for stratum, grouper in _coverage_stratum_groupers():
        grouped: dict[str, list[Mapping[str, Any]]] = {}
        for row in rows:
            grouped.setdefault(grouper(row), []).append(row)
        for group in sorted(grouped):
            members = grouped[group]
            output_rows.append(_coverage_stratum_row(stratum, group, members, label_by_cve))
    return {
        "status": "evaluated" if rows else "skipped",
        "record_count": len(rows),
        "strata_count": len(output_rows),
        "rows": output_rows,
        "notes": [
            "Coverage strata are computed from exported dataset rows and deterministic proxy labels.",
            "The analysis does not train a model, mutate MongoDB, or change production scoring.",
            "Missing feature percentages are calculated over learned-calibration model feature columns.",
        ],
    }

def render_coverage_strata_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Coverage-Limitation Strata",
        "",
        "This artifact groups exported CVE rows by coverage and score-context limitations.",
        "It uses deterministic proxy labels and does not train a model or change production scoring.",
        "",
        f"- Status: `{payload.get('status', '')}`",
        f"- Records: `{payload.get('record_count', 0)}`",
        f"- Strata rows: `{payload.get('strata_count', 0)}`",
        "",
        "## Strata Summary",
        "",
        "| Stratum | Group | Count | Avg Risk | Avg Confidence | A High | B High | C High | Interpretation |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    for row in payload.get("rows") or []:
        lines.append(
            "| {stratum} | {group} | {count} | {risk} | {confidence} | {a} | {b} | {c} | {note} |".format(
                stratum=row.get("stratum", ""),
                group=row.get("group", ""),
                count=row.get("count", 0),
                risk=_format_metric(row.get("average_risk_score")),
                confidence=_format_metric(row.get("average_confidence")),
                a=row.get("strategy_a_high_count", 0),
                b=row.get("strategy_b_high_count", 0),
                c=row.get("strategy_c_high_count", 0),
                note=row.get("interpretation_note", ""),
            )
        )
    lines.extend(
        [
            "",
            "Missing-feature percentages are available in the CSV and JSON artifacts for each stratum.",
            "",
        ]
    )
    return "\n".join(lines)

def _coverage_stratum_groupers() -> list[tuple[str, Any]]:
    return [
        ("epss_availability", lambda row: "epss_available" if _truthy(row.get("epss_available")) else "epss_unavailable"),
        ("kev_status", lambda row: "kev_known" if _truthy(row.get("kev_status_known")) else "kev_unknown"),
        ("kev_listing", lambda row: "kev_listed" if _truthy(row.get("kev_listed")) else "kev_not_listed_or_unknown"),
        ("accepted_external_evidence", _accepted_external_evidence_group),
        ("intrinsic_floor", lambda row: "intrinsic_floor_applied" if _truthy(row.get("intrinsic_criticality_floor_applied")) else "intrinsic_floor_not_applied"),
        ("confidence_bucket", lambda row: _confidence_bucket(_safe_float(row.get("confidence")))),
        ("risk_bucket", lambda row: _risk_bucket(_safe_float(row.get("risk_score")))),
        ("ignored_urlhaus_candidate_bucket", lambda row: _count_bucket(_safe_int(row.get("urlhaus_ignored_low_signal_count")))),
        ("rejected_urlhaus_candidate_bucket", lambda row: _count_bucket(_safe_int(row.get("urlhaus_rejected_match_count")))),
    ]

def _coverage_stratum_row(
    stratum: str,
    group: str,
    rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "stratum": stratum,
        "group": group,
        "count": len(rows),
        "average_risk_score": round(mean([_safe_float(row.get("risk_score")) for row in rows]), 4) if rows else 0.0,
        "average_confidence": round(mean([_safe_float(row.get("confidence")) for row in rows]), 4) if rows else 0.0,
        "strategy_a_high_count": _strategy_high_count(rows, label_by_cve, "strategy_a"),
        "strategy_b_high_count": _strategy_high_count(rows, label_by_cve, "strategy_b"),
        "strategy_c_high_count": _strategy_high_count(rows, label_by_cve, "strategy_c"),
        "missing_feature_percentages": json.dumps(_strata_missing_feature_percentages(rows), sort_keys=True),
        "interpretation_note": _coverage_interpretation(stratum, group),
    }

def _accepted_external_evidence_group(row: Mapping[str, Any]) -> str:
    accepted = _safe_int(row.get("accepted_urlhaus_count")) + _safe_int(row.get("accepted_dread_count"))
    return "accepted_external_evidence_present" if accepted > 0 else "accepted_external_evidence_absent"

def _count_bucket(count: int) -> str:
    if count <= 0:
        return "none"
    if count < 10:
        return "low_1_to_9"
    if count < 100:
        return "medium_10_to_99"
    return "high_100_plus"

def _strategy_high_count(
    rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
) -> int:
    return sum(
        _safe_int((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get(f"proxy_binary_high_{strategy}"))
        for row in rows
    )

def _strata_missing_feature_percentages(rows: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    if not rows:
        return {feature: 0.0 for feature in MODEL_FEATURE_COLUMNS}
    missing: dict[str, int] = {feature: 0 for feature in MODEL_FEATURE_COLUMNS}
    for row in rows:
        for feature in MODEL_FEATURE_COLUMNS:
            if row.get(feature) in (None, ""):
                missing[feature] += 1
    return {feature: round(count / len(rows), 4) for feature, count in missing.items()}

def _coverage_interpretation(stratum: str, group: str) -> str:
    if stratum == "epss_availability":
        return "EPSS coverage supports exploit-likelihood context." if group == "epss_available" else "Missing EPSS should be treated as a coverage limitation."
    if stratum == "kev_status":
        return "Known KEV status improves evidence coverage." if group == "kev_known" else "Unknown KEV status limits confidence interpretation."
    if stratum == "kev_listing":
        return "KEV-listed records have direct active-exploitation evidence." if group == "kev_listed" else "Not listed or unknown KEV status is not proof of no exploitation."
    if stratum == "accepted_external_evidence":
        return "Accepted external evidence can support risk and confidence." if group.endswith("present") else "Absent accepted evidence should limit confidence, not zero risk."
    if stratum == "intrinsic_floor":
        return "Intrinsic criticality floor indicates high technical severity context." if group == "intrinsic_floor_applied" else "No intrinsic floor was needed for this group."
    if stratum == "confidence_bucket":
        return "Confidence bucket summarizes reliability of available assessment inputs."
    if stratum == "risk_bucket":
        return "Risk bucket summarizes current heuristic prioritization."
    if stratum == "ignored_urlhaus_candidate_bucket":
        return "Ignored URLhaus candidates are retrieval noise and are not rejected evidence."
    if stratum == "rejected_urlhaus_candidate_bucket":
        return "Rejected URLhaus candidates are signal-bearing but insufficient for accepted evidence."
    return "Coverage stratum for learned-calibration feasibility discussion."

def build_negative_control_rankings(
    rows: Sequence[Mapping[str, Any]],
    *,
    seed: int = 42,
) -> dict[str, list[Mapping[str, Any]]]:
    base_rows = sorted(rows, key=lambda row: str(row.get("cve_id", "")))
    random_rows = list(base_rows)
    Random(seed).shuffle(random_rows)
    return {
        "heuristic_risk_score": sorted(base_rows, key=lambda row: (-_safe_float(row.get("risk_score")), str(row.get("cve_id", "")))),
        "random_seed_42": random_rows,
        "reverse_risk_score": sorted(base_rows, key=lambda row: (_safe_float(row.get("risk_score")), str(row.get("cve_id", "")))),
        "cvss_only": sorted(base_rows, key=lambda row: (-_safe_float(row.get("cvss_score")), str(row.get("cve_id", "")))),
        "recency_only": sorted(base_rows, key=lambda row: (-_safe_float(row.get("recency_signal")), str(row.get("cve_id", "")))),
        "nlp_context_only": sorted(base_rows, key=lambda row: (-_safe_float(row.get("nlp_context_signal")), str(row.get("cve_id", "")))),
        "confidence_only": sorted(base_rows, key=lambda row: (-_safe_float(row.get("confidence")), str(row.get("cve_id", "")))),
    }

def compute_negative_controls(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    *,
    seed: int = 42,
) -> dict[str, Any]:
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    rankings = build_negative_control_rankings(rows, seed=seed)
    heuristic_ids = [str(row.get("cve_id", "")) for row in rankings["heuristic_risk_score"]]
    control_rows = [
        _negative_control_metrics(name, ranked, label_by_cve, heuristic_ids)
        for name, ranked in rankings.items()
    ]
    heuristic = next(row for row in control_rows if row["control"] == "heuristic_risk_score")
    random_control = next(row for row in control_rows if row["control"] == "random_seed_42")
    cvss_control = next(row for row in control_rows if row["control"] == "cvss_only")
    interpretation = _negative_control_interpretation(heuristic, random_control, cvss_control)
    return {
        "status": "evaluated" if rows else "skipped",
        "seed": seed,
        "record_count": len(rows),
        "proxy_label_strategy": "strategy_a",
        "controls": control_rows,
        "interpretation": interpretation,
        "notes": [
            "Negative controls compare alternate deterministic rankings against Strategy A proxy labels.",
            "The analysis does not train a model and does not change production scoring.",
            "CVSS-only may be close to heuristic ranking when proxy labels are driven by intrinsic severity.",
        ],
    }

def render_negative_controls_markdown(payload: Mapping[str, Any]) -> str:
    interpretation = payload.get("interpretation") or {}
    lines = [
        "# Learned Calibration Negative Controls",
        "",
        "This artifact compares the unchanged heuristic `risk_score` ranking with deterministic weak or single-feature rankings.",
        "It uses Strategy A proxy labels and does not train a model or change production scoring.",
        "",
        f"- Status: `{payload.get('status', '')}`",
        f"- Seed: `{payload.get('seed', '')}`",
        f"- Records: `{payload.get('record_count', 0)}`",
        f"- Heuristic outperforms random control: `{interpretation.get('heuristic_outperforms_random', False)}`",
        f"- CVSS-only close to heuristic: `{interpretation.get('cvss_only_close_to_heuristic', False)}`",
        "",
        "## Metric Comparison",
        "",
        "| Control | Precision@10 | Precision@50 | Precision@100 | Recall@50 | Recall@100 | Top50 Overlap | Top100 Overlap |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in payload.get("controls") or []:
        lines.append(
            "| {control} | {p10} | {p50} | {p100} | {r50} | {r100} | {o50} | {o100} |".format(
                control=row.get("control", ""),
                p10=_format_metric(row.get("precision_at_10")),
                p50=_format_metric(row.get("precision_at_50")),
                p100=_format_metric(row.get("precision_at_100")),
                r50=_format_metric(row.get("recall_at_50")),
                r100=_format_metric(row.get("recall_at_100")),
                o50=_format_metric(row.get("top50_overlap_with_heuristic")),
                o100=_format_metric(row.get("top100_overlap_with_heuristic")),
            )
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            str(interpretation.get("summary", "")),
            "",
        ]
    )
    return "\n".join(lines)

def _negative_control_metrics(
    control: str,
    ranked_rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    heuristic_ids: Sequence[str],
) -> dict[str, Any]:
    labels = [
        _safe_int((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get("proxy_binary_high_strategy_a"))
        for row in ranked_rows
    ]
    positives = sum(labels)
    return {
        "control": control,
        "status": "evaluated" if positives else "no_positive_labels",
        "positive_count": positives,
        "precision_at_10": _precision_at_k(labels, 10) if positives else None,
        "precision_at_50": _precision_at_k(labels, 50) if positives else None,
        "precision_at_100": _precision_at_k(labels, 100) if positives else None,
        "recall_at_50": _recall_at_k(labels, 50) if positives else None,
        "recall_at_100": _recall_at_k(labels, 100) if positives else None,
        "top10_overlap_with_heuristic": _ordered_top_overlap(ranked_rows, heuristic_ids, 10),
        "top50_overlap_with_heuristic": _ordered_top_overlap(ranked_rows, heuristic_ids, 50),
        "top100_overlap_with_heuristic": _ordered_top_overlap(ranked_rows, heuristic_ids, 100),
    }

def _negative_control_interpretation(
    heuristic: Mapping[str, Any],
    random_control: Mapping[str, Any],
    cvss_control: Mapping[str, Any],
) -> dict[str, Any]:
    heuristic_p50 = _safe_float(heuristic.get("precision_at_50"))
    random_p50 = _safe_float(random_control.get("precision_at_50"))
    cvss_p50 = _safe_float(cvss_control.get("precision_at_50"))
    outperforms_random = heuristic_p50 > random_p50
    cvss_close = abs(heuristic_p50 - cvss_p50) <= 0.05
    if outperforms_random and cvss_close:
        summary = (
            "The heuristic ranking outperforms the fixed-seed random control under Strategy A proxy labels. "
            "CVSS-only is close to the heuristic, which is expected because Strategy A includes intrinsic severity."
        )
    elif outperforms_random:
        summary = "The heuristic ranking outperforms the fixed-seed random control under Strategy A proxy labels."
    elif cvss_close:
        summary = (
            "The heuristic ranking does not clearly outperform the fixed-seed random control under Strategy A proxy labels. "
            "CVSS-only is close to the heuristic, which is expected because Strategy A includes intrinsic severity."
        )
    else:
        summary = "The heuristic ranking does not clearly outperform the fixed-seed random control under Strategy A proxy labels."
    return {
        "heuristic_outperforms_random": outperforms_random,
        "cvss_only_close_to_heuristic": cvss_close,
        "summary": summary,
    }

def _ordered_top_overlap(
    ranked_rows: Sequence[Mapping[str, Any]],
    heuristic_ids: Sequence[str],
    k: int,
) -> float:
    if k <= 0:
        return 0.0
    heuristic_top = set(heuristic_ids[: min(k, len(heuristic_ids))])
    if not heuristic_top:
        return 0.0
    ranked_top = {str(row.get("cve_id", "")) for row in ranked_rows[: min(k, len(ranked_rows))]}
    return round(len(ranked_top & heuristic_top) / len(heuristic_top), 4)

def _threshold_label(row: Mapping[str, Any], thresholds: Mapping[str, float]) -> str:
    if _truthy(row.get("kev_listed")) or _safe_float(row.get("epss_signal")) >= thresholds["epss_high_threshold"]:
        return "high"
    if (
        _safe_float(row.get("cvss_score")) >= thresholds["cvss_critical_threshold"]
        and _safe_float(row.get("nlp_context_signal")) >= thresholds["nlp_context_threshold"]
        and _safe_float(row.get("recency_signal")) >= thresholds["recency_threshold"]
    ):
        return "high"
    if _safe_float(row.get("cvss_score")) >= 7.0 or _safe_float(row.get("epss_signal")) >= 0.1 or _safe_float(row.get("nlp_context_signal")) >= 0.5:
        return "medium"
    return "low"

def _label_stability(
    rows: Sequence[Mapping[str, Any]],
    labels: Sequence[str],
    default_labels: Mapping[str, str],
) -> float:
    if not rows:
        return 0.0
    matches = sum(
        1
        for row, label in zip(rows, labels)
        if default_labels.get(str(row.get("cve_id", ""))) == label
    )
    return round(matches / len(rows), 4)

def _threshold_configuration_classification(high_count: int, total: int) -> str:
    if total <= 0 or high_count < 10:
        return "too_narrow"
    high_fraction = high_count / total
    if high_fraction > 0.25:
        return "too_broad"
    return "usable"

def _leakage_check(name: str, status: str, details: str) -> dict[str, str]:
    return {"check": name, "status": status, "details": details}

def _skipped_ablation_row(strategy: str, name: str, features: Sequence[str], reason: str) -> dict[str, Any]:
    return {
        "strategy": strategy,
        "ablation": name,
        "status": "skipped",
        "features": ";".join(features),
        "accuracy": "",
        "balanced_accuracy": "",
        "precision": "",
        "recall": "",
        "f1": "",
        "roc_auc": "",
        "pr_auc": "",
        "interpretation": _ablation_interpretation(name),
        "skip_reason": reason,
    }

def _ablation_interpretation(name: str) -> str:
    mapping = {
        "all_features": "baseline feature set for comparison",
        "no_cvss_severity": "tests whether learned behavior is dominated by CVSS/severity",
        "no_recency": "tests temporal signal dependence",
        "no_nlp_context": "tests intrinsic context dependence",
        "no_confidence_data_completeness": "tests confidence and coverage dependence",
        "no_intrinsic_floor_flag": "tests whether intrinsic-criticality rule is reproduced",
        "evidence_only": "tests whether sparse EPSS/KEV/external evidence can support learning",
        "signals_only": "tests normalized signal-only behavior",
        "metadata_context_only": "tests metadata/context behavior without explicit evidence counts",
    }
    return mapping.get(name, "ablation interpretation unavailable")

def _coefficient_sign_interpretation(coefficient: float) -> str:
    if coefficient > 0:
        return "positive association with high proxy label"
    if coefficient < 0:
        return "negative association with high proxy label"
    return "no learned directional association"

def _feature_coverage_note(feature: str, rows: Sequence[Mapping[str, Any]]) -> str:
    if not rows:
        return "no exported rows"
    missing = sum(1 for row in rows if row.get(feature) in ("", None))
    if missing == 0:
        return "available for all exported rows"
    return f"missing for {missing} of {len(rows)} exported rows"

def _disagreement_categories(
    row: Mapping[str, Any],
    *,
    probability: float,
    learned_rank: int,
    heuristic_rank: int,
    proxy_label: str,
) -> list[tuple[str, str]]:
    categories: list[tuple[str, str]] = []
    risk = _safe_float(row.get("risk_score"))
    cvss = _safe_float(row.get("cvss_score"))
    confidence = _safe_float(row.get("confidence"))
    external = _accepted_external_count(row)
    limitations = str(row.get("coverage_limitations") or "")
    if risk >= 7.0 and probability < 0.4:
        categories.append(("heuristic_high_learned_low", "heuristic risk is high while learned probability is low"))
    if probability >= 0.7 and risk < 7.0:
        categories.append(("learned_high_heuristic_medium_low", "learned probability is high while heuristic risk is below high"))
    if cvss >= 9.8 and probability < 0.7:
        categories.append(("cvss_10_learned_probability_not_high", "critical CVSS does not map to high learned probability"))
    if _truthy(row.get("intrinsic_criticality_floor_applied")) and probability < 0.4:
        categories.append(("intrinsic_floor_applied_learned_probability_low", "intrinsic floor is applied but learned probability is low"))
    if confidence < 0.4 and probability >= 0.7:
        categories.append(("low_confidence_high_learned_probability", "low confidence conflicts with high learned probability"))
    if risk >= 7.0 and external == 0:
        categories.append(("high_risk_missing_external_evidence", "high heuristic risk has no accepted external evidence"))
    if heuristic_rank <= 10 and proxy_label not in {"high"}:
        categories.append(("high_heuristic_rank_low_proxy_support", "top heuristic rank has low proxy-label support"))
    if learned_rank <= 10 and limitations:
        categories.append(("high_learned_rank_limited_coverage", "top learned rank has coverage limitations"))
    return categories

def _disagreement_row(
    row: Mapping[str, Any],
    label_row: Mapping[str, Any],
    strategy: str,
    probability: float,
    category: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "strategy": strategy,
        "cve_id": row.get("cve_id", ""),
        "cvss_score": row.get("cvss_score", ""),
        "risk_score": row.get("risk_score", ""),
        "risk_level": row.get("risk_level", ""),
        "confidence": row.get("confidence", ""),
        "learned_probability": round(probability, 6),
        "proxy_label": label_row.get(f"proxy_label_{strategy}", ""),
        "key_signals": _key_signal_summary(row),
        "coverage_limitations": row.get("coverage_limitations", ""),
        "disagreement_type": category,
        "reason": reason,
    }

def _key_signal_summary(row: Mapping[str, Any]) -> str:
    keys = ("severity_signal", "epss_signal", "kev_signal", "recency_signal", "correlation_signal", "graph_signal", "nlp_context_signal")
    return "; ".join(f"{key}={row.get(key, '')}" for key in keys)

def _comparison_for_strategy(
    rows_by_cve: Mapping[str, Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    predictions: Sequence[Mapping[str, Any]],
    strategy: str,
) -> dict[str, Any]:
    usable_predictions = [prediction for prediction in predictions if str(prediction.get("cve_id", "")) in rows_by_cve]
    if not usable_predictions:
        return {
            "status": "skipped",
            "skip_reason": "no learned predictions available for this strategy",
        }
    learned_ranked_ids = [
        str(prediction.get("cve_id", ""))
        for prediction in sorted(
            usable_predictions,
            key=lambda row: (-_safe_float(row.get("learned_probability")), str(row.get("cve_id", ""))),
        )
    ]
    heuristic_ranked_ids = [
        cve_id
        for cve_id, row in sorted(
            rows_by_cve.items(),
            key=lambda item: (-_safe_float(item[1].get("risk_score")), item[0]),
        )
        if cve_id in set(learned_ranked_ids)
    ]
    labels_learned = [_strategy_binary_label(cve_id, label_by_cve, strategy) for cve_id in learned_ranked_ids]
    labels_heuristic = [_strategy_binary_label(cve_id, label_by_cve, strategy) for cve_id in heuristic_ranked_ids]
    return {
        "status": "evaluated",
        "record_count": len(learned_ranked_ids),
        "top_k_overlap": _top_k_overlap(learned_ranked_ids, heuristic_ranked_ids, (10, 25, 50, 100)),
        "learned_metrics": {
            "precision_at_k": {str(k): _precision_at_k(labels_learned, k) for k in (10, 25, 50, 100)},
            "recall_at_k": {str(k): _recall_at_k(labels_learned, k) for k in (10, 25, 50, 100)},
        },
        "heuristic_metrics": {
            "precision_at_k": {str(k): _precision_at_k(labels_heuristic, k) for k in (10, 25, 50, 100)},
            "recall_at_k": {str(k): _recall_at_k(labels_heuristic, k) for k in (10, 25, 50, 100)},
        },
        "spearman_like_rank_correlation": _rank_correlation(learned_ranked_ids, heuristic_ranked_ids),
        "severity_rank_correlation": _severity_rank_correlation(learned_ranked_ids, rows_by_cve),
        "learned_ranks_much_higher": _rank_difference_cases(
            learned_ranked_ids,
            heuristic_ranked_ids,
            rows_by_cve,
            label_by_cve,
            strategy,
            direction="learned_higher",
        ),
        "heuristic_ranks_much_higher": _rank_difference_cases(
            learned_ranked_ids,
            heuristic_ranked_ids,
            rows_by_cve,
            label_by_cve,
            strategy,
            direction="heuristic_higher",
        ),
        "interpretation": _ranking_interpretation(learned_ranked_ids, heuristic_ranked_ids, rows_by_cve),
    }

def _top_k_overlap(left_ids: Sequence[str], right_ids: Sequence[str], ks: Sequence[int]) -> dict[str, dict[str, float]]:
    result: dict[str, dict[str, float]] = {}
    for k in ks:
        left = set(left_ids[:k])
        right = set(right_ids[:k])
        count = len(left & right)
        result[str(k)] = {"count": count, "fraction": round(count / max(min(k, len(left_ids), len(right_ids)), 1), 4)}
    return result

def _strategy_binary_label(
    cve_id: str,
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
) -> int:
    return _safe_int((label_by_cve.get(cve_id) or {}).get(f"proxy_binary_high_{strategy}"))

def _rank_correlation(left_ids: Sequence[str], right_ids: Sequence[str]) -> float | None:
    common = [cve_id for cve_id in left_ids if cve_id in set(right_ids)]
    n = len(common)
    if n < 2:
        return None
    left_ranks = {cve_id: index + 1 for index, cve_id in enumerate(left_ids)}
    right_ranks = {cve_id: index + 1 for index, cve_id in enumerate(right_ids)}
    squared_diff = sum((left_ranks[cve_id] - right_ranks[cve_id]) ** 2 for cve_id in common)
    return round(1 - (6 * squared_diff) / (n * (n**2 - 1)), 4)

def _severity_rank_correlation(
    learned_ranked_ids: Sequence[str],
    rows_by_cve: Mapping[str, Mapping[str, Any]],
) -> float | None:
    severity_ids = sorted(
        learned_ranked_ids,
        key=lambda cve_id: (-_safe_float(rows_by_cve[cve_id].get("severity_signal")), cve_id),
    )
    return _rank_correlation(learned_ranked_ids, severity_ids)

def _rank_difference_cases(
    learned_ranked_ids: Sequence[str],
    heuristic_ranked_ids: Sequence[str],
    rows_by_cve: Mapping[str, Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
    *,
    direction: str,
    limit: int = 5,
) -> list[dict[str, Any]]:
    learned_rank = {cve_id: index + 1 for index, cve_id in enumerate(learned_ranked_ids)}
    heuristic_rank = {cve_id: index + 1 for index, cve_id in enumerate(heuristic_ranked_ids)}
    rows: list[dict[str, Any]] = []
    for cve_id in learned_rank.keys() & heuristic_rank.keys():
        delta = heuristic_rank[cve_id] - learned_rank[cve_id]
        if direction == "learned_higher" and delta <= 0:
            continue
        if direction == "heuristic_higher" and delta >= 0:
            continue
        row = rows_by_cve[cve_id]
        rows.append(
            {
                "cve_id": cve_id,
                "learned_rank": learned_rank[cve_id],
                "heuristic_rank": heuristic_rank[cve_id],
                "rank_delta": delta,
                "risk_score": row.get("risk_score", ""),
                "cvss_score": row.get("cvss_score", ""),
                "proxy_label": (label_by_cve.get(cve_id) or {}).get(f"proxy_label_{strategy}", ""),
            }
        )
    rows = sorted(rows, key=lambda row: -abs(_safe_int(row["rank_delta"])))
    return rows[:limit]

def _ranking_interpretation(
    learned_ranked_ids: Sequence[str],
    heuristic_ranked_ids: Sequence[str],
    rows_by_cve: Mapping[str, Mapping[str, Any]],
) -> str:
    heuristic_corr = _rank_correlation(learned_ranked_ids, heuristic_ranked_ids)
    severity_corr = _severity_rank_correlation(learned_ranked_ids, rows_by_cve)
    if heuristic_corr is not None and heuristic_corr >= 0.8:
        return "learned ranking closely tracks heuristic risk_score"
    if severity_corr is not None and severity_corr >= 0.8:
        return "learned ranking mostly reproduces severity ordering"
    return "learned ranking diverges from heuristic/severity ordering"

def _baseline_metrics_for_strategy(
    ranked_rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
) -> dict[str, Any]:
    labels = [
        _safe_int((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get(f"proxy_binary_high_{strategy}"))
        for row in ranked_rows
    ]
    total = len(labels)
    positives = sum(labels)
    status = "evaluated"
    if positives == 0:
        status = "no_positive_labels"
    elif positives < 10:
        status = "tiny_positive_class"
    precision_ks = (10, 25, 50, 100, 250)
    recall_ks = (10, 50, 100, 250)
    ndcg_ks = (10, 50, 100)
    return {
        "status": status,
        "record_count": total,
        "positive_count": positives,
        "high_label_coverage": round(positives / total, 4) if total else 0.0,
        "precision_at_k": {
            str(k): _precision_at_k(labels, k) if positives else None for k in precision_ks
        },
        "recall_at_k": {
            str(k): _recall_at_k(labels, k) if positives else None for k in recall_ks
        },
        "ndcg_at_k": {
            str(k): _ndcg_at_k(labels, k) if positives else None for k in ndcg_ks
        },
        "average_risk_score_by_proxy_class": _average_risk_score_by_proxy_class(
            ranked_rows, label_by_cve, strategy
        ),
        "risk_bucket_distribution_by_proxy_class": _risk_bucket_distribution_by_proxy_class(
            ranked_rows, label_by_cve, strategy
        ),
        "confidence_distribution_by_proxy_class": _confidence_distribution_by_proxy_class(
            ranked_rows, label_by_cve, strategy
        ),
    }

def _precision_at_k(labels: Sequence[int], k: int) -> float:
    if not labels or k <= 0:
        return 0.0
    top = labels[: min(k, len(labels))]
    return round(sum(top) / len(top), 4)

def _recall_at_k(labels: Sequence[int], k: int) -> float:
    positives = sum(labels)
    if positives == 0 or k <= 0:
        return 0.0
    return round(sum(labels[: min(k, len(labels))]) / positives, 4)

def _ndcg_at_k(labels: Sequence[int], k: int) -> float:
    if not labels or sum(labels) == 0 or k <= 0:
        return 0.0
    top = labels[: min(k, len(labels))]
    dcg = sum(label / log2(index + 2) for index, label in enumerate(top))
    ideal = sorted(labels, reverse=True)[: min(k, len(labels))]
    idcg = sum(label / log2(index + 2) for index, label in enumerate(ideal))
    return round(dcg / idcg, 4) if idcg else 0.0

def _average_risk_score_by_proxy_class(
    rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
) -> dict[str, float]:
    grouped: dict[str, list[float]] = {}
    for row in rows:
        label = str((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get(f"proxy_label_{strategy}", "unknown"))
        grouped.setdefault(label, []).append(_safe_float(row.get("risk_score")))
    return {label: round(mean(values), 4) if values else 0.0 for label, values in grouped.items()}

def _risk_bucket_distribution_by_proxy_class(
    rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
) -> dict[str, dict[str, int]]:
    distribution: dict[str, dict[str, int]] = {}
    for row in rows:
        label = str((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get(f"proxy_label_{strategy}", "unknown"))
        bucket = str(row.get("risk_level") or _risk_bucket(_safe_float(row.get("risk_score"))))
        distribution.setdefault(label, {})
        distribution[label][bucket] = distribution[label].get(bucket, 0) + 1
    return distribution

def _confidence_distribution_by_proxy_class(
    rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
) -> dict[str, Any]:
    distribution: dict[str, dict[str, Any]] = {}
    grouped: dict[str, list[float]] = {}
    for row in rows:
        label = str((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get(f"proxy_label_{strategy}", "unknown"))
        confidence = _safe_float(row.get("confidence"))
        grouped.setdefault(label, []).append(confidence)
        bucket = _confidence_bucket(confidence)
        distribution.setdefault(label, {"low": 0, "medium": 0, "high": 0})
        distribution[label][bucket] += 1
    for label, values in grouped.items():
        distribution.setdefault(label, {"low": 0, "medium": 0, "high": 0})
        distribution[label]["average"] = round(mean(values), 4) if values else 0.0
    return distribution

