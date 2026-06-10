from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from statistics import mean, median
from typing import Any, Iterable, Mapping, Sequence

from evaluation.datasets import EvaluationRecord, safe_float
from evaluation.metrics import spearman_rank_correlation
from evaluation.runner import write_report_json


DEFAULT_OUTPUT_DIR = Path("reports/objective_evaluation")


class EvaluationObjective(str, Enum):
    SEVERITY = "severity"
    EXPLOITATION_PRIORITY = "exploitation_priority"
    OPERATIONAL_RISK = "operational_risk"


@dataclass(frozen=True)
class ObjectiveDefinition:
    name: EvaluationObjective
    intended_meaning: str
    valid_inputs: tuple[str, ...]
    labels_or_references: tuple[str, ...]
    metrics: tuple[str, ...]
    production_score_suitability: str
    proxy_usage: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "intended_meaning": self.intended_meaning,
            "valid_inputs": list(self.valid_inputs),
            "labels_or_references": list(self.labels_or_references),
            "metrics": list(self.metrics),
            "production_score_suitability": self.production_score_suitability,
            "proxy_usage": self.proxy_usage,
            "limitations": list(self.limitations),
        }


def objective_definitions() -> dict[str, dict[str, Any]]:
    definitions = [
        ObjectiveDefinition(
            name=EvaluationObjective.SEVERITY,
            intended_meaning="Technical severity and impact ordering independent of local asset context.",
            valid_inputs=("balanced benchmark records", "CVSS score", "model risk score"),
            labels_or_references=("CVSS technical severity reference",),
            metrics=("Spearman rank correlation", "score deltas", "disagreement cases"),
            production_score_suitability="proxy_only",
            proxy_usage="The current risk score includes temporal, correlation, and graph signals, so it is not a pure severity score.",
            limitations=("CVSS is a reference scale, not perfect ground truth.", "Risk-score disagreements may be intended prioritization behavior."),
        ),
        ObjectiveDefinition(
            name=EvaluationObjective.EXPLOITATION_PRIORITY,
            intended_meaning="Priority ordering for likely or observed exploitation at the CVE level.",
            valid_inputs=("balanced benchmark records", "CISA KEV membership", "FIRST EPSS", "correlation-focused URLhaus labels"),
            labels_or_references=("CISA KEV", "FIRST EPSS", "confirmed URLhaus CVE relationships"),
            metrics=("Precision@K", "Recall@K", "NDCG@K", "MRR", "KEV hit rate", "EPSS rank correlation", "correlation confusion matrix"),
            production_score_suitability="partial_proxy",
            proxy_usage="The current risk score can be compared to exploitation-priority signals but also contains technical severity and age effects.",
            limitations=("KEV is incomplete and curated.", "EPSS is probabilistic.", "Exact URLhaus correlation coverage is a small subset."),
        ),
        ObjectiveDefinition(
            name=EvaluationObjective.OPERATIONAL_RISK,
            intended_meaning="Asset-specific actionability after applicability, business criticality, exposure, patch state, and controls.",
            valid_inputs=("operational-risk result rows", "asset context", "source risk score"),
            labels_or_references=("fixture-derived operational comparisons",),
            metrics=("grouped score summaries", "applicability/exposure/patch/criticality contrasts", "case comparisons"),
            production_score_suitability="not_directly_suitable",
            proxy_usage="The source risk score is an input to operational risk, not a replacement for asset-aware operational impact.",
            limitations=("Current thesis artifacts use deterministic fixture assets unless a real operational report is supplied.",),
        ),
    ]
    return {definition.name.value: definition.to_dict() for definition in definitions}


def run_objective_evaluation(
    *,
    balanced_dir: str | Path,
    correlation_dir: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    operational_report_path: str | Path | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    balanced = _load_balanced_artifacts(Path(balanced_dir))
    correlation = _load_correlation_artifacts(Path(correlation_dir))
    operational_report, operational_source = _load_operational_report(operational_report_path)
    missing_inputs = []
    if operational_report_path is None:
        missing_inputs.append(
            {
                "input": "operational_report_path",
                "impact": "Used deterministic thesis fixture scenario; operational-risk results are fixture-derived.",
            }
        )

    severity = build_severity_evaluation(balanced["records"], balanced["case_candidates"], generated_at=generated)
    exploitation = build_exploitation_priority_evaluation(balanced, correlation, generated_at=generated)
    operational = build_operational_risk_evaluation(operational_report, source=operational_source, generated_at=generated)
    comparison = build_objective_comparison()
    metrics = build_objective_metrics(severity, exploitation, operational)
    cases = build_objective_case_candidates(severity, exploitation, operational, balanced, correlation)
    summary = {
        "generated_at": generated,
        "objectives": objective_definitions(),
        "input_artifacts": {
            "balanced_dir": str(Path(balanced_dir)),
            "correlation_dir": str(Path(correlation_dir)),
            "operational_report_path": str(operational_report_path) if operational_report_path is not None else None,
        },
        "missing_optional_inputs": missing_inputs,
        "severity": _summary_block(severity),
        "exploitation_priority": _summary_block(exploitation),
        "operational_risk": _summary_block(operational),
        "case_candidate_keys": sorted(cases),
        "limitations": _combined_limitations(comparison),
    }
    report = {
        "generated_at": generated,
        "evaluation_objectives": {
            "generated_at": generated,
            "objectives": objective_definitions(),
            "input_artifacts": summary["input_artifacts"],
            "missing_optional_inputs": missing_inputs,
        },
        "severity_evaluation": severity,
        "exploitation_priority_evaluation": exploitation,
        "operational_risk_evaluation": operational,
        "objective_comparison": comparison,
        "objective_metrics": metrics,
        "objective_case_candidates": cases,
        "thesis_results_summary": summary,
    }
    write_objective_artifacts(report, output_dir)
    return _stable(report)


def build_severity_evaluation(
    records: Sequence[Mapping[str, Any]],
    case_candidates: Mapping[str, Any] | None = None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [row for row in records if _has_number(row.get("model_risk_score")) and _has_number(row.get("cvss_score"))]
    eval_records = [
        EvaluationRecord(
            cve_id=row["cve_id"],
            model_risk_score=safe_float(row.get("model_risk_score")),
            model_confidence=safe_float(row.get("model_confidence")),
            cvss_score=safe_float(row.get("cvss_score")),
        )
        for row in rows
    ]
    deltas = [
        {
            "cve_id": row["cve_id"],
            "cvss_score": safe_float(row.get("cvss_score")),
            "model_risk_score": safe_float(row.get("model_risk_score")),
            "score_delta": round(safe_float(row.get("model_risk_score")) - safe_float(row.get("cvss_score")), 6),
            "absolute_delta": round(abs(safe_float(row.get("model_risk_score")) - safe_float(row.get("cvss_score"))), 6),
            "direction": "model_higher" if safe_float(row.get("model_risk_score")) > safe_float(row.get("cvss_score")) else "model_lower",
            "bucket": row.get("bucket"),
            "is_kev": _bool(row.get("is_kev")),
        }
        for row in rows
    ]
    disagreements = sorted(deltas, key=lambda row: (-row["absolute_delta"], row["cve_id"]))[:10]
    return {
        "generated_at": generated_at,
        "objective": EvaluationObjective.SEVERITY.value,
        "reference": "CVSS technical severity reference, not perfect ground truth",
        "record_count": len(rows),
        "metrics": {
            "spearman_model_vs_cvss": spearman_rank_correlation(eval_records, lambda record: record.model_risk_score, lambda record: record.cvss_score),
            "mean_absolute_score_delta": _mean(row["absolute_delta"] for row in deltas),
            "median_absolute_score_delta": _median(row["absolute_delta"] for row in deltas),
            "max_absolute_score_delta": max((row["absolute_delta"] for row in deltas), default=0.0),
        },
        "score_delta_summary": _distribution(row["score_delta"] for row in deltas),
        "disagreement_cases": disagreements,
        "source_case_candidates": dict(case_candidates or {}),
        "limitations": objective_definitions()[EvaluationObjective.SEVERITY.value]["limitations"],
    }


def build_exploitation_priority_evaluation(
    balanced: Mapping[str, Any],
    correlation: Mapping[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    records = list(balanced.get("records", []))
    eval_records = [
        EvaluationRecord(
            cve_id=row["cve_id"],
            model_risk_score=safe_float(row.get("model_risk_score")),
            model_confidence=safe_float(row.get("model_confidence")),
            cvss_score=safe_float(row.get("cvss_score")),
            epss_score=safe_float(row.get("epss_score")) if _has_number(row.get("epss_score")) else None,
            is_kev=_bool(row.get("is_kev")),
        )
        for row in records
        if row.get("cve_id")
    ]
    correlation_eval = dict(correlation.get("evaluation", {}))
    paired_records = list(correlation.get("paired_records", []))
    return {
        "generated_at": generated_at,
        "objective": EvaluationObjective.EXPLOITATION_PRIORITY.value,
        "balanced_benchmark": {
            "record_count": len(records),
            "metric_config": dict(balanced.get("summary", {}).get("metric_config") or {}),
            "diagnostics": dict(balanced.get("diagnostics") or {}),
            "model_risk": _strategy_summary(balanced.get("summary", {}).get("baselines", {}).get("model_risk")),
            "cvss_only": _strategy_summary(balanced.get("summary", {}).get("baselines", {}).get("cvss_only")),
            "epss_only": _strategy_summary(balanced.get("summary", {}).get("baselines", {}).get("epss_only")),
            "cvss_epss": _strategy_summary(balanced.get("summary", {}).get("baselines", {}).get("cvss_epss")),
            "model_confidence_weighted": _strategy_summary(balanced.get("summary", {}).get("baselines", {}).get("model_confidence_weighted")),
        },
        "epss_correlation": {
            "spearman_model_vs_epss": spearman_rank_correlation(eval_records, lambda record: record.model_risk_score, lambda record: record.epss_score or 0.0),
            "records_with_epss": sum(1 for record in eval_records if record.epss_score is not None),
        },
        "correlation_focused_subset": {
            "record_count": sum((correlation_eval.get("label_counts") or {}).values()) if isinstance(correlation_eval.get("label_counts"), Mapping) else 0,
            "label_counts": dict(correlation_eval.get("label_counts") or {}),
            "decision_counts": dict(correlation_eval.get("decision_counts") or {}),
            "included_ground_truth_count": correlation_eval.get("included_ground_truth_count", 0),
            "unknown_excluded_count": correlation_eval.get("unknown_excluded_count", 0),
            "accepted_manual_review_are_separate": True,
            "metrics": {
                "precision": correlation_eval.get("precision", 0.0),
                "recall": correlation_eval.get("recall", 0.0),
                "f1": correlation_eval.get("f1", 0.0),
                "manual_review_count": correlation_eval.get("manual_review_count", 0),
                "manual_review_positive_count": correlation_eval.get("manual_review_positive_count", 0),
                "true_positives": correlation_eval.get("true_positives", 0),
                "false_positives": correlation_eval.get("false_positives", 0),
                "true_negatives": correlation_eval.get("true_negatives", 0),
                "false_negatives": correlation_eval.get("false_negatives", 0),
            },
        },
        "paired_evidence_effect": _paired_effect_summary(paired_records),
        "case_candidates": dict(correlation.get("case_candidates") or {}),
        "limitations": objective_definitions()[EvaluationObjective.EXPLOITATION_PRIORITY.value]["limitations"],
    }


def build_operational_risk_evaluation(report: Mapping[str, Any], *, source: str, generated_at: str | None = None) -> dict[str, Any]:
    rows = list(report.get("asset_operational_risk") or [])
    comparisons = {
        "applicability": _group_summary(rows, lambda row: _nested(row, "applicability", "status")),
        "exposure": _group_summary(rows, lambda row: _nested(row, "component_breakdown", "exposure")),
        "patch_state": _group_summary(rows, lambda row: _nested(row, "component_breakdown", "patch_state")),
        "criticality": _group_summary(rows, lambda row: _nested(row, "component_breakdown", "criticality")),
    }
    return {
        "generated_at": generated_at,
        "objective": EvaluationObjective.OPERATIONAL_RISK.value,
        "source": source,
        "fixture_derived": source != "provided_report",
        "record_count": len(rows),
        "comparisons": comparisons,
        "top_operational_risk_cases": sorted(rows, key=lambda row: (-safe_float(row.get("final_operational_risk_score")), str(row.get("cve_id")), str(row.get("asset_id"))))[:10],
        "non_actionable_cases": [
            row
            for row in sorted(rows, key=lambda row: (str(row.get("cve_id")), str(row.get("asset_id"))))
            if safe_float(row.get("final_operational_risk_score")) == 0.0
        ],
        "source_fixture_metadata": dict(report.get("fixture_metadata") or {}),
        "limitations": objective_definitions()[EvaluationObjective.OPERATIONAL_RISK.value]["limitations"],
    }


def build_objective_comparison() -> list[dict[str, Any]]:
    rows = []
    for definition in objective_definitions().values():
        rows.append(
            {
                "objective": definition["name"],
                "measures": definition["intended_meaning"],
                "source_signals": "; ".join(definition["valid_inputs"]),
                "labels_or_references": "; ".join(definition["labels_or_references"]),
                "metrics": "; ".join(definition["metrics"]),
                "production_score_suitability": definition["production_score_suitability"],
                "proxy_usage": definition["proxy_usage"],
                "known_limitations": "; ".join(definition["limitations"]),
            }
        )
    return rows


def build_objective_metrics(
    severity: Mapping[str, Any],
    exploitation: Mapping[str, Any],
    operational: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for metric, value in (severity.get("metrics") or {}).items():
        rows.append({"objective": "severity", "scope": "cvss_reference", "metric": metric, "value": value})
    for strategy in ("model_risk", "cvss_only", "epss_only", "cvss_epss", "model_confidence_weighted"):
        metrics = ((exploitation.get("balanced_benchmark") or {}).get(strategy) or {}).get("metrics") or {}
        for metric, value in sorted(metrics.items()):
            rows.append({"objective": "exploitation_priority", "scope": f"balanced:{strategy}", "metric": metric, "value": value})
    for metric, value in ((exploitation.get("epss_correlation") or {})).items():
        rows.append({"objective": "exploitation_priority", "scope": "epss", "metric": metric, "value": value})
    for metric, value in (((exploitation.get("correlation_focused_subset") or {}).get("metrics") or {})).items():
        rows.append({"objective": "exploitation_priority", "scope": "correlation_focused", "metric": metric, "value": value})
    for dimension, summary in (operational.get("comparisons") or {}).items():
        for group, values in (summary or {}).items():
            rows.append(
                {
                    "objective": "operational_risk",
                    "scope": f"{dimension}:{group}",
                    "metric": "mean_final_operational_risk_score",
                    "value": values.get("mean_final_operational_risk_score"),
                }
            )
            rows.append({"objective": "operational_risk", "scope": f"{dimension}:{group}", "metric": "count", "value": values.get("count")})
    return sorted(rows, key=lambda row: (row["objective"], row["scope"], row["metric"]))


def build_objective_case_candidates(
    severity: Mapping[str, Any],
    exploitation: Mapping[str, Any],
    operational: Mapping[str, Any],
    balanced: Mapping[str, Any],
    correlation: Mapping[str, Any],
) -> dict[str, Any]:
    records = list(balanced.get("records", []))
    operational_rows = []
    for group in ("top_operational_risk_cases", "non_actionable_cases"):
        operational_rows.extend(operational.get(group) or [])
    cases = {
        "high_severity_low_exploitation_priority": _case_from_balanced_candidates(balanced, "high_cvss_low_exploitation_signal_case")
        or _best(records, lambda row: safe_float(row.get("cvss_score")) - safe_float(row.get("epss_score")) * 10.0),
        "low_or_medium_severity_high_exploitation_priority": _best(
            [row for row in records if safe_float(row.get("cvss_score")) <= 7.0 and (_bool(row.get("is_kev")) or safe_float(row.get("epss_score")) >= 0.75)],
            lambda row: safe_float(row.get("epss_score")),
        ),
        "high_exploitation_priority_low_operational_risk": _best(
            [row for row in operational_rows if safe_float(row.get("final_operational_risk_score")) == 0.0],
            lambda row: safe_float(row.get("source_risk_score")),
        ),
        "moderate_severity_high_operational_risk_due_to_asset_context": _best(
            [row for row in operational_rows if safe_float(row.get("source_risk_score")) <= 7.0],
            lambda row: safe_float(row.get("final_operational_risk_score")) - safe_float(row.get("source_risk_score")),
        ),
        "correlation_driven_uplift_case": _best(
            correlation.get("paired_records", []),
            lambda row: safe_float(row.get("risk_score_delta")),
        ),
        "old_but_still_actively_exploited_case": _case_from_balanced_candidates(balanced, "old_but_actively_exploited_case"),
        "strongest_severity_disagreement": (severity.get("disagreement_cases") or [None])[0],
    }
    return {key: _missing_case(key) if value is None else value for key, value in cases.items()}


def write_objective_artifacts(report: Mapping[str, Any], output_dir: str | Path) -> dict[str, str]:
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    files = {
        "evaluation_objectives": path / "evaluation_objectives.json",
        "severity_evaluation": path / "severity_evaluation.json",
        "exploitation_priority_evaluation": path / "exploitation_priority_evaluation.json",
        "operational_risk_evaluation": path / "operational_risk_evaluation.json",
        "objective_comparison": path / "objective_comparison.csv",
        "objective_metrics": path / "objective_metrics.csv",
        "objective_case_candidates": path / "objective_case_candidates.json",
        "thesis_results_summary": path / "thesis_results_summary.json",
    }
    write_report_json(report["evaluation_objectives"], files["evaluation_objectives"])
    write_report_json(report["severity_evaluation"], files["severity_evaluation"])
    write_report_json(report["exploitation_priority_evaluation"], files["exploitation_priority_evaluation"])
    write_report_json(report["operational_risk_evaluation"], files["operational_risk_evaluation"])
    write_report_json(report["objective_case_candidates"], files["objective_case_candidates"])
    write_report_json(report["thesis_results_summary"], files["thesis_results_summary"])
    _write_csv(report["objective_comparison"], files["objective_comparison"])
    _write_csv(report["objective_metrics"], files["objective_metrics"])
    return {name: str(file_path) for name, file_path in files.items()}


def _load_balanced_artifacts(path: Path) -> dict[str, Any]:
    return {
        "summary": _read_json(path / "benchmark_summary.json"),
        "diagnostics": _read_json(path / "benchmark_diagnostics.json"),
        "case_candidates": _read_json(path / "case_candidates.json"),
        "records": _read_csv(path / "benchmark_records.csv"),
    }


def _load_correlation_artifacts(path: Path) -> dict[str, Any]:
    return {
        "evaluation": _read_json(path / "correlation_evaluation.json"),
        "case_candidates": _read_json(path / "correlation_case_candidates.json"),
        "records": _read_csv(path / "correlation_records.csv"),
        "paired_records": list((_read_json(path / "paired_model_results.json").get("records") or [])),
    }


def _load_operational_report(path: str | Path | None) -> tuple[dict[str, Any], str]:
    if path is not None:
        return _read_json(Path(path)), "provided_report"
    from integration.thesis_scenario import run_thesis_scenario

    return run_thesis_scenario(), "deterministic_thesis_fixture"


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Required objective-evaluation input is missing: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def _read_csv(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Required objective-evaluation input is missing: {path}")
    with path.open(newline="", encoding="utf-8") as handle:
        return [_coerce_csv_row(row) for row in csv.DictReader(handle)]


def _coerce_csv_row(row: Mapping[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in row.items():
        if value in {"True", "False"}:
            result[key] = value == "True"
        elif value == "":
            result[key] = None
        elif _looks_float(value):
            result[key] = safe_float(value)
        else:
            result[key] = value
    return result


def _strategy_summary(strategy: Mapping[str, Any] | None) -> dict[str, Any]:
    if not strategy:
        return {"available": False, "metrics": {}, "ranking_count": 0}
    return {
        "available": True,
        "metrics": dict(strategy.get("metrics") or {}),
        "ranking_count": len(strategy.get("ranking") or []),
        "spearman_vs_model_risk": strategy.get("spearman_vs_model_risk"),
    }


def _paired_effect_summary(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "record_count": len(records),
        "risk_changed_count": sum(1 for row in records if safe_float(row.get("risk_score_delta")) != 0.0),
        "confidence_changed_count": sum(1 for row in records if safe_float(row.get("confidence_delta")) != 0.0),
        "graph_edge_changed_count": sum(1 for row in records if safe_float(row.get("graph_edge_delta")) != 0.0),
        "cross_source_edge_changed_count": sum(1 for row in records if safe_float(row.get("cross_source_edge_delta")) != 0.0),
        "max_risk_delta": max((abs(safe_float(row.get("risk_score_delta"))) for row in records), default=0.0),
        "max_confidence_delta": max((abs(safe_float(row.get("confidence_delta"))) for row in records), default=0.0),
    }


def _group_summary(rows: Sequence[Mapping[str, Any]], key_fn: Any) -> dict[str, dict[str, Any]]:
    groups: dict[str, list[Mapping[str, Any]]] = {}
    for row in rows:
        key = str(key_fn(row) or "unknown")
        groups.setdefault(key, []).append(row)
    return {
        key: {
            "count": len(values),
            "mean_source_risk_score": _mean(safe_float(row.get("source_risk_score")) for row in values),
            "mean_final_operational_risk_score": _mean(safe_float(row.get("final_operational_risk_score")) for row in values),
            "max_final_operational_risk_score": max((safe_float(row.get("final_operational_risk_score")) for row in values), default=0.0),
        }
        for key, values in sorted(groups.items())
    }


def _nested(row: Mapping[str, Any], *keys: str) -> Any:
    value: Any = row
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _case_from_balanced_candidates(balanced: Mapping[str, Any], key: str) -> Any:
    return (balanced.get("case_candidates") or {}).get(key)


def _missing_case(key: str) -> dict[str, Any]:
    return {
        "available": False,
        "case": key,
        "reason": "No matching case was present in the supplied benchmark artifacts; no case was fabricated.",
    }


def _best(rows: Iterable[Mapping[str, Any]], score_fn: Any) -> dict[str, Any] | None:
    values = list(rows)
    if not values:
        return None
    return dict(sorted(values, key=lambda row: (-safe_float(score_fn(row)), str(row.get("cve_id")), str(row.get("asset_id", ""))))[0])


def _summary_block(report: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "objective": report.get("objective"),
        "record_count": report.get("record_count")
        or (report.get("balanced_benchmark") or {}).get("record_count")
        or (report.get("correlation_focused_subset") or {}).get("record_count"),
        "key_metrics": dict(report.get("metrics") or (report.get("correlation_focused_subset") or {}).get("metrics") or {}),
        "limitations": list(report.get("limitations") or []),
    }


def _combined_limitations(comparison: Sequence[Mapping[str, Any]]) -> list[str]:
    values: list[str] = []
    for row in comparison:
        for item in str(row.get("known_limitations") or "").split("; "):
            if item and item not in values:
                values.append(item)
    return values


def _write_csv(rows: Sequence[Mapping[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field)) for field in fieldnames})


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return value


def _distribution(values: Iterable[Any]) -> dict[str, Any]:
    rows = sorted(safe_float(value) for value in values if value is not None)
    if not rows:
        return {"count": 0}
    return {
        "count": len(rows),
        "min": rows[0],
        "median": round(median(rows), 6),
        "max": rows[-1],
        "mean": _mean(rows),
    }


def _mean(values: Iterable[Any]) -> float:
    rows = [safe_float(value) for value in values]
    return round(mean(rows), 6) if rows else 0.0


def _median(values: Iterable[Any]) -> float:
    rows = [safe_float(value) for value in values]
    return round(median(rows), 6) if rows else 0.0


def _has_number(value: Any) -> bool:
    if value is None or value == "":
        return False
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


def _looks_float(value: Any) -> bool:
    try:
        float(str(value))
    except (TypeError, ValueError):
        return False
    return True


def _bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"true", "1", "yes"}


def _stable(report: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(report, sort_keys=True, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate thesis objective-specific evaluation artifacts")
    parser.add_argument("--balanced-dir", required=True, help="Directory containing balanced benchmark artifacts")
    parser.add_argument("--correlation-dir", required=True, help="Directory containing correlation benchmark artifacts")
    parser.add_argument("--operational-report", default=None, help="Optional thesis scenario/operational-risk report JSON")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for objective evaluation artifacts")
    parser.add_argument("--generated-at", default=None, help="Optional deterministic timestamp")
    args = parser.parse_args()
    report = run_objective_evaluation(
        balanced_dir=args.balanced_dir,
        correlation_dir=args.correlation_dir,
        operational_report_path=args.operational_report,
        output_dir=args.output_dir,
        generated_at=args.generated_at,
    )
    print(
        json.dumps(
            {
                "output_dir": args.output_dir,
                "objectives": sorted(report["evaluation_objectives"]["objectives"]),
                "severity_records": report["severity_evaluation"]["record_count"],
                "operational_records": report["operational_risk_evaluation"]["record_count"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
