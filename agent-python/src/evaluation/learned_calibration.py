from __future__ import annotations

import argparse
import csv
import json
from math import log2
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Mapping, Sequence

import pymongo
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from config import DB_NAME, MONGO_URI, get_settings


_MISSING = object()

DATASET_COLUMNS = [
    "cve_id",
    "cvss_score",
    "risk_score",
    "risk_level",
    "confidence",
    "severity_signal",
    "epss_signal",
    "kev_signal",
    "recency_signal",
    "correlation_signal",
    "graph_signal",
    "nlp_context_signal",
    "score_before_intrinsic_floor",
    "intrinsic_criticality_floor_applied",
    "accepted_urlhaus_count",
    "accepted_dread_count",
    "candidate_urlhaus_count",
    "candidate_dread_count",
    "urlhaus_raw_candidate_count",
    "urlhaus_ignored_low_signal_count",
    "urlhaus_rejected_match_count",
    "assessment_confidence",
    "data_completeness",
    "coverage_limitations",
    "epss_available",
    "kev_status_known",
    "kev_listed",
    "age_days",
]

LABEL_COLUMNS = [
    "cve_id",
    "proxy_label_strategy_a",
    "proxy_binary_high_strategy_a",
    "proxy_label_strategy_b",
    "proxy_binary_high_strategy_b",
    "proxy_label_strategy_c",
    "proxy_binary_high_strategy_c",
    "proxy_label_reason",
    "proxy_label_limitations",
]


def extract_calibration_row(doc: Mapping[str, Any]) -> dict[str, Any] | None:
    source = deepcopy(dict(doc))
    risk_score = _coalesce_nested(
        source,
        "analysis.risk_score",
        "analysis.final_score",
        "risk_score",
        "final_score",
        "model_risk_score",
        default=None,
    )
    if risk_score in (None, ""):
        return None
    evidence = _first_mapping(
        source,
        "analysis.evidence",
        "analysis.evidence_summary",
        "evidence",
        "evidence_summary",
    )
    feature_breakdown = _first_mapping(
        source,
        "analysis.feature_breakdown",
        "analysis.features",
        "feature_breakdown",
        "features",
    )
    confidence_breakdown = _first_mapping(
        source,
        "analysis.confidence_breakdown",
        "confidence_breakdown",
    )
    urlhaus_stats = _first_mapping(
        source,
        "analysis.evidence.urlhaus_match_stats",
        "evidence.urlhaus_match_stats",
        "urlhaus_match_stats",
    )
    row = {
        "cve_id": str(
            _coalesce_nested(source, "analysis.entity_id", "analysis.cve_id", "cve_id", "id", "_id", default="")
        ),
        "cvss_score": _coalesce_nested(source, "analysis.evidence.cvss_score", "evidence.cvss_score", "analysis.cvss_score", "cvss_score", default=""),
        "risk_score": risk_score,
        "risk_level": _coalesce_nested(source, "analysis.risk_level", "risk_level", default=""),
        "confidence": _coalesce_nested(source, "analysis.confidence", "confidence", "model_confidence", default=""),
        "severity_signal": _coalesce_nested(feature_breakdown, "severity_signal", default=""),
        "epss_signal": _coalesce_nested(feature_breakdown, "epss_signal", default=""),
        "kev_signal": _coalesce_nested(feature_breakdown, "kev_signal", default=""),
        "recency_signal": _coalesce_nested(feature_breakdown, "recency_signal", default=""),
        "correlation_signal": _coalesce_nested(feature_breakdown, "correlation_signal", default=""),
        "graph_signal": _coalesce_nested(feature_breakdown, "graph_signal", default=""),
        "nlp_context_signal": _coalesce_nested(feature_breakdown, "nlp_context_signal", default=""),
        "score_before_intrinsic_floor": _coalesce_nested(feature_breakdown, "score_before_intrinsic_floor", default=""),
        "intrinsic_criticality_floor_applied": _coalesce_nested(feature_breakdown, "intrinsic_criticality_floor_applied", default=""),
        "accepted_urlhaus_count": _coalesce_nested(source, "analysis.evidence.related_urlhaus_count", "evidence.related_urlhaus_count", "related_urlhaus_count", default=0),
        "accepted_dread_count": _coalesce_nested(source, "analysis.evidence.related_dread_count", "evidence.related_dread_count", "related_dread_count", default=0),
        "candidate_urlhaus_count": _coalesce_nested(source, "analysis.evidence.candidate_urlhaus_count", "evidence.candidate_urlhaus_count", "candidate_urlhaus_count", default=0),
        "candidate_dread_count": _coalesce_nested(source, "analysis.evidence.candidate_dread_count", "evidence.candidate_dread_count", "candidate_dread_count", default=0),
        "urlhaus_raw_candidate_count": _coalesce_nested(urlhaus_stats, "raw_candidate_count", default=_coalesce_nested(source, "analysis.evidence.candidate_urlhaus_count", "evidence.candidate_urlhaus_count", "candidate_urlhaus_count", default=0)),
        "urlhaus_ignored_low_signal_count": _coalesce_nested(urlhaus_stats, "ignored_low_signal_count", default=0),
        "urlhaus_rejected_match_count": _coalesce_nested(urlhaus_stats, "rejected_match_count", default=0),
        "assessment_confidence": _coalesce_nested(confidence_breakdown, "assessment_confidence", default=""),
        "data_completeness": _coalesce_nested(confidence_breakdown, "data_completeness", default=""),
        "coverage_limitations": ";".join(_as_list(_coalesce_nested(confidence_breakdown, "coverage_limitations", default=[]))),
        "epss_available": _coalesce_nested(source, "analysis.evidence.epss_available", "evidence.epss_available", "epss_available", default=""),
        "kev_status_known": _coalesce_nested(source, "analysis.evidence.kev_status_known", "evidence.kev_status_known", "kev_status_known", default=""),
        "kev_listed": _coalesce_nested(source, "analysis.evidence.kev_listed", "evidence.kev_listed", "kev_listed", default=""),
        "age_days": _coalesce_nested(source, "analysis.evidence.age_days", "evidence.age_days", "feature_breakdown.age_days", "age_days", default=""),
    }
    return {column: row.get(column, "") for column in DATASET_COLUMNS}


def build_feasibility_report(
    rows: Sequence[Mapping[str, Any]],
    *,
    total_records_read: int,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    analyzed = len(rows)
    epss_count = sum(1 for row in rows if _truthy(row.get("epss_available")))
    kev_known_count = sum(1 for row in rows if _truthy(row.get("kev_status_known")))
    kev_listed_count = sum(1 for row in rows if _truthy(row.get("kev_listed")))
    urlhaus_accepted = sum(_safe_int(row.get("accepted_urlhaus_count")) for row in rows)
    dread_accepted = sum(_safe_int(row.get("accepted_dread_count")) for row in rows)
    floor_count = sum(1 for row in rows if _truthy(row.get("intrinsic_criticality_floor_applied")))
    missing_feature_counts = _missing_feature_counts(rows)
    missing_feature_percentages = _missing_feature_percentages(missing_feature_counts, analyzed)
    label_rows = build_proxy_label_rows(rows)
    label_summary = summarize_proxy_labels(label_rows, rows)
    warnings = _coverage_warnings(
        analyzed=analyzed,
        epss_count=epss_count,
        kev_known_count=kev_known_count,
        accepted_external_count=urlhaus_accepted + dread_accepted,
    )
    warnings.extend(label_summary["warnings"])
    return {
        "generated_at": generated,
        "total_cve_records_read": int(total_records_read),
        "analyzed_records_exported": analyzed,
        "records_with_cvss": sum(1 for row in rows if _safe_float(row.get("cvss_score")) > 0),
        "epss_availability_count": epss_count,
        "kev_known_count": kev_known_count,
        "kev_listed_count": kev_listed_count,
        "accepted_external_evidence_count": urlhaus_accepted + dread_accepted,
        "urlhaus_accepted_count": urlhaus_accepted,
        "dread_accepted_count": dread_accepted,
        "intrinsic_criticality_floor_count": floor_count,
        "missing_feature_counts": missing_feature_counts,
        "missing_feature_percentages": missing_feature_percentages,
        "missing_feature_accounting": {
            "columns": list(DATASET_COLUMNS),
            "counts": missing_feature_counts,
            "percentages": missing_feature_percentages,
        },
        "coverage": {
            "cvss_count": sum(1 for row in rows if _safe_float(row.get("cvss_score")) > 0),
            "epss_available_count": epss_count,
            "kev_status_known_count": kev_known_count,
            "kev_listed_count": kev_listed_count,
            "accepted_external_evidence_count": urlhaus_accepted + dread_accepted,
        },
        "evidence_counts": {
            "urlhaus_accepted_count": urlhaus_accepted,
            "dread_accepted_count": dread_accepted,
            "accepted_external_evidence_count": urlhaus_accepted + dread_accepted,
        },
        "dataset_columns": list(DATASET_COLUMNS),
        "warnings": warnings,
        "proxy_supervised_learning_feasibility": _feasibility_label(
            analyzed=analyzed,
            records_with_cvss=sum(1 for row in rows if _safe_float(row.get("cvss_score")) > 0),
            epss_count=epss_count,
            kev_known_count=kev_known_count,
            accepted_external_count=urlhaus_accepted + dread_accepted,
        ),
        "summary_statistics": _summary_statistics(rows),
        "proxy_label_class_counts": label_summary["class_counts"],
        "proxy_label_percentages": label_summary["percentages"],
        "proxy_binary_counts": label_summary["binary_counts"],
        "proxy_label_trainability": label_summary["trainability"],
        "proxy_label_limitations": label_summary["limitations"],
        "proxy_label_reason_counts": label_summary["reason_counts"],
    }


def render_summary_markdown(report: Mapping[str, Any]) -> str:
    label = report.get("proxy_supervised_learning_feasibility", "not_recommended")
    warnings = report.get("warnings") or []
    lines = [
        "# Learned Calibration Feasibility Summary",
        "",
        "This export is an experimental calibration layer for analysis, not a production scoring change.",
        "Proxy labels are not ground truth, and production `risk_score` behavior is unchanged.",
        "Confidence remains separate from risk. Dread live crawling is not used.",
        "",
        "## Dataset Snapshot",
        "",
        f"- Total CVE records read: `{report.get('total_cve_records_read', 0)}`",
        f"- Analyzed records exported: `{report.get('analyzed_records_exported', 0)}`",
        f"- Records with CVSS: `{report.get('records_with_cvss', 0)}`",
        f"- EPSS available: `{report.get('epss_availability_count', 0)}`",
        f"- KEV status known: `{report.get('kev_known_count', 0)}`",
        f"- Accepted external evidence count: `{report.get('accepted_external_evidence_count', 0)}`",
        f"- Proxy label rows: `{report.get('analyzed_records_exported', 0)}`",
        "",
        "## Feasibility",
        "",
        f"- Proxy-supervised learning feasibility: `{label}`",
        "",
        "The current data is suitable for proxy-supervised learning only if feature coverage and externally defensible proxy labels are adequate. Weak EPSS, KEV, or external-evidence coverage limits what can be learned responsibly.",
        "Proxy labels are deterministic thesis-analysis aids, not verified exploitation outcomes.",
        "",
        "## Warnings",
        "",
    ]
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- No major feasibility warnings were generated.")
    lines.append("")
    return "\n".join(lines)


def write_outputs(rows: Sequence[Mapping[str, Any]], report: Mapping[str, Any], output_dir: str | Path) -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    dataset_path = output / "learned_calibration_dataset.csv"
    labels_path = output / "learned_calibration_labels.csv"
    report_path = output / "learned_calibration_report.json"
    summary_path = output / "learned_calibration_summary.md"
    baseline_json_path = output / "learned_calibration_baseline_metrics.json"
    baseline_md_path = output / "learned_calibration_baseline_metrics.md"
    label_rows = build_proxy_label_rows(rows)
    baseline_metrics = compute_baseline_metrics(rows, label_rows)
    with dataset_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DATASET_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in DATASET_COLUMNS})
    with labels_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LABEL_COLUMNS)
        writer.writeheader()
        for row in label_rows:
            writer.writerow({column: row.get(column, "") for column in LABEL_COLUMNS})
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
    summary_path.write_text(render_summary_markdown(report), encoding="utf-8")
    baseline_json_path.write_text(json.dumps(baseline_metrics, indent=2, sort_keys=True, default=str), encoding="utf-8")
    baseline_md_path.write_text(render_baseline_metrics_markdown(baseline_metrics), encoding="utf-8")
    return {
        "dataset": str(dataset_path),
        "labels": str(labels_path),
        "report": str(report_path),
        "summary": str(summary_path),
        "baseline_metrics": str(baseline_json_path),
        "baseline_summary": str(baseline_md_path),
    }


def export_from_documents(docs: Sequence[Mapping[str, Any]], output_dir: str | Path, *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [row for doc in docs if (row := extract_calibration_row(doc)) is not None]
    rows = sorted(rows, key=lambda row: str(row.get("cve_id", "")))
    report = build_feasibility_report(rows, total_records_read=len(docs), generated_at=generated_at)
    paths = write_outputs(rows, report, output_dir)
    return {"paths": paths, "report": report}


def read_analyzed_cves_from_mongo(limit: int = 0) -> list[Mapping[str, Any]]:
    settings = get_settings()
    try:
        client = pymongo.MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=settings.database.server_selection_timeout_ms,
            connectTimeoutMS=settings.database.connect_timeout_ms,
        )
        client.admin.command("ping")
        cursor = client[DB_NAME]["cve_intel"].find({})
        if limit > 0:
            cursor = cursor.limit(limit)
        return list(cursor)
    except ServerSelectionTimeoutError as exc:
        raise RuntimeError(
            "MongoDB is unavailable for learned calibration export. "
            "Start MongoDB or run against an existing analyzed database; this command is read-only. "
            f"Original error: {exc}"
        ) from exc
    except PyMongoError as exc:
        raise RuntimeError(f"Unable to read cve_intel for learned calibration export: {exc}") from exc


def _coverage_warnings(*, analyzed: int, epss_count: int, kev_known_count: int, accepted_external_count: int) -> list[str]:
    warnings: list[str] = []
    if analyzed == 0:
        return ["No analyzed CVE records were available for export."]
    if epss_count / analyzed < 0.25:
        warnings.append("EPSS coverage is weak; exploit-likelihood proxy features may be sparse.")
    if kev_known_count / analyzed < 0.25:
        warnings.append("KEV status coverage is weak; active-exploitation proxy labels may be sparse.")
    if accepted_external_count == 0:
        warnings.append("Accepted URLhaus/Dread external evidence is absent; correlation-derived proxy labels are unavailable.")
    return warnings


def _feasibility_label(
    *,
    analyzed: int,
    records_with_cvss: int,
    epss_count: int,
    kev_known_count: int,
    accepted_external_count: int,
) -> str:
    if analyzed < 50 or records_with_cvss / max(analyzed, 1) < 0.5:
        return "not_recommended"
    if epss_count / analyzed >= 0.5 and kev_known_count / analyzed >= 0.5 and accepted_external_count > 0:
        return "meaningful"
    return "limited"


def _summary_statistics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    risks = [_safe_float(row.get("risk_score")) for row in rows if row.get("risk_score") not in ("", None)]
    confidences = [_safe_float(row.get("confidence")) for row in rows if row.get("confidence") not in ("", None)]
    return {
        "average_risk_score": round(mean(risks), 4) if risks else 0.0,
        "average_confidence": round(mean(confidences), 4) if confidences else 0.0,
    }


def strict_validation_errors(report: Mapping[str, Any]) -> list[str]:
    errors: list[str] = []
    if _safe_int(report.get("analyzed_records_exported")) == 0:
        errors.append("No analyzed CVE records were exported.")
    if _safe_int(report.get("records_with_cvss")) == 0:
        errors.append("No exported records include CVSS scores.")
    return errors


def build_proxy_label_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return [build_proxy_label_row(row) for row in deepcopy(list(rows))]


def build_proxy_label_row(row: Mapping[str, Any]) -> dict[str, Any]:
    strategy_a, reason_a = _strategy_a_label(row)
    strategy_b, reason_b, limitations_b = _strategy_b_label(row)
    strategy_c, reason_c = _strategy_c_label(row)
    limitations = list(limitations_b)
    if _safe_float(row.get("epss_signal")) == 0 and not _truthy(row.get("epss_available")):
        limitations.append("epss coverage missing or unavailable")
    if not _truthy(row.get("kev_status_known")):
        limitations.append("kev status unknown")
    if _accepted_external_count(row) == 0:
        limitations.append("no accepted external evidence")
    return {
        "cve_id": row.get("cve_id", ""),
        "proxy_label_strategy_a": strategy_a,
        "proxy_binary_high_strategy_a": int(strategy_a == "high"),
        "proxy_label_strategy_b": strategy_b,
        "proxy_binary_high_strategy_b": int(strategy_b == "high"),
        "proxy_label_strategy_c": strategy_c,
        "proxy_binary_high_strategy_c": int(strategy_c == "high"),
        "proxy_label_reason": f"strategy_a:{reason_a}; strategy_b:{reason_b}; strategy_c:{reason_c}",
        "proxy_label_limitations": "; ".join(dict.fromkeys(limitations)),
    }


def summarize_proxy_labels(
    label_rows: Sequence[Mapping[str, Any]],
    feature_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    strategies = ("strategy_a", "strategy_b", "strategy_c")
    class_counts = {
        strategy: _label_counts(label_rows, f"proxy_label_{strategy}")
        for strategy in strategies
    }
    percentages = {
        strategy: _label_percentages(counts, len(label_rows))
        for strategy, counts in class_counts.items()
    }
    binary_counts = {
        strategy: {
            "high": sum(_safe_int(row.get(f"proxy_binary_high_{strategy}")) for row in label_rows),
            "not_high": len(label_rows) - sum(_safe_int(row.get(f"proxy_binary_high_{strategy}")) for row in label_rows),
        }
        for strategy in strategies
    }
    reason_counts = _proxy_reason_counts(label_rows)
    limitations = {
        "strategy_a": ["Uses intrinsic technical severity when external evidence is sparse."],
        "strategy_b": _strategy_b_limitations(feature_rows),
        "strategy_c": ["Conservative binary proxy; non-high cases are not negative ground truth."],
    }
    trainability = {
        strategy: _trainability_decision(
            total=len(label_rows),
            high_count=binary_counts[strategy]["high"],
            limitations=limitations[strategy],
        )
        for strategy in strategies
    }
    warnings = _proxy_label_warnings(label_rows, feature_rows, reason_counts)
    return {
        "class_counts": class_counts,
        "percentages": percentages,
        "binary_counts": binary_counts,
        "trainability": trainability,
        "limitations": limitations,
        "reason_counts": reason_counts,
        "warnings": warnings,
    }


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


def _risk_bucket(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _confidence_bucket(confidence: float) -> str:
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.4:
        return "medium"
    return "low"


def _format_metric(value: Any) -> str:
    if value is None:
        return "n/a"
    return str(value)


def _strategy_a_label(row: Mapping[str, Any]) -> tuple[str, str]:
    if _truthy(row.get("kev_listed")):
        return "high", "kev listed"
    if _safe_float(row.get("epss_signal")) >= 0.7:
        return "high", "epss signal >= 0.7"
    if (
        _safe_float(row.get("cvss_score")) >= 9.8
        and _safe_float(row.get("nlp_context_signal")) >= 0.8
        and _safe_float(row.get("recency_signal")) >= 0.5
    ):
        return "high", "intrinsic criticality pattern"
    if (
        _safe_float(row.get("cvss_score")) >= 7.0
        or _safe_float(row.get("epss_signal")) >= 0.1
        or _safe_float(row.get("nlp_context_signal")) >= 0.5
    ):
        return "medium", "moderate intrinsic or exploit-likelihood signal"
    return "low", "no high or medium proxy condition met"


def _strategy_b_label(row: Mapping[str, Any]) -> tuple[str, str, list[str]]:
    limitations: list[str] = []
    epss = _safe_float(row.get("epss_signal"))
    accepted_external = _accepted_external_count(row)
    confidence = _safe_float(row.get("confidence"))
    if not _truthy(row.get("epss_available")):
        limitations.append("epss unavailable")
    if not _truthy(row.get("kev_status_known")):
        limitations.append("kev status unknown")
    if accepted_external == 0:
        limitations.append("accepted external evidence absent")
    if _truthy(row.get("kev_listed")):
        return "high", "kev listed", limitations
    if epss >= 0.7:
        return "high", "high epss signal", limitations
    if accepted_external > 0 and confidence >= 0.5:
        return "high", "accepted external evidence with adequate confidence", limitations
    if epss >= 0.1 or accepted_external > 0:
        return "medium", "some evidence signal but below high threshold", limitations
    return "low", "no accepted evidence-prioritized high condition met", limitations


def _strategy_c_label(row: Mapping[str, Any]) -> tuple[str, str]:
    if _truthy(row.get("kev_listed")):
        return "high", "kev listed"
    if _safe_float(row.get("epss_signal")) >= 0.8:
        return "high", "epss signal >= 0.8"
    if (
        _truthy(row.get("intrinsic_criticality_floor_applied"))
        and _safe_float(row.get("cvss_score")) >= 9.8
        and _safe_float(row.get("nlp_context_signal")) >= 0.8
    ):
        return "high", "intrinsic floor with critical cvss and strong context"
    return "not_high", "no conservative high proxy condition met"


def _accepted_external_count(row: Mapping[str, Any]) -> int:
    return _safe_int(row.get("accepted_urlhaus_count")) + _safe_int(row.get("accepted_dread_count"))


def _label_counts(rows: Sequence[Mapping[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        label = str(row.get(key, ""))
        counts[label] = counts.get(label, 0) + 1
    return counts


def _label_percentages(counts: Mapping[str, int], total: int) -> dict[str, float]:
    if total <= 0:
        return {label: 0.0 for label in counts}
    return {label: round(count / total, 4) for label, count in counts.items()}


def _strategy_b_limitations(rows: Sequence[Mapping[str, Any]]) -> list[str]:
    total = len(rows)
    if total == 0:
        return ["no exported rows"]
    limitations: list[str] = []
    epss_available = sum(1 for row in rows if _truthy(row.get("epss_available")))
    kev_known = sum(1 for row in rows if _truthy(row.get("kev_status_known")))
    accepted_external = sum(1 for row in rows if _accepted_external_count(row) > 0)
    if epss_available / total < 0.25:
        limitations.append("EPSS coverage is sparse")
    if kev_known / total < 0.25:
        limitations.append("KEV status coverage is sparse")
    if accepted_external == 0:
        limitations.append("accepted external evidence is absent")
    return limitations or ["evidence coverage is adequate for this proxy definition"]


def _trainability_decision(*, total: int, high_count: int, limitations: Sequence[str]) -> str:
    if total < 50 or high_count == 0:
        return "not_recommended"
    high_fraction = high_count / total
    if high_fraction < 0.01 or high_fraction > 0.95:
        return "not_recommended"
    if any("sparse" in limitation or "absent" in limitation for limitation in limitations):
        return "limited"
    return "usable"


def _proxy_reason_counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        for reason in str(row.get("proxy_label_reason", "")).split(";"):
            reason = reason.strip()
            if not reason:
                continue
            counts[reason] = counts.get(reason, 0) + 1
    return counts


def _proxy_label_warnings(
    label_rows: Sequence[Mapping[str, Any]],
    feature_rows: Sequence[Mapping[str, Any]],
    reason_counts: Mapping[str, int],
) -> list[str]:
    warnings: list[str] = []
    high_a = sum(1 for row in label_rows if row.get("proxy_label_strategy_a") == "high")
    intrinsic_high_a = reason_counts.get("strategy_a:intrinsic criticality pattern", 0)
    if high_a and intrinsic_high_a / high_a >= 0.7:
        warnings.append("Strategy A high labels are mostly CVSS/intrinsic-context driven.")
    if _strategy_b_limitations(feature_rows) != ["evidence coverage is adequate for this proxy definition"]:
        warnings.append("Strategy B is limited by sparse EPSS/KEV or accepted external-evidence coverage.")
    return warnings


def _missing_feature_counts(rows: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    return {
        column: sum(1 for row in rows if row.get(column) in ("", None))
        for column in DATASET_COLUMNS
    }


def _missing_feature_percentages(missing_counts: Mapping[str, int], analyzed: int) -> dict[str, float]:
    if analyzed <= 0:
        return {column: 0.0 for column in DATASET_COLUMNS}
    return {column: round(count / analyzed, 4) for column, count in missing_counts.items()}


def _get_nested(doc: Mapping[str, Any], path: str, default: Any = None) -> Any:
    current: Any = doc
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def _coalesce_nested(doc: Mapping[str, Any], *paths: str, default: Any = None) -> Any:
    for path in paths:
        value = _get_nested(doc, path, _MISSING)
        if value is _MISSING or value in (None, ""):
            continue
        return value
    return default


def _first_mapping(doc: Mapping[str, Any], *paths: str) -> Mapping[str, Any]:
    for path in paths:
        value = _get_nested(doc, path, _MISSING)
        if isinstance(value, Mapping):
            return value
    return {}


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value]
    return [str(value)]


def _safe_int(value: Any) -> int:
    try:
        if value in ("", None):
            return 0
        return int(value)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any) -> float:
    try:
        if value in ("", None):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "listed"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Export learned-calibration feasibility artifacts from analyzed CVE records.")
    parser.add_argument("--output-dir", default="../reports/thesis")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when no usable analyzed CVE rows are exported.")
    args = parser.parse_args()
    docs = read_analyzed_cves_from_mongo(limit=args.limit)
    result = export_from_documents(docs, args.output_dir)
    if args.strict:
        errors = strict_validation_errors(result["report"])
        if errors:
            print(json.dumps({"status": "failed", "errors": errors}, indent=2))
            raise SystemExit(2)
    print(json.dumps({"status": "written", **result["paths"], "analyzed_records_exported": result["report"]["analyzed_records_exported"]}, indent=2))


if __name__ == "__main__":
    main()
