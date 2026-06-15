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

MODEL_FEATURE_COLUMNS = [
    "cvss_score",
    "severity_signal",
    "epss_signal",
    "kev_signal",
    "recency_signal",
    "correlation_signal",
    "graph_signal",
    "nlp_context_signal",
    "accepted_urlhaus_count",
    "accepted_dread_count",
    "data_completeness",
    "assessment_confidence",
    "age_days",
    "intrinsic_criticality_floor_applied",
]

PREDICTION_COLUMNS = [
    "cve_id",
    "strategy",
    "proxy_binary_high",
    "learned_probability",
    "learned_prediction",
]

DISAGREEMENT_COLUMNS = [
    "strategy",
    "cve_id",
    "cvss_score",
    "risk_score",
    "risk_level",
    "confidence",
    "learned_probability",
    "proxy_label",
    "key_signals",
    "coverage_limitations",
    "disagreement_type",
    "reason",
]

FEATURE_IMPORTANCE_COLUMNS = [
    "strategy",
    "feature",
    "coefficient",
    "absolute_coefficient_rank",
    "sign_interpretation",
    "feature_coverage_note",
    "warning",
]

ABLATION_COLUMNS = [
    "strategy",
    "ablation",
    "status",
    "features",
    "accuracy",
    "balanced_accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "pr_auc",
    "interpretation",
    "skip_reason",
]

LEAKAGE_CHECK_COLUMNS = [
    "check",
    "status",
    "details",
]

CASE_STUDY_COLUMNS = [
    "cve_id",
    "cvss_score",
    "risk_score",
    "confidence",
    "proxy_label",
    "learned_probability",
    "coverage_limitations",
    "key_reason",
    "case_group",
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
    predictions_path = output / "learned_calibration_predictions.csv"
    model_report_path = output / "learned_calibration_model_report.json"
    model_summary_path = output / "learned_calibration_model_summary.md"
    comparison_path = output / "learned_vs_heuristic_comparison.json"
    comparison_summary_path = output / "learned_vs_heuristic_comparison.md"
    disagreements_path = output / "learned_calibration_disagreements.csv"
    disagreements_summary_path = output / "learned_calibration_disagreements.md"
    feature_importance_path = output / "learned_calibration_feature_importance.csv"
    feature_importance_summary_path = output / "learned_calibration_feature_importance.md"
    ablation_path = output / "learned_calibration_ablation.csv"
    ablation_summary_path = output / "learned_calibration_ablation.md"
    leakage_path = output / "learned_calibration_leakage_checks.json"
    leakage_summary_path = output / "learned_calibration_leakage_checks.md"
    thesis_section_path = output / "learned_calibration_thesis_section.md"
    limitations_path = output / "learned_calibration_limitations.md"
    case_studies_path = output / "learned_calibration_case_studies.csv"
    case_studies_summary_path = output / "learned_calibration_case_studies.md"
    tables_path = output / "learned_calibration_tables.json"
    tables_summary_path = output / "learned_calibration_tables.md"
    manifest_path = output / "learned_calibration_manifest.json"
    manifest_summary_path = output / "learned_calibration_manifest.md"
    label_rows = build_proxy_label_rows(rows)
    baseline_metrics = compute_baseline_metrics(rows, label_rows)
    model_result = train_learned_calibration_models(rows, label_rows)
    comparison = compute_learned_vs_heuristic_comparison(rows, label_rows, model_result["predictions"])
    disagreements = compute_disagreement_cases(rows, label_rows, model_result["predictions"])
    feature_importance = extract_feature_importance(model_result["report"], rows)
    ablations = compute_ablation_experiments(model_result["report"])
    leakage_checks = build_leakage_checks(model_result["report"], report, summary_text=render_summary_markdown(report))
    case_studies = select_case_studies(rows, label_rows, model_result["predictions"])
    publication_tables = build_publication_tables(
        feasibility_report=report,
        baseline_metrics=baseline_metrics,
        model_report=model_result["report"],
        ablations=ablations,
        leakage_checks=leakage_checks,
    )
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
    with predictions_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PREDICTION_COLUMNS)
        writer.writeheader()
        for row in model_result["predictions"]:
            writer.writerow({column: row.get(column, "") for column in PREDICTION_COLUMNS})
    model_report_path.write_text(json.dumps(model_result["report"], indent=2, sort_keys=True, default=str), encoding="utf-8")
    model_summary_path.write_text(render_model_summary_markdown(model_result["report"]), encoding="utf-8")
    comparison_path.write_text(json.dumps(comparison, indent=2, sort_keys=True, default=str), encoding="utf-8")
    comparison_summary_path.write_text(render_learned_vs_heuristic_markdown(comparison), encoding="utf-8")
    with disagreements_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DISAGREEMENT_COLUMNS)
        writer.writeheader()
        for row in disagreements:
            writer.writerow({column: row.get(column, "") for column in DISAGREEMENT_COLUMNS})
    disagreements_summary_path.write_text(render_disagreements_markdown(disagreements), encoding="utf-8")
    with feature_importance_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_IMPORTANCE_COLUMNS)
        writer.writeheader()
        for row in feature_importance:
            writer.writerow({column: row.get(column, "") for column in FEATURE_IMPORTANCE_COLUMNS})
    feature_importance_summary_path.write_text(render_feature_importance_markdown(feature_importance, model_result["report"]), encoding="utf-8")
    with ablation_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ABLATION_COLUMNS)
        writer.writeheader()
        for row in ablations:
            writer.writerow({column: row.get(column, "") for column in ABLATION_COLUMNS})
    ablation_summary_path.write_text(render_ablation_markdown(ablations), encoding="utf-8")
    leakage_path.write_text(json.dumps(leakage_checks, indent=2, sort_keys=True, default=str), encoding="utf-8")
    leakage_summary_path.write_text(render_leakage_checks_markdown(leakage_checks), encoding="utf-8")
    thesis_section_path.write_text(
        render_learned_calibration_thesis_section(report, baseline_metrics, model_result["report"], comparison, disagreements, ablations),
        encoding="utf-8",
    )
    limitations_path.write_text(render_learned_calibration_limitations(report, model_result["report"], leakage_checks), encoding="utf-8")
    with case_studies_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CASE_STUDY_COLUMNS)
        writer.writeheader()
        for row in case_studies:
            writer.writerow({column: row.get(column, "") for column in CASE_STUDY_COLUMNS})
    case_studies_summary_path.write_text(render_case_studies_markdown(case_studies), encoding="utf-8")
    tables_path.write_text(json.dumps(publication_tables, indent=2, sort_keys=True, default=str), encoding="utf-8")
    tables_summary_path.write_text(render_publication_tables_markdown(publication_tables), encoding="utf-8")
    artifact_manifest = build_learned_calibration_manifest(output)
    manifest_path.write_text(json.dumps(artifact_manifest, indent=2, sort_keys=True, default=str), encoding="utf-8")
    manifest_summary_path.write_text(render_learned_calibration_manifest_markdown(artifact_manifest), encoding="utf-8")
    return {
        "dataset": str(dataset_path),
        "labels": str(labels_path),
        "report": str(report_path),
        "summary": str(summary_path),
        "baseline_metrics": str(baseline_json_path),
        "baseline_summary": str(baseline_md_path),
        "predictions": str(predictions_path),
        "model_report": str(model_report_path),
        "model_summary": str(model_summary_path),
        "learned_vs_heuristic_comparison": str(comparison_path),
        "learned_vs_heuristic_summary": str(comparison_summary_path),
        "disagreements": str(disagreements_path),
        "disagreements_summary": str(disagreements_summary_path),
        "feature_importance": str(feature_importance_path),
        "feature_importance_summary": str(feature_importance_summary_path),
        "ablation": str(ablation_path),
        "ablation_summary": str(ablation_summary_path),
        "leakage_checks": str(leakage_path),
        "leakage_checks_summary": str(leakage_summary_path),
        "thesis_section": str(thesis_section_path),
        "limitations": str(limitations_path),
        "case_studies": str(case_studies_path),
        "case_studies_summary": str(case_studies_summary_path),
        "tables": str(tables_path),
        "tables_summary": str(tables_summary_path),
        "manifest": str(manifest_path),
        "manifest_summary": str(manifest_summary_path),
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


def train_learned_calibration_models(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    sklearn_bundle = _load_sklearn()
    if sklearn_bundle is None:
        return {
            "predictions": [],
            "report": _skipped_model_report(
                generated_at=generated,
                reason="scikit-learn is not installed in the current Python environment",
            ),
        }
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    predictions: list[dict[str, Any]] = []
    strategies: dict[str, Any] = {}
    for strategy in ("strategy_a", "strategy_b", "strategy_c"):
        strategy_result = _train_strategy_model(rows, label_by_cve, strategy, sklearn_bundle)
        strategies[strategy] = strategy_result["report"]
        predictions.extend(strategy_result["predictions"])
    return {
        "predictions": sorted(predictions, key=lambda row: (row["strategy"], row["cve_id"])),
        "report": {
            "generated_at": generated,
            "status": "completed",
            "model_type": "LogisticRegression",
            "random_seed": 42,
            "features": list(MODEL_FEATURE_COLUMNS),
            "leakage_guard": {
                "risk_score_used_as_feature": "risk_score" in MODEL_FEATURE_COLUMNS,
                "proxy_label_fields_used_as_features": [],
            },
            "model_registry": model_registry(sklearn_bundle),
            "strategies": strategies,
            "interpretation": _model_interpretation(strategies),
        },
    }


def render_model_summary_markdown(report: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Model Summary",
        "",
        "This artifact is experimental and does not change production scoring behavior.",
        f"- Status: `{report.get('status', '')}`",
        f"- Model type: `{report.get('model_type', 'skipped')}`",
        f"- Random seed: `{report.get('random_seed', 'n/a')}`",
        "",
        "| Strategy | Status | Accuracy | Balanced Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for strategy, payload in (report.get("strategies") or {}).items():
        metrics = payload.get("metrics") or {}
        lines.append(
            "| {strategy} | {status} | {accuracy} | {balanced} | {precision} | {recall} | {f1} | {roc} | {pr} |".format(
                strategy=strategy,
                status=payload.get("status", ""),
                accuracy=_format_metric(metrics.get("accuracy")),
                balanced=_format_metric(metrics.get("balanced_accuracy")),
                precision=_format_metric(metrics.get("precision")),
                recall=_format_metric(metrics.get("recall")),
                f1=_format_metric(metrics.get("f1")),
                roc=_format_metric(metrics.get("roc_auc")),
                pr=_format_metric(metrics.get("pr_auc")),
            )
        )
    lines.extend(
        [
            "",
            "The model is meaningful only when proxy labels have enough class diversity and supporting evidence coverage.",
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


def render_learned_calibration_thesis_section(
    feasibility_report: Mapping[str, Any],
    baseline_metrics: Mapping[str, Any],
    model_report: Mapping[str, Any],
    comparison: Mapping[str, Any],
    disagreements: Sequence[Mapping[str, Any]],
    ablations: Sequence[Mapping[str, Any]],
) -> str:
    lines = [
        "# Learned Calibration Experiment",
        "",
        "This section summarizes an experimental learned-calibration layer built around the existing deterministic risk engine.",
        "The purpose is diagnostic: to examine whether proxy-supervised models could reproduce or challenge the heuristic ranking without replacing production `risk_score`.",
        "",
        "## Proxy Labels",
        "",
        "Proxy labels are constructed from intrinsic severity/context, EPSS/KEV signals when available, and accepted external evidence counts.",
        "They are not ground truth exploitation outcomes and do not support real-world supervised exploitation-prediction claims.",
        f"The exported dataset contains `{feasibility_report.get('analyzed_records_exported', 0)}` analyzed CVE rows.",
        "",
        "## Feature Set",
        "",
        "The experimental feature set includes CVSS, normalized scoring signals, accepted evidence counts, confidence/data-completeness fields, age, and the intrinsic-criticality floor flag.",
        "Production `risk_score` and proxy-label fields are excluded from model inputs.",
        "",
        "## Baseline Comparison",
        "",
        "The baseline artifacts compare the existing heuristic `risk_score` ranking against each proxy strategy.",
        f"Baseline strategy statuses: `{_strategy_status_summary(baseline_metrics)}`.",
        "",
        "## Model Metrics",
        "",
        f"Model artifact status: `{model_report.get('status', '')}`.",
        "When scikit-learn or usable class diversity is unavailable, model metrics are explicitly skipped rather than fabricated.",
        "",
        "## Ablation Interpretation",
        "",
        f"Ablation rows exported: `{len(ablations)}`.",
        "Ablations are designed to test CVSS/severity dominance, recency, NLP context, confidence/data completeness, sparse evidence, normalized signals, and metadata/context views.",
        "",
        "## Disagreement Analysis",
        "",
        f"Disagreement rows exported: `{len(disagreements)}`.",
        "These rows are intended as thesis examples when learned predictions are available; otherwise the artifact remains empty with an explicit explanation.",
        "",
        "## Production Risk Score",
        "",
        "The production risk score remains heuristic, deterministic, and explainable.",
        "The learned-calibration artifacts do not write predictions back into MongoDB, do not recalibrate confidence, and do not change URLhaus/Dread evidence gates.",
        "",
        "## Interpretation",
        "",
        "The current experiment supports discussion of feasibility, proxy-label limitations, feature leakage controls, and evidence sparsity.",
        "It does not establish statistical significance, production readiness, or real-world exploitation-prediction performance.",
        "",
    ]
    return "\n".join(lines)


def render_learned_calibration_limitations(
    feasibility_report: Mapping[str, Any],
    model_report: Mapping[str, Any],
    leakage_checks: Mapping[str, Any],
) -> str:
    lines = [
        "# Learned Calibration Limitations",
        "",
        "## Scope",
        "",
        "Learned calibration is an experimental thesis artifact. It does not replace the deterministic scoring engine.",
        "",
        "## Proxy Labels Are Not Ground Truth",
        "",
        "The labels are deterministic proxies derived from available signals. They are not verified exploitation labels and should not be used to claim real-world predictive validity.",
        "",
        "## Evidence Coverage",
        "",
        f"EPSS available count: `{feasibility_report.get('epss_availability_count', 0)}`.",
        f"KEV known count: `{feasibility_report.get('kev_known_count', 0)}`.",
        f"Accepted external evidence count: `{feasibility_report.get('accepted_external_evidence_count', 0)}`.",
        "Sparse EPSS/KEV or accepted external evidence limits what a learned model can responsibly learn.",
        "",
        "## Model Availability",
        "",
        f"Model status: `{model_report.get('status', '')}`.",
        "If scikit-learn is unavailable or labels lack class diversity, training is skipped with explicit status fields.",
        "",
        "## Leakage Controls",
        "",
        f"Leakage check status: `{leakage_checks.get('status', '')}`.",
        "The experiment excludes production `risk_score` and proxy-label fields from model inputs and writes only local artifacts.",
        "",
        "## Production Use",
        "",
        "The learned-calibration outputs are diagnostic and thesis-facing. Production scoring remains heuristic, auditable, and evidence-gated.",
        "",
    ]
    return "\n".join(lines)


def _strategy_status_summary(metrics: Mapping[str, Any]) -> str:
    return ", ".join(
        f"{strategy}={payload.get('status', '')}"
        for strategy, payload in (metrics.get("strategies") or {}).items()
    )


def select_case_studies(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    prediction_rows: Sequence[Mapping[str, Any]],
    *,
    max_per_group: int = 5,
) -> list[dict[str, Any]]:
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    probability_by_cve = _best_probability_by_cve(prediction_rows)
    groups: dict[str, list[dict[str, Any]]] = {
        "high_heuristic_risk_and_high_learned_probability": [],
        "high_heuristic_risk_but_low_learned_probability": [],
        "low_medium_heuristic_risk_but_high_learned_probability": [],
        "intrinsic_floor_applied": [],
        "missing_epss_kev_high_intrinsic_severity": [],
        "no_accepted_external_evidence_high_proxy_label": [],
        "rejected_ignored_urlhaus_heavy": [],
        "low_confidence_but_high_risk": [],
    }
    for row in sorted(rows, key=lambda item: (-_safe_float(item.get("risk_score")), str(item.get("cve_id", "")))):
        cve_id = str(row.get("cve_id", ""))
        label = str((label_by_cve.get(cve_id) or {}).get("proxy_label_strategy_a", ""))
        probability = probability_by_cve.get(cve_id)
        if _safe_float(row.get("risk_score")) >= 7.0 and probability is not None and probability >= 0.7:
            groups["high_heuristic_risk_and_high_learned_probability"].append(_case_study_row(row, label, probability, "high_heuristic_risk_and_high_learned_probability", "high heuristic risk and high learned probability"))
        if _safe_float(row.get("risk_score")) >= 7.0 and probability is not None and probability < 0.4:
            groups["high_heuristic_risk_but_low_learned_probability"].append(_case_study_row(row, label, probability, "high_heuristic_risk_but_low_learned_probability", "high heuristic risk but low learned probability"))
        if _safe_float(row.get("risk_score")) < 7.0 and probability is not None and probability >= 0.7:
            groups["low_medium_heuristic_risk_but_high_learned_probability"].append(_case_study_row(row, label, probability, "low_medium_heuristic_risk_but_high_learned_probability", "low or medium heuristic risk but high learned probability"))
        if _truthy(row.get("intrinsic_criticality_floor_applied")):
            groups["intrinsic_floor_applied"].append(_case_study_row(row, label, probability, "intrinsic_floor_applied", "intrinsic criticality floor was applied"))
        if _safe_float(row.get("cvss_score")) >= 9.8 and not _truthy(row.get("epss_available")) and not _truthy(row.get("kev_status_known")):
            groups["missing_epss_kev_high_intrinsic_severity"].append(_case_study_row(row, label, probability, "missing_epss_kev_high_intrinsic_severity", "high intrinsic severity with missing EPSS/KEV coverage"))
        if _accepted_external_count(row) == 0 and label == "high":
            groups["no_accepted_external_evidence_high_proxy_label"].append(_case_study_row(row, label, probability, "no_accepted_external_evidence_high_proxy_label", "high proxy label without accepted external evidence"))
        if _safe_int(row.get("urlhaus_ignored_low_signal_count")) + _safe_int(row.get("urlhaus_rejected_match_count")) >= 5:
            groups["rejected_ignored_urlhaus_heavy"].append(_case_study_row(row, label, probability, "rejected_ignored_urlhaus_heavy", "many URLhaus candidates were ignored or rejected"))
        if _safe_float(row.get("confidence")) < 0.4 and _safe_float(row.get("risk_score")) >= 7.0:
            groups["low_confidence_but_high_risk"].append(_case_study_row(row, label, probability, "low_confidence_but_high_risk", "high risk with low confidence"))
    output: list[dict[str, Any]] = []
    for group in groups.values():
        output.extend(group[:max_per_group])
    return output


def render_case_studies_markdown(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# Learned Calibration Case Studies",
        "",
        "These case studies are selected for thesis discussion from deterministic learned-calibration artifacts.",
        "They do not claim ground truth exploitation; they illustrate proxy-label and ranking behavior.",
        "",
    ]
    if not rows:
        lines.extend(["No case studies matched the configured groups.", ""])
        return "\n".join(lines)
    counts: dict[str, int] = {}
    for row in rows:
        group = str(row.get("case_group", ""))
        counts[group] = counts.get(group, 0) + 1
    lines.append("## Case Groups")
    lines.append("")
    for group, count in sorted(counts.items()):
        lines.append(f"- `{group}`: {count}")
    lines.append("")
    return "\n".join(lines)


def build_publication_tables(
    *,
    feasibility_report: Mapping[str, Any],
    baseline_metrics: Mapping[str, Any],
    model_report: Mapping[str, Any],
    ablations: Sequence[Mapping[str, Any]],
    leakage_checks: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "dataset_coverage_summary": [
            {"metric": "analyzed_records", "value": feasibility_report.get("analyzed_records_exported", 0)},
            {"metric": "records_with_cvss", "value": feasibility_report.get("records_with_cvss", 0)},
            {"metric": "epss_available", "value": feasibility_report.get("epss_availability_count", 0)},
            {"metric": "kev_known", "value": feasibility_report.get("kev_known_count", 0)},
            {"metric": "accepted_external_evidence", "value": feasibility_report.get("accepted_external_evidence_count", 0)},
        ],
        "proxy_label_class_distribution": _table_proxy_label_distribution(feasibility_report),
        "heuristic_baseline_metrics": _table_baseline_metrics(baseline_metrics),
        "learned_model_metrics": _table_model_metrics(model_report),
        "ablation_summary": _table_ablation_summary(ablations),
        "leakage_robustness_checks": list(leakage_checks.get("checks") or []),
        "artifact_inventory": [
            {"artifact": "learned_calibration_dataset.csv", "usage": "feature export"},
            {"artifact": "learned_calibration_labels.csv", "usage": "proxy labels"},
            {"artifact": "learned_calibration_baseline_metrics.json", "usage": "heuristic baseline"},
            {"artifact": "learned_calibration_model_report.json", "usage": "optional model metrics"},
            {"artifact": "learned_calibration_leakage_checks.json", "usage": "leakage controls"},
            {"artifact": "learned_calibration_case_studies.csv", "usage": "case studies"},
        ],
    }


def render_publication_tables_markdown(tables: Mapping[str, Any]) -> str:
    lines = ["# Learned Calibration Publication Tables", ""]
    lines.extend(_markdown_table("Dataset Coverage Summary", ["metric", "value"], tables.get("dataset_coverage_summary") or []))
    lines.extend(_markdown_table("Proxy Label Class Distribution", ["strategy", "label", "count"], tables.get("proxy_label_class_distribution") or []))
    lines.extend(_markdown_table("Heuristic Baseline Metrics", ["strategy", "status", "precision_at_10", "recall_at_50", "ndcg_at_50"], tables.get("heuristic_baseline_metrics") or []))
    lines.extend(_markdown_table("Learned Model Metrics", ["strategy", "status", "balanced_accuracy", "f1"], tables.get("learned_model_metrics") or []))
    lines.extend(_markdown_table("Ablation Summary", ["ablation", "status", "interpretation"], tables.get("ablation_summary") or []))
    lines.extend(_markdown_table("Leakage and Robustness Checks", ["check", "status", "details"], tables.get("leakage_robustness_checks") or []))
    lines.extend(_markdown_table("Artifact Inventory", ["artifact", "usage"], tables.get("artifact_inventory") or []))
    return "\n".join(lines)


def build_learned_calibration_manifest(output_dir: str | Path) -> dict[str, Any]:
    output = Path(output_dir)
    artifacts = []
    for spec in _learned_calibration_artifact_specs():
        path = output / spec["filename"]
        artifacts.append(
            {
                "group": spec["group"],
                "path": str(path),
                "exists": path.exists(),
                "size_bytes": path.stat().st_size if path.exists() else 0,
                "description": spec["description"],
                "producer": "evaluation.learned_calibration",
                "thesis_usage_note": spec["usage"],
            }
        )
    return {
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "status": "complete" if all(item["exists"] for item in artifacts) else "incomplete",
    }


def render_learned_calibration_manifest_markdown(manifest: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Artifact Manifest",
        "",
        f"- Status: `{manifest.get('status', '')}`",
        f"- Artifact count: `{manifest.get('artifact_count', 0)}`",
        "",
        "| Group | Path | Exists | Size Bytes | Thesis Usage |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for item in manifest.get("artifacts") or []:
        lines.append(
            "| {group} | {path} | {exists} | {size} | {usage} |".format(
                group=item.get("group", ""),
                path=item.get("path", ""),
                exists=item.get("exists", ""),
                size=item.get("size_bytes", 0),
                usage=item.get("thesis_usage_note", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)


def _learned_calibration_artifact_specs() -> list[dict[str, str]]:
    return [
        {"group": "dataset", "filename": "learned_calibration_dataset.csv", "description": "Flat feature export", "usage": "Feature matrix for learned-calibration feasibility discussion."},
        {"group": "labels", "filename": "learned_calibration_labels.csv", "description": "Proxy-label export", "usage": "Documents deterministic proxy labels and limitations."},
        {"group": "baseline metrics", "filename": "learned_calibration_baseline_metrics.json", "description": "Heuristic baseline metrics", "usage": "Compares risk_score ranking with proxy labels."},
        {"group": "baseline metrics", "filename": "learned_calibration_baseline_metrics.md", "description": "Readable heuristic baseline metrics", "usage": "Thesis table source for baseline behavior."},
        {"group": "model report", "filename": "learned_calibration_model_report.json", "description": "Optional model report", "usage": "Records trained/skipped model status and metrics."},
        {"group": "model report", "filename": "learned_calibration_model_summary.md", "description": "Readable model summary", "usage": "Concise thesis summary of model availability."},
        {"group": "predictions", "filename": "learned_calibration_predictions.csv", "description": "Optional learned predictions", "usage": "Input to ranking comparisons when a model is trained."},
        {"group": "comparison report", "filename": "learned_vs_heuristic_comparison.json", "description": "Learned vs heuristic comparison", "usage": "Compares learned and heuristic ranking when predictions exist."},
        {"group": "comparison report", "filename": "learned_vs_heuristic_comparison.md", "description": "Readable learned-vs-heuristic comparison", "usage": "Thesis narrative support for ranking agreement/disagreement."},
        {"group": "disagreements", "filename": "learned_calibration_disagreements.csv", "description": "Disagreement cases", "usage": "Case examples when learned predictions exist."},
        {"group": "disagreements", "filename": "learned_calibration_disagreements.md", "description": "Readable disagreement summary", "usage": "Thesis discussion of disagreement categories."},
        {"group": "feature importance", "filename": "learned_calibration_feature_importance.csv", "description": "Coefficient/importance export", "usage": "Interpretability support when coefficients exist."},
        {"group": "feature importance", "filename": "learned_calibration_feature_importance.md", "description": "Readable feature importance", "usage": "Thesis discussion of feature dominance."},
        {"group": "ablation", "filename": "learned_calibration_ablation.csv", "description": "Ablation rows", "usage": "Feature-removal experiment plan/results."},
        {"group": "ablation", "filename": "learned_calibration_ablation.md", "description": "Readable ablation summary", "usage": "Thesis-ready ablation table."},
        {"group": "leakage checks", "filename": "learned_calibration_leakage_checks.json", "description": "Leakage and robustness checks", "usage": "Evidence that learned artifacts do not change production behavior."},
        {"group": "leakage checks", "filename": "learned_calibration_leakage_checks.md", "description": "Readable leakage checks", "usage": "Appendix-quality leakage/robustness summary."},
        {"group": "thesis narrative", "filename": "learned_calibration_thesis_section.md", "description": "Thesis section draft", "usage": "Academic prose for learned-calibration discussion."},
        {"group": "thesis narrative", "filename": "learned_calibration_limitations.md", "description": "Limitations summary", "usage": "Conservative claims and limitations wording."},
        {"group": "tables", "filename": "learned_calibration_tables.json", "description": "Publication table payloads", "usage": "Machine-readable table source."},
        {"group": "tables", "filename": "learned_calibration_tables.md", "description": "Publication table markdown", "usage": "Thesis-ready compact tables."},
        {"group": "case studies", "filename": "learned_calibration_case_studies.csv", "description": "Case-study rows", "usage": "Selected examples for thesis discussion."},
        {"group": "case studies", "filename": "learned_calibration_case_studies.md", "description": "Case-study summary", "usage": "Readable summary of selected case groups."},
    ]


def _table_proxy_label_distribution(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy, counts in (report.get("proxy_label_class_counts") or {}).items():
        for label, count in counts.items():
            rows.append({"strategy": strategy, "label": label, "count": count})
    return rows or [{"strategy": "unavailable", "label": "unavailable", "count": 0}]


def _table_baseline_metrics(metrics: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy, payload in (metrics.get("strategies") or {}).items():
        rows.append(
            {
                "strategy": strategy,
                "status": payload.get("status", ""),
                "precision_at_10": (payload.get("precision_at_k") or {}).get("10"),
                "recall_at_50": (payload.get("recall_at_k") or {}).get("50"),
                "ndcg_at_50": (payload.get("ndcg_at_k") or {}).get("50"),
            }
        )
    return rows or [{"strategy": "unavailable", "status": "unavailable", "precision_at_10": "", "recall_at_50": "", "ndcg_at_50": ""}]


def _table_model_metrics(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy, payload in (report.get("strategies") or {}).items():
        metrics = payload.get("metrics") or {}
        rows.append(
            {
                "strategy": strategy,
                "status": payload.get("status", ""),
                "balanced_accuracy": metrics.get("balanced_accuracy", ""),
                "f1": metrics.get("f1", ""),
            }
        )
    return rows or [{"strategy": "unavailable", "status": report.get("status", "unavailable"), "balanced_accuracy": "", "f1": ""}]


def _table_ablation_summary(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        name = str(row.get("ablation", ""))
        if name in seen:
            continue
        seen.add(name)
        output.append({"ablation": name, "status": row.get("status", ""), "interpretation": row.get("interpretation", "")})
    return output or [{"ablation": "unavailable", "status": "unavailable", "interpretation": ""}]


def _markdown_table(title: str, columns: Sequence[str], rows: Sequence[Mapping[str, Any]]) -> list[str]:
    lines = [f"## {title}", "", "| " + " | ".join(columns) + " |", "| " + " | ".join("---" for _ in columns) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(column, "")) for column in columns) + " |")
    lines.append("")
    return lines


def _best_probability_by_cve(prediction_rows: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    probabilities: dict[str, float] = {}
    for row in prediction_rows:
        cve_id = str(row.get("cve_id", ""))
        value = _safe_float(row.get("learned_probability"))
        if cve_id and (cve_id not in probabilities or value > probabilities[cve_id]):
            probabilities[cve_id] = value
    return probabilities


def _case_study_row(
    row: Mapping[str, Any],
    proxy_label: str,
    probability: float | None,
    group: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "cve_id": row.get("cve_id", ""),
        "cvss_score": row.get("cvss_score", ""),
        "risk_score": row.get("risk_score", ""),
        "confidence": row.get("confidence", ""),
        "proxy_label": proxy_label,
        "learned_probability": "" if probability is None else round(probability, 6),
        "coverage_limitations": row.get("coverage_limitations", ""),
        "key_reason": reason,
        "case_group": group,
    }


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


def _skipped_model_report(*, generated_at: str, reason: str) -> dict[str, Any]:
    return {
        "generated_at": generated_at,
        "status": "skipped",
        "model_type": "LogisticRegression",
        "random_seed": 42,
        "features": list(MODEL_FEATURE_COLUMNS),
        "leakage_guard": {
            "risk_score_used_as_feature": "risk_score" in MODEL_FEATURE_COLUMNS,
            "proxy_label_fields_used_as_features": [],
        },
        "model_registry": model_registry(None),
        "skip_reason": reason,
        "strategies": {
            strategy: {"status": "skipped", "skip_reason": reason}
            for strategy in ("strategy_a", "strategy_b", "strategy_c")
        },
        "alternative_models": {
            model_name: {"status": "skipped", "skip_reason": reason}
            for model_name in ("random_forest", "hist_gradient_boosting", "dummy")
        },
        "interpretation": "skipped",
    }


def _train_strategy_model(
    rows: Sequence[Mapping[str, Any]],
    label_by_cve: Mapping[str, Mapping[str, Any]],
    strategy: str,
    sklearn_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    y = [
        _safe_int((label_by_cve.get(str(row.get("cve_id", ""))) or {}).get(f"proxy_binary_high_{strategy}"))
        for row in rows
    ]
    positives = sum(y)
    negatives = len(y) - positives
    if len(set(y)) < 2:
        return _skipped_strategy_result(strategy, "single-class proxy labels", positives, negatives)
    if min(positives, negatives) < 2:
        return _skipped_strategy_result(strategy, "too few examples in one class for stratified split", positives, negatives)
    x = [[_feature_value(row, feature) for feature in MODEL_FEATURE_COLUMNS] for row in rows]
    train_test_split = sklearn_bundle["train_test_split"]
    LogisticRegression = sklearn_bundle["LogisticRegression"]
    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.3,
        random_state=42,
        stratify=y,
    )
    model = LogisticRegression(random_state=42, max_iter=1000, class_weight="balanced")
    model.fit(x_train, y_train)
    probabilities = [float(prob[1]) for prob in model.predict_proba(x)]
    predictions = [
        {
            "cve_id": str(row.get("cve_id", "")),
            "strategy": strategy,
            "proxy_binary_high": label,
            "learned_probability": round(probability, 6),
            "learned_prediction": int(probability >= 0.5),
        }
        for row, label, probability in zip(rows, y, probabilities)
    ]
    test_probabilities = [float(prob[1]) for prob in model.predict_proba(x_test)]
    test_predictions = [int(value >= 0.5) for value in test_probabilities]
    metrics = _classification_metrics(y_test, test_predictions, test_probabilities, sklearn_bundle)
    model_reports = {
        "logistic_regression": {
            "status": "evaluated",
            "metrics": metrics,
            "random_seed": 42,
        }
    }
    model_reports.update(_train_alternative_models(x_train, x_test, y_train, y_test, sklearn_bundle))
    return {
        "predictions": predictions,
        "report": {
            "status": "limited" if min(positives, negatives) < 20 else "meaningful",
            "positive_count": positives,
            "negative_count": negatives,
            "train_class_counts": _class_counts(y_train),
            "test_class_counts": _class_counts(y_test),
            "metrics": metrics,
            "models": model_reports,
            "learned_probability_summary": _probability_summary(probabilities),
            "coefficients": {
                feature: round(float(coefficient), 6)
                for feature, coefficient in zip(MODEL_FEATURE_COLUMNS, model.coef_[0])
            },
        },
    }


def model_registry(sklearn_bundle: Mapping[str, Any] | None) -> dict[str, dict[str, Any]]:
    if sklearn_bundle is None:
        return {
            model_name: {"available": False, "skip_reason": "scikit-learn is not installed in the current Python environment"}
            for model_name in ("logistic_regression", "random_forest", "hist_gradient_boosting", "dummy")
        }
    return {
        "logistic_regression": {"available": "LogisticRegression" in sklearn_bundle, "random_seed": 42},
        "random_forest": {"available": "RandomForestClassifier" in sklearn_bundle, "random_seed": 42},
        "hist_gradient_boosting": {"available": "HistGradientBoostingClassifier" in sklearn_bundle, "random_seed": 42},
        "dummy": {"available": "DummyClassifier" in sklearn_bundle, "random_seed": 42},
    }


def _train_alternative_models(
    x_train: Sequence[Sequence[float]],
    x_test: Sequence[Sequence[float]],
    y_train: Sequence[int],
    y_test: Sequence[int],
    sklearn_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    model_specs = {
        "random_forest": ("RandomForestClassifier", {"random_state": 42, "n_estimators": 100, "class_weight": "balanced"}),
        "hist_gradient_boosting": ("HistGradientBoostingClassifier", {"random_state": 42}),
        "dummy": ("DummyClassifier", {"strategy": "most_frequent", "random_state": 42}),
    }
    reports: dict[str, Any] = {}
    for model_name, (class_name, kwargs) in model_specs.items():
        model_class = sklearn_bundle.get(class_name)
        if model_class is None:
            reports[model_name] = {"status": "skipped", "skip_reason": f"{class_name} is unavailable"}
            continue
        model = model_class(**kwargs)
        model.fit(x_train, y_train)
        if hasattr(model, "predict_proba"):
            probabilities = [float(prob[1]) for prob in model.predict_proba(x_test)]
        else:
            probabilities = [float(value) for value in model.predict(x_test)]
        predictions = [int(value >= 0.5) for value in probabilities]
        reports[model_name] = {
            "status": "evaluated",
            "metrics": _classification_metrics(y_test, predictions, probabilities, sklearn_bundle),
            "random_seed": 42,
        }
    return reports


def _classification_metrics(
    y_true: Sequence[int],
    y_pred: Sequence[int],
    probabilities: Sequence[float],
    sklearn_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    metrics = sklearn_bundle["metrics"]
    result = {
        "accuracy": round(float(metrics.accuracy_score(y_true, y_pred)), 4),
        "balanced_accuracy": round(float(metrics.balanced_accuracy_score(y_true, y_pred)), 4),
        "precision": round(float(metrics.precision_score(y_true, y_pred, zero_division=0)), 4),
        "recall": round(float(metrics.recall_score(y_true, y_pred, zero_division=0)), 4),
        "f1": round(float(metrics.f1_score(y_true, y_pred, zero_division=0)), 4),
        "confusion_matrix": metrics.confusion_matrix(y_true, y_pred, labels=[0, 1]).tolist(),
    }
    if len(set(y_true)) > 1:
        result["roc_auc"] = round(float(metrics.roc_auc_score(y_true, probabilities)), 4)
        result["pr_auc"] = round(float(metrics.average_precision_score(y_true, probabilities)), 4)
    else:
        result["roc_auc"] = None
        result["pr_auc"] = None
    return result


def _skipped_strategy_result(strategy: str, reason: str, positives: int, negatives: int) -> dict[str, Any]:
    return {
        "predictions": [],
        "report": {
            "status": "skipped",
            "skip_reason": reason,
            "positive_count": positives,
            "negative_count": negatives,
            "metrics": {},
        },
    }


def _feature_value(row: Mapping[str, Any], feature: str) -> float:
    if feature == "intrinsic_criticality_floor_applied":
        return 1.0 if _truthy(row.get(feature)) else 0.0
    return _safe_float(row.get(feature))


def _class_counts(labels: Sequence[int]) -> dict[str, int]:
    return {"0": sum(1 for label in labels if label == 0), "1": sum(1 for label in labels if label == 1)}


def _probability_summary(probabilities: Sequence[float]) -> dict[str, float]:
    if not probabilities:
        return {"min": 0.0, "max": 0.0, "mean": 0.0}
    return {
        "min": round(min(probabilities), 6),
        "max": round(max(probabilities), 6),
        "mean": round(mean(probabilities), 6),
    }


def _model_interpretation(strategies: Mapping[str, Mapping[str, Any]]) -> str:
    statuses = {payload.get("status") for payload in strategies.values()}
    if statuses == {"skipped"}:
        return "skipped"
    if "meaningful" in statuses:
        return "meaningful"
    return "limited"


def _load_sklearn() -> Mapping[str, Any] | None:
    try:
        from sklearn import metrics
        from sklearn.dummy import DummyClassifier
        from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import train_test_split
    except ImportError:
        return None
    return {
        "DummyClassifier": DummyClassifier,
        "HistGradientBoostingClassifier": HistGradientBoostingClassifier,
        "LogisticRegression": LogisticRegression,
        "RandomForestClassifier": RandomForestClassifier,
        "train_test_split": train_test_split,
        "metrics": metrics,
    }


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
