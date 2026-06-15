from __future__ import annotations

import argparse
import csv
import json
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
    warnings = _coverage_warnings(
        analyzed=analyzed,
        epss_count=epss_count,
        kev_known_count=kev_known_count,
        accepted_external_count=urlhaus_accepted + dread_accepted,
    )
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
        "",
        "## Feasibility",
        "",
        f"- Proxy-supervised learning feasibility: `{label}`",
        "",
        "The current data is suitable for proxy-supervised learning only if feature coverage and externally defensible proxy labels are adequate. Weak EPSS, KEV, or external-evidence coverage limits what can be learned responsibly.",
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
    report_path = output / "learned_calibration_report.json"
    summary_path = output / "learned_calibration_summary.md"
    with dataset_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DATASET_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in DATASET_COLUMNS})
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
    summary_path.write_text(render_summary_markdown(report), encoding="utf-8")
    return {
        "dataset": str(dataset_path),
        "report": str(report_path),
        "summary": str(summary_path),
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
