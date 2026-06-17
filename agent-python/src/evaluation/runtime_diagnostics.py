from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Mapping, Sequence

from core.database import DatabaseManager


RISK_BUCKETS = (0, 2, 4, 6, 8, 10, 11)
CONFIDENCE_BUCKETS = (0, 0.35, 0.5, 0.65, 0.8, 1.1)


def build_runtime_diagnostics(
    *,
    cve_docs: Sequence[Mapping[str, Any]],
    urlhaus_docs: Sequence[Mapping[str, Any]] = (),
    dread_docs: Sequence[Mapping[str, Any]] = (),
    generated_at: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    analyzed = [doc for doc in cve_docs if _get_nested(doc, "analysis.risk_score") is not None]
    risk_scores = [_safe_float(_get_nested(doc, "analysis.risk_score")) for doc in analyzed]
    confidences = [_safe_float(_get_nested(doc, "analysis.confidence")) for doc in analyzed]
    risk_levels = Counter(str(_get_nested(doc, "analysis.risk_level", "UNKNOWN")) for doc in analyzed)

    urlhaus_stats = [_get_nested(doc, "analysis.evidence.urlhaus_match_stats", {}) or {} for doc in analyzed]
    dread_stats = [_get_nested(doc, "analysis.evidence.dread_match_stats", {}) or {} for doc in analyzed]
    confidence_breakdowns = [_get_nested(doc, "analysis.confidence_breakdown", {}) or {} for doc in analyzed]
    epss_available = sum(1 for doc in analyzed if _get_nested(doc, "analysis.evidence.epss_available") is True)
    kev_known = sum(1 for doc in analyzed if _get_nested(doc, "analysis.evidence.kev_status_known") is True)
    kev_listed = sum(1 for doc in analyzed if _get_nested(doc, "analysis.evidence.kev_listed") is True)

    confidence_component_averages = _average_numeric_components(confidence_breakdowns)
    urlhaus_diagnostics = {
        "raw_candidate_count": _sum_stat(urlhaus_stats, "raw_candidate_count", fallback_key="candidate_count"),
        "ignored_low_signal_count": _sum_stat(urlhaus_stats, "ignored_low_signal_count"),
        "evaluated_candidate_count": _sum_stat(urlhaus_stats, "evaluated_candidate_count"),
        "signal_candidate_count": _sum_stat(urlhaus_stats, "signal_candidate_count"),
        "accepted_match_count": _sum_stat(urlhaus_stats, "accepted_match_count"),
        "manual_review_match_count": _sum_stat(urlhaus_stats, "manual_review_match_count"),
        "rejected_match_count": _sum_stat(urlhaus_stats, "rejected_match_count"),
        "accepted_evidence_count": _sum_stat(urlhaus_stats, "accepted_evidence_count"),
        "manual_review_evidence_count": _sum_stat(urlhaus_stats, "manual_review_evidence_count"),
        "rejected_evidence_count": _sum_stat(urlhaus_stats, "rejected_evidence_count"),
        "status_distribution": _sum_counter_stat(urlhaus_stats, "status_distribution"),
        "reason_code_distribution": _sum_counter_stat(urlhaus_stats, "reason_code_distribution"),
        "accepted_reason_distribution": _sum_counter_stat(urlhaus_stats, "accepted_reason_distribution"),
        "manual_review_reason_distribution": _sum_counter_stat(urlhaus_stats, "manual_review_reason_distribution"),
        "rejection_reason_distribution": _sum_counter_stat(urlhaus_stats, "rejection_reason_distribution"),
        "ignored_reason_distribution": _sum_counter_stat(urlhaus_stats, "ignored_reason_distribution"),
    }
    dread_diagnostics = {
        "raw_candidate_count": _sum_stat(dread_stats, "raw_candidate_count", fallback_key="candidate_count"),
        "ignored_low_signal_count": _sum_stat(dread_stats, "ignored_low_signal_count"),
        "evaluated_candidate_count": _sum_stat(dread_stats, "evaluated_candidate_count"),
        "signal_candidate_count": _sum_stat(dread_stats, "signal_candidate_count"),
        "accepted_match_count": _sum_stat(dread_stats, "accepted_match_count"),
        "manual_review_match_count": _sum_stat(dread_stats, "manual_review_match_count"),
        "rejected_match_count": _sum_stat(dread_stats, "rejected_match_count"),
        "accepted_evidence_count": _sum_stat(dread_stats, "accepted_evidence_count"),
        "manual_review_evidence_count": _sum_stat(dread_stats, "manual_review_evidence_count"),
        "rejected_evidence_count": _sum_stat(dread_stats, "rejected_evidence_count"),
        "status_distribution": _sum_counter_stat(dread_stats, "status_distribution"),
        "reason_code_distribution": _sum_counter_stat(dread_stats, "reason_code_distribution"),
        "accepted_reason_distribution": _sum_counter_stat(dread_stats, "accepted_reason_distribution"),
        "manual_review_reason_distribution": _sum_counter_stat(dread_stats, "manual_review_reason_distribution"),
        "rejection_reason_distribution": _sum_counter_stat(dread_stats, "rejection_reason_distribution"),
        "ignored_reason_distribution": _sum_counter_stat(dread_stats, "ignored_reason_distribution"),
        "observed_dread_category_distribution": _list_value_distribution(dread_stats, "observed_dread_categories"),
        "accepted_dread_category_distribution": _list_value_distribution(dread_stats, "accepted_dread_categories"),
    }
    high_risk_low_confidence = sorted(
        [
            {
                "cve_id": str(_get_nested(doc, "analysis.entity_id", doc.get("_id"))),
                "risk_score": _safe_float(_get_nested(doc, "analysis.risk_score")),
                "risk_level": _get_nested(doc, "analysis.risk_level"),
                "confidence": _safe_float(_get_nested(doc, "analysis.confidence")),
                "cvss_score": _safe_float(_get_nested(doc, "analysis.evidence.cvss_score")),
                "coverage_limitations": list((_get_nested(doc, "analysis.confidence_breakdown.coverage_limitations", []) or [])[:8]),
                "ignored_urlhaus_candidates": int((_get_nested(doc, "analysis.evidence.urlhaus_match_stats.ignored_low_signal_count", 0) or 0)),
            }
            for doc in analyzed
            if _safe_float(_get_nested(doc, "analysis.risk_score")) >= 6.5
            and _safe_float(_get_nested(doc, "analysis.confidence")) < 0.65
        ],
        key=lambda item: (-item["risk_score"], item["confidence"], item["cve_id"]),
    )[:25]

    return {
        "generated_at": generated,
        "scope_note": "Live database diagnostics are an operational sanity check, not the deterministic thesis benchmark.",
        "processed_counts": {
            "cve_total": len(cve_docs),
            "cve_analyzed": len(analyzed),
            "urlhaus_total": len(urlhaus_docs),
            "urlhaus_processed": sum(1 for doc in urlhaus_docs if bool(doc.get("processed"))),
            "dread_total": len(dread_docs),
            "dread_processed": sum(1 for doc in dread_docs if bool(doc.get("processed"))),
        },
        "risk_distribution": {
            "average_risk_score": round(mean(risk_scores), 4) if risk_scores else 0.0,
            "risk_score_buckets": _bucket_counts(risk_scores, RISK_BUCKETS),
            "risk_level_distribution": dict(risk_levels),
        },
        "confidence_distribution": {
            "average_confidence": round(mean(confidences), 4) if confidences else 0.0,
            "confidence_buckets": _bucket_counts(confidences, CONFIDENCE_BUCKETS),
            "confidence_component_averages": confidence_component_averages,
        },
        "external_signal_coverage": {
            "epss_available_count": epss_available,
            "epss_missing_count": max(len(analyzed) - epss_available, 0),
            "kev_status_known_count": kev_known,
            "kev_status_unknown_count": max(len(analyzed) - kev_known, 0),
            "kev_listed_count": kev_listed,
        },
        "urlhaus_correlation_diagnostics": urlhaus_diagnostics,
        "dread_correlation_diagnostics": dread_diagnostics,
        "high_risk_low_confidence_cases": high_risk_low_confidence,
    }


def write_runtime_diagnostics(report: Mapping[str, Any], output_dir: str | Path) -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    paths = {
        "live_reanalysis_summary_json": output / "live_reanalysis_summary.json",
        "live_reanalysis_summary_md": output / "live_reanalysis_summary.md",
        "confidence_distribution": output / "confidence_distribution.json",
        "risk_distribution": output / "risk_distribution.json",
        "urlhaus_correlation_diagnostics": output / "urlhaus_correlation_diagnostics.json",
        "dread_correlation_diagnostics": output / "dread_correlation_diagnostics.json",
        "high_risk_low_confidence_cases": output / "high_risk_low_confidence_cases.json",
    }
    paths["live_reanalysis_summary_json"].write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    paths["live_reanalysis_summary_md"].write_text(render_runtime_summary_markdown(report), encoding="utf-8")
    paths["confidence_distribution"].write_text(json.dumps(report.get("confidence_distribution", {}), indent=2), encoding="utf-8")
    paths["risk_distribution"].write_text(json.dumps(report.get("risk_distribution", {}), indent=2), encoding="utf-8")
    paths["urlhaus_correlation_diagnostics"].write_text(json.dumps(report.get("urlhaus_correlation_diagnostics", {}), indent=2), encoding="utf-8")
    paths["dread_correlation_diagnostics"].write_text(json.dumps(report.get("dread_correlation_diagnostics", {}), indent=2), encoding="utf-8")
    paths["high_risk_low_confidence_cases"].write_text(json.dumps(report.get("high_risk_low_confidence_cases", []), indent=2, default=str), encoding="utf-8")
    return {key: str(value) for key, value in paths.items()}


def render_runtime_summary_markdown(report: Mapping[str, Any]) -> str:
    counts = report.get("processed_counts", {}) or {}
    coverage = report.get("external_signal_coverage", {}) or {}
    urlhaus = report.get("urlhaus_correlation_diagnostics", {}) or {}
    dread = report.get("dread_correlation_diagnostics", {}) or {}
    confidence = report.get("confidence_distribution", {}) or {}
    risk = report.get("risk_distribution", {}) or {}
    lines = [
        "# Live Reanalysis Runtime Diagnostics",
        "",
        f"Generated at: `{report.get('generated_at')}`",
        "",
        report.get("scope_note", "Live diagnostics are operational sanity checks, not a thesis benchmark."),
        "",
        "## Processed Counts",
        "",
        f"- CVE analyzed / total: `{counts.get('cve_analyzed', 0)}` / `{counts.get('cve_total', 0)}`",
        f"- URLhaus processed / total: `{counts.get('urlhaus_processed', 0)}` / `{counts.get('urlhaus_total', 0)}`",
        f"- Dread processed / total: `{counts.get('dread_processed', 0)}` / `{counts.get('dread_total', 0)}`",
        "",
        "## Risk and Confidence",
        "",
        f"- Average risk score: `{risk.get('average_risk_score', 0.0)}`",
        f"- Average confidence: `{confidence.get('average_confidence', 0.0)}`",
        "",
        "## EPSS / KEV Coverage",
        "",
        f"- EPSS available: `{coverage.get('epss_available_count', 0)}`",
        f"- EPSS missing: `{coverage.get('epss_missing_count', 0)}`",
        f"- KEV status known: `{coverage.get('kev_status_known_count', 0)}`",
        f"- KEV status unknown: `{coverage.get('kev_status_unknown_count', 0)}`",
        f"- KEV listed: `{coverage.get('kev_listed_count', 0)}`",
        "",
        "## URLhaus Candidate Accounting",
        "",
        f"- Raw candidates: `{urlhaus.get('raw_candidate_count', 0)}`",
        f"- Ignored low-signal candidates: `{urlhaus.get('ignored_low_signal_count', 0)}`",
        f"- Signal-bearing evaluated candidates: `{urlhaus.get('signal_candidate_count', 0)}`",
        f"- Accepted candidates: `{urlhaus.get('accepted_match_count', 0)}`",
        f"- Manual-review candidates: `{urlhaus.get('manual_review_match_count', 0)}`",
        f"- Rejected signal-bearing candidates: `{urlhaus.get('rejected_match_count', 0)}`",
        f"- Status distribution: `{_format_distribution(urlhaus.get('status_distribution'))}`",
        f"- Accepted reason codes: `{_format_distribution(urlhaus.get('accepted_reason_distribution'))}`",
        f"- Manual-review reason codes: `{_format_distribution(urlhaus.get('manual_review_reason_distribution'))}`",
        f"- Rejection reason codes: `{_format_distribution(urlhaus.get('rejection_reason_distribution'))}`",
        "",
        "Ignored low-signal candidates are raw retrieval noise, not rejected evidence. They do not increase correlation risk, confidence, or graph support.",
        "",
        "## Dread Candidate Accounting",
        "",
        f"- Raw candidates: `{dread.get('raw_candidate_count', 0)}`",
        f"- Accepted candidates: `{dread.get('accepted_match_count', 0)}`",
        f"- Manual-review candidates: `{dread.get('manual_review_match_count', 0)}`",
        f"- Rejected signal-bearing candidates: `{dread.get('rejected_match_count', 0)}`",
        f"- Status distribution: `{_format_distribution(dread.get('status_distribution'))}`",
        f"- Manual-review reason codes: `{_format_distribution(dread.get('manual_review_reason_distribution'))}`",
        f"- Rejection reason codes: `{_format_distribution(dread.get('rejection_reason_distribution'))}`",
        "",
        "Dread diagnostics are weak chatter / early-warning indicators only. Dread-only candidates remain outside accepted scoring evidence.",
        "",
        "## High-Risk Moderate/Low-Confidence Cases",
        "",
    ]
    cases = report.get("high_risk_low_confidence_cases") or []
    if not cases:
        lines.append("None.")
    else:
        for item in cases[:10]:
            lines.append(
                f"- `{item.get('cve_id')}` risk `{item.get('risk_score')}` / `{item.get('risk_level')}`, "
                f"confidence `{item.get('confidence')}`, coverage limitations `{', '.join(item.get('coverage_limitations') or [])}`"
            )
    lines.append("")
    return "\n".join(lines)


def load_runtime_documents(limit: int = 0) -> tuple[list[Mapping[str, Any]], list[Mapping[str, Any]], list[Mapping[str, Any]]]:
    db = DatabaseManager()
    return (
        list(db.collections["cve"].find({}).limit(limit if limit > 0 else 0)),
        list(db.collections["urlhaus"].find({}).limit(limit if limit > 0 else 0)),
        list(db.collections["dread"].find({}).limit(limit if limit > 0 else 0)),
    )


def _average_numeric_components(rows: Iterable[Mapping[str, Any]]) -> dict[str, float]:
    values: dict[str, list[float]] = {}
    for row in rows:
        for key, value in row.items():
            if isinstance(value, (int, float)):
                values.setdefault(key, []).append(float(value))
    return {key: round(mean(items), 4) for key, items in sorted(values.items()) if items}


def _sum_stat(rows: Iterable[Mapping[str, Any]], key: str, *, fallback_key: str | None = None) -> int:
    total = 0
    for row in rows:
        value = row.get(key)
        if value is None and fallback_key:
            value = row.get(fallback_key)
        total += int(value or 0)
    return total


def _sum_counter_stat(rows: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for row in rows:
        values = row.get(key) or {}
        if not isinstance(values, Mapping):
            continue
        for item_key, value in values.items():
            counter[str(item_key)] += int(value or 0)
    return dict(sorted((key, value) for key, value in counter.items() if value > 0))


def _list_value_distribution(rows: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for row in rows:
        values = row.get(key) or []
        if isinstance(values, str):
            values = [values]
        for value in values:
            if value not in (None, ""):
                counter[str(value)] += 1
    return dict(sorted(counter.items()))


def _format_distribution(values: Any) -> str:
    if not isinstance(values, Mapping) or not values:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in sorted(values.items()))


def _bucket_counts(values: Iterable[float], boundaries: Sequence[float]) -> dict[str, int]:
    buckets = {f"{boundaries[idx]}-{boundaries[idx + 1]}": 0 for idx in range(len(boundaries) - 1)}
    buckets["other"] = 0
    for value in values:
        placed = False
        for idx in range(len(boundaries) - 1):
            if boundaries[idx] <= value < boundaries[idx + 1]:
                buckets[f"{boundaries[idx]}-{boundaries[idx + 1]}"] += 1
                placed = True
                break
        if not placed:
            buckets["other"] += 1
    return buckets


def _get_nested(doc: Mapping[str, Any], path: str, default: Any = None) -> Any:
    current: Any = doc
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate read-only diagnostics from persisted live analysis results.")
    parser.add_argument("--output-dir", default="reports/runtime")
    parser.add_argument("--limit", type=int, default=0, help="Maximum documents per source to inspect. 0 means no limit.")
    args = parser.parse_args()
    cve_docs, urlhaus_docs, dread_docs = load_runtime_documents(limit=args.limit)
    report = build_runtime_diagnostics(cve_docs=cve_docs, urlhaus_docs=urlhaus_docs, dread_docs=dread_docs)
    paths = write_runtime_diagnostics(report, args.output_dir)
    print(json.dumps({"status": "written", "output_dir": args.output_dir, "files": paths}, indent=2))


if __name__ == "__main__":
    main()
