from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Dict, Iterable, List, Sequence

from core.database import DatabaseManager

RISK_BUCKETS = [0, 2, 4, 6, 8, 10, 11]
CONFIDENCE_BUCKETS = [0, 0.4, 0.6, 0.75, 0.9, 1.1]


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _get_nested(doc: Dict[str, Any], path: str, default: Any = None) -> Any:
    current: Any = doc
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def bucket_counts(values: Iterable[float], boundaries: Sequence[float]) -> Dict[str, int]:
    buckets = {f"{boundaries[idx]}-{boundaries[idx + 1]}": 0 for idx in range(len(boundaries) - 1)}
    buckets["other"] = 0
    for value in values:
        placed = False
        for idx in range(len(boundaries) - 1):
            low = boundaries[idx]
            high = boundaries[idx + 1]
            if low <= value < high:
                buckets[f"{low}-{high}"] += 1
                placed = True
                break
        if not placed:
            buckets["other"] += 1
    return buckets


def extract_cvss_from_doc(doc: Dict[str, Any]) -> float:
    analysis_cvss = _get_nested(doc, "analysis.evidence.cvss_score")
    if analysis_cvss is not None:
        return _safe_float(analysis_cvss)

    metric_containers = [doc.get("metrics") or {}, _get_nested(doc, "raw.metrics", {}) or {}]
    for metrics in metric_containers:
        for key in ("cvss_metric_v40", "cvssMetricV40", "cvss_metric_v31", "cvssMetricV31", "cvss_metric_v30", "cvssMetricV30", "cvss_metric_v2", "cvssMetricV2"):
            values = metrics.get(key) or []
            if values:
                cvss_data = values[0].get("cvss_data") or values[0].get("cvssData") or {}
                score = cvss_data.get("base_score", cvss_data.get("baseScore"))
                return _safe_float(score)
    return 0.0


def summarize_documents(docs: List[Dict[str, Any]]) -> Dict[str, Any]:
    analyzed = [doc for doc in docs if _get_nested(doc, "analysis.risk_score") is not None]
    risk_scores = [_safe_float(_get_nested(doc, "analysis.risk_score")) for doc in analyzed]
    confidences = [_safe_float(_get_nested(doc, "analysis.confidence")) for doc in analyzed]
    cvss_scores = [extract_cvss_from_doc(doc) for doc in analyzed]
    levels = Counter(str(_get_nested(doc, "analysis.risk_level", "UNKNOWN")) for doc in analyzed)

    high_cvss_suppressed = sorted(
        [
            {
                "id": str(doc.get("_id")),
                "cvss": extract_cvss_from_doc(doc),
                "risk_score": _safe_float(_get_nested(doc, "analysis.risk_score")),
                "risk_level": _get_nested(doc, "analysis.risk_level"),
                "age_penalty": _safe_float(_get_nested(doc, "analysis.feature_breakdown.age_penalty")),
                "confidence": _safe_float(_get_nested(doc, "analysis.confidence")),
            }
            for doc in analyzed
            if extract_cvss_from_doc(doc) >= 9.0 and _safe_float(_get_nested(doc, "analysis.risk_score")) < 6.5
        ],
        key=lambda item: (item["risk_score"], -item["cvss"]),
    )[:20]

    low_cvss_boosted = sorted(
        [
            {
                "id": str(doc.get("_id")),
                "cvss": extract_cvss_from_doc(doc),
                "risk_score": _safe_float(_get_nested(doc, "analysis.risk_score")),
                "risk_level": _get_nested(doc, "analysis.risk_level"),
                "active_threat_score": _safe_float(_get_nested(doc, "analysis.feature_breakdown.active_threat_score")),
                "confidence": _safe_float(_get_nested(doc, "analysis.confidence")),
            }
            for doc in analyzed
            if 0 < extract_cvss_from_doc(doc) <= 5.0 and _safe_float(_get_nested(doc, "analysis.risk_score")) >= 6.5
        ],
        key=lambda item: item["risk_score"],
        reverse=True,
    )[:20]

    accepted_urlhaus = sum(int(_get_nested(doc, "analysis.evidence.related_urlhaus_count", 0) or 0) for doc in analyzed)
    accepted_dread = sum(int(_get_nested(doc, "analysis.evidence.related_dread_count", 0) or 0) for doc in analyzed)

    confidence_component_keys = [
        "base_confidence",
        "metadata_confidence",
        "entity_confidence",
        "external_evidence_confidence",
        "correlation_confidence",
        "freshness_confidence",
        "penalties",
    ]
    confidence_breakdown_averages = {
        key: round(
            mean([_safe_float(_get_nested(doc, f"analysis.confidence_breakdown.{key}")) for doc in analyzed]),
            4,
        ) if analyzed else 0.0
        for key in confidence_component_keys
    }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_documents": len(docs),
        "analyzed_documents": len(analyzed),
        "analysis_coverage": round(len(analyzed) / max(len(docs), 1), 4),
        "risk_level_distribution": dict(levels),
        "risk_score_buckets": bucket_counts(risk_scores, RISK_BUCKETS),
        "confidence_buckets": bucket_counts(confidences, CONFIDENCE_BUCKETS),
        "cvss_buckets": bucket_counts(cvss_scores, RISK_BUCKETS),
        "average_risk_score": round(mean(risk_scores), 4) if risk_scores else 0.0,
        "average_confidence": round(mean(confidences), 4) if confidences else 0.0,
        "average_cvss": round(mean(cvss_scores), 4) if cvss_scores else 0.0,
        "accepted_urlhaus_evidence_total": accepted_urlhaus,
        "accepted_dread_evidence_total": accepted_dread,
        "confidence_breakdown_averages": confidence_breakdown_averages,
        "high_cvss_suppressed_examples": high_cvss_suppressed,
        "low_cvss_boosted_examples": low_cvss_boosted,
    }


def render_markdown(summary: Dict[str, Any], *, title: str) -> str:
    lines = [f"# {title}", ""]
    lines.append(f"Generated at: `{summary['generated_at']}`")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"- Total documents: `{summary['total_documents']}`")
    lines.append(f"- Analyzed documents: `{summary['analyzed_documents']}`")
    lines.append(f"- Analysis coverage: `{summary['analysis_coverage']}`")
    lines.append(f"- Average CVSS: `{summary['average_cvss']}`")
    lines.append(f"- Average risk score: `{summary['average_risk_score']}`")
    lines.append(f"- Average confidence: `{summary['average_confidence']}`")
    lines.append("")
    for section, key in [
        ("Risk level distribution", "risk_level_distribution"),
        ("Risk score buckets", "risk_score_buckets"),
        ("Confidence buckets", "confidence_buckets"),
        ("CVSS buckets", "cvss_buckets"),
    ]:
        lines.append(f"## {section}")
        lines.append("")
        for name, count in summary[key].items():
            lines.append(f"- `{name}`: `{count}`")
        lines.append("")

    lines.append("## Evidence totals")
    lines.append("")
    lines.append(f"- Accepted URLhaus evidence: `{summary['accepted_urlhaus_evidence_total']}`")
    lines.append(f"- Accepted Dread evidence: `{summary['accepted_dread_evidence_total']}`")
    lines.append("")

    lines.append("## Confidence breakdown averages")
    lines.append("")
    breakdown = summary.get("confidence_breakdown_averages") or {}
    if not breakdown:
        lines.append("No confidence breakdown data found.")
    else:
        for name, value in breakdown.items():
            lines.append(f"- `{name}`: `{value}`")
    lines.append("")

    lines.append("## High-CVSS suppressed examples")
    lines.append("")
    if not summary["high_cvss_suppressed_examples"]:
        lines.append("None.")
    else:
        for item in summary["high_cvss_suppressed_examples"][:10]:
            lines.append(f"- `{item['id']}` CVSS `{item['cvss']}` → risk `{item['risk_score']}` / `{item['risk_level']}`, confidence `{item['confidence']}`, age penalty `{item['age_penalty']}`")
    lines.append("")

    lines.append("## Low-CVSS boosted examples")
    lines.append("")
    if not summary["low_cvss_boosted_examples"]:
        lines.append("None.")
    else:
        for item in summary["low_cvss_boosted_examples"][:10]:
            lines.append(f"- `{item['id']}` CVSS `{item['cvss']}` → risk `{item['risk_score']}` / `{item['risk_level']}`, active threat `{item['active_threat_score']}`, confidence `{item['confidence']}`")
    lines.append("")
    return "\n".join(lines)


def load_docs(source: str, limit: int) -> List[Dict[str, Any]]:
    db = DatabaseManager()
    cursor = db.collections[source].find({}).limit(limit if limit > 0 else 0)
    return list(cursor)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate risk model diagnostics from MongoDB analysis results.")
    parser.add_argument("--source", choices=["cve", "urlhaus", "dread"], default="cve")
    parser.add_argument("--limit", type=int, default=0, help="Maximum documents to inspect. 0 means no limit.")
    parser.add_argument("--output-dir", default="report_outputs")
    parser.add_argument("--suffix", default="current")
    args = parser.parse_args()

    docs = load_docs(args.source, args.limit)
    summary = summarize_documents(docs)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / f"model_diagnostics_{args.source}_{args.suffix}.json"
    md_path = output_dir / f"model_diagnostics_{args.source}_{args.suffix}.md"
    json_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    md_path.write_text(render_markdown(summary, title=f"Model Diagnostics: {args.source.upper()} ({args.suffix})"), encoding="utf-8")
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")


if __name__ == "__main__":
    main()
