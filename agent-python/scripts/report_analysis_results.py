#!/usr/bin/env python3
"""Read-only analysis audit for the threat-intelligence MongoDB.

Produces corpus-level JSON/CSV reports without recalculating scores or mutating data.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import sys
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from bson import ObjectId
from pymongo import MongoClient

AGENT_PYTHON_ROOT = Path(__file__).resolve().parents[1]
SRC_PATH = AGENT_PYTHON_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from config import DB_NAME, MONGO_URI, get_settings  # noqa: E402


SETTINGS = get_settings()
SOURCE_COLLECTIONS = {
    "cve": "cve_intel",
    "urlhaus": "urlhaus_intel",
    "dread": "dread_intel",
}

PROJECTION = {
    "_id": 1,
    "processed": 1,
    "published": 1,
    "last_modified": 1,
    "lastModified": 1,
    "urlhaus_id": 1,
    "url": 1,
    "title": 1,
    "threat": 1,
    "url_status": 1,
    "date_added": 1,
    "category": 1,
    "job_lifecycle.state": 1,
    "job_lifecycle.attempt_count": 1,
    "job_lifecycle.analysis_version": 1,
    "job_lifecycle.started_at": 1,
    "job_lifecycle.completed_at": 1,
    "job_lifecycle.last_error": 1,
    "analysis_history": 1,
    "analysis.entity_type": 1,
    "analysis.entity_id": 1,
    "analysis.risk_score": 1,
    "analysis.risk_level": 1,
    "analysis.confidence": 1,
    "analysis.diagnosis": 1,
    "analysis.analyzed_at": 1,
    "analysis.pipeline_version": 1,
    "analysis.recommendations": 1,
    "analysis.critic_review.status": 1,
    "analysis.critic_review.warnings": 1,
    "analysis.critic_review.issues": 1,
    "analysis.persistence_meta.persisted_at": 1,
    "analysis.persistence_meta.pipeline_version": 1,
    "analysis.evidence.cvss_score": 1,
    "analysis.evidence.cvss_version": 1,
    "analysis.evidence.epss_probability": 1,
    "analysis.evidence.epss_available": 1,
    "analysis.evidence.kev_listed": 1,
    "analysis.evidence.kev_status_known": 1,
    "analysis.evidence.age_days": 1,
    "analysis.evidence.validity_status": 1,
    "analysis.evidence.related_urlhaus_count": 1,
    "analysis.evidence.related_dread_count": 1,
    "analysis.evidence.related_cve_count": 1,
    "analysis.evidence.candidate_urlhaus_count": 1,
    "analysis.evidence.candidate_dread_count": 1,
    "analysis.evidence.urlhaus_match_stats.accepted_evidence_count": 1,
    "analysis.evidence.urlhaus_match_stats.manual_review_evidence_count": 1,
    "analysis.evidence.urlhaus_match_stats.rejected_evidence_count": 1,
    "analysis.evidence.urlhaus_match_stats.accepted_match_count": 1,
    "analysis.evidence.urlhaus_match_stats.manual_review_match_count": 1,
    "analysis.evidence.urlhaus_match_stats.rejected_match_count": 1,
    "analysis.evidence.urlhaus_match_stats.ignored_low_signal_count": 1,
    "analysis.evidence.urlhaus_match_stats.exact_cve_hits": 1,
    "analysis.evidence.urlhaus_match_stats.high_signal_hits": 1,
    "analysis.evidence.dread_match_stats.accepted_evidence_count": 1,
    "analysis.evidence.dread_match_stats.manual_review_evidence_count": 1,
    "analysis.evidence.dread_match_stats.rejected_evidence_count": 1,
    "analysis.evidence.dread_match_stats.accepted_match_count": 1,
    "analysis.evidence.dread_match_stats.manual_review_match_count": 1,
    "analysis.evidence.dread_match_stats.rejected_match_count": 1,
    "analysis.evidence.dread_match_stats.ignored_low_signal_count": 1,
    "analysis.evidence.dread_match_stats.exact_cve_hits": 1,
    "analysis.evidence.dread_match_stats.high_signal_hits": 1,
    "analysis.evidence.threat": 1,
    "analysis.evidence.url_status": 1,
    "analysis.evidence.tags": 1,
    "analysis.evidence.categories": 1,
    "analysis.evidence.matched_terms": 1,
    "analysis.evidence.payload_signals": 1,
    "analysis.evidence.malware_family_signals": 1,
    "analysis.feature_breakdown.base_cvss_component": 1,
    "analysis.feature_breakdown.recentness_bonus": 1,
    "analysis.feature_breakdown.urlhaus_correlation_bonus": 1,
    "analysis.feature_breakdown.dread_correlation_bonus": 1,
    "analysis.feature_breakdown.nlp_context_bonus": 1,
    "analysis.feature_breakdown.llm_context_bonus": 1,
    "analysis.feature_breakdown.cross_source_bonus": 1,
    "analysis.feature_breakdown.age_penalty": 1,
    "analysis.feature_breakdown.raw_age_penalty": 1,
    "analysis.feature_breakdown.graph_centrality_score": 1,
    "analysis.feature_breakdown.graph_bonus": 1,
    "analysis.feature_breakdown.pre_graph_score": 1,
    "analysis.feature_breakdown.raw_score_before_clamp": 1,
    "analysis.feature_breakdown.final_score": 1,
    "analysis.feature_breakdown.risk_score_from_signals": 1,
    "analysis.feature_breakdown.severity_signal": 1,
    "analysis.feature_breakdown.epss_signal": 1,
    "analysis.feature_breakdown.kev_signal": 1,
    "analysis.feature_breakdown.recency_signal": 1,
    "analysis.feature_breakdown.correlation_signal": 1,
    "analysis.feature_breakdown.graph_signal": 1,
    "analysis.feature_breakdown.nlp_context_signal": 1,
    "analysis.feature_breakdown.weighted_signal_score": 1,
    "analysis.feature_breakdown.risk_raw": 1,
    "analysis.feature_breakdown.score_before_intrinsic_floor": 1,
    "analysis.feature_breakdown.intrinsic_criticality_floor_applied": 1,
    "analysis.feature_breakdown.risk_signal_contributions": 1,
    "analysis.feature_breakdown.base_feed_component": 1,
    "analysis.feature_breakdown.threat_type_score": 1,
    "analysis.feature_breakdown.status_score": 1,
    "analysis.feature_breakdown.payload_score": 1,
    "analysis.feature_breakdown.malware_family_score": 1,
    "analysis.feature_breakdown.delivery_pattern_score": 1,
    "analysis.feature_breakdown.tag_density_score": 1,
    "analysis.feature_breakdown.freshness_score": 1,
    "analysis.feature_breakdown.cross_source_score": 1,
    "analysis.feature_breakdown.base_darkweb_component": 1,
    "analysis.feature_breakdown.category_bonus": 1,
    "analysis.feature_breakdown.related_cve_bonus": 1,
    "analysis.feature_breakdown.related_urlhaus_bonus": 1,
    "analysis.feature_breakdown.llm_bonus": 1,
    "analysis.graph_summary.node_count": 1,
    "analysis.graph_summary.edge_count": 1,
    "analysis.graph_summary.cross_source_edge_count": 1,
    "analysis.graph_summary.centrality_score": 1,
    "analysis.graph_summary.structural_strength": 1,
}

COMMON_COLUMNS = [
    "source", "entity_id", "risk_score", "risk_level", "confidence", "confidence_band",
    "processed", "job_state", "job_attempt_count", "job_analysis_version", "analyzed_at",
    "pipeline_version", "critic_status", "warning_count", "issue_count", "recommendation_count",
    "graph_node_count", "graph_edge_count", "graph_cross_source_edge_count", "graph_centrality",
    "graph_structural_strength", "analysis_history_count", "diagnosis",
]

CVE_COLUMNS = COMMON_COLUMNS + [
    "published", "last_modified", "cvss_score", "cvss_version", "risk_minus_cvss", "age_days",
    "epss_probability", "epss_available", "kev_listed", "kev_status_known", "validity_status",
    "related_urlhaus_count", "related_dread_count", "candidate_urlhaus_count", "candidate_dread_count",
    "urlhaus_accepted", "urlhaus_manual_review", "urlhaus_rejected", "urlhaus_ignored_low_signal",
    "urlhaus_exact_cve_hits", "urlhaus_high_signal_hits", "dread_accepted", "dread_manual_review",
    "dread_rejected", "dread_ignored_low_signal", "dread_exact_cve_hits", "dread_high_signal_hits",
    "base_cvss_component", "recentness_bonus", "urlhaus_correlation_bonus", "dread_correlation_bonus",
    "cross_source_bonus", "nlp_context_bonus", "llm_context_bonus", "age_penalty", "graph_bonus",
    "pre_graph_score", "raw_score_before_clamp", "risk_score_from_signals", "severity_signal",
    "epss_signal", "kev_signal", "recency_signal", "correlation_signal", "graph_signal",
    "nlp_context_signal", "weighted_signal_score", "risk_raw", "score_before_intrinsic_floor",
    "intrinsic_criticality_floor_applied", "severity_contribution", "epss_contribution",
    "kev_contribution", "recency_contribution", "correlation_contribution", "graph_contribution",
    "nlp_context_contribution",
]

URLHAUS_COLUMNS = COMMON_COLUMNS + [
    "urlhaus_id", "url", "threat", "url_status", "date_added", "related_cve_count",
    "related_dread_count", "tags", "malware_families", "script_payload", "binary_payload",
    "archive_payload", "living_off_land_delivery", "base_feed_component", "threat_type_score",
    "status_score", "payload_score", "malware_family_score", "delivery_pattern_score",
    "tag_density_score", "freshness_score", "cross_source_score", "graph_bonus", "pre_graph_score",
]

DREAD_COLUMNS = COMMON_COLUMNS + [
    "title", "category", "categories", "matched_terms", "related_cve_count", "related_urlhaus_count",
    "base_darkweb_component", "category_bonus", "related_cve_bonus", "related_urlhaus_bonus",
    "llm_bonus", "graph_bonus",
]


def nested(payload: Mapping[str, Any] | None, path: str, default: Any = None) -> Any:
    current: Any = payload
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return default
        current = current[part]
    return current


def number(value: Any, default: float | None = None) -> float | None:
    if value is None or value == "":
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if math.isfinite(parsed) else default


def integer(value: Any, default: int = 0) -> int:
    parsed = number(value)
    return int(parsed) if parsed is not None else default


def boolean(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "listed"}:
        return True
    if text in {"false", "0", "no", "not_listed", "unknown"}:
        return False
    return None


def iso(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    return str(value)


def text_id(value: Any) -> str:
    if isinstance(value, ObjectId):
        return str(value)
    return str(value or "")


def list_text(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, (list, tuple, set)):
        return "|".join(str(item) for item in value if item not in (None, ""))
    return str(value)


def confidence_band(value: float | None) -> str:
    if value is None:
        return "MISSING"
    if value >= 0.80:
        return "HIGH"
    if value >= 0.55:
        return "MODERATE"
    return "LOW"


def expected_risk_level(score: float | None) -> str:
    score = score or 0.0
    weights = SETTINGS.scoring
    if score >= weights.critical_threshold:
        return "CRITICAL"
    if score >= weights.high_threshold:
        return "HIGH"
    if score >= weights.medium_threshold:
        return "MEDIUM"
    return "LOW"


def percentile(sorted_values: Sequence[float], fraction: float) -> float | None:
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return round(sorted_values[0], 4)
    position = (len(sorted_values) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return round(sorted_values[lower], 4)
    weighted = sorted_values[lower] * (upper - position) + sorted_values[upper] * (position - lower)
    return round(weighted, 4)


def numeric_summary(values: Iterable[float | None]) -> dict[str, Any]:
    cleaned = sorted(float(value) for value in values if value is not None and math.isfinite(float(value)))
    if not cleaned:
        return {"count": 0, "min": None, "avg": None, "median": None, "p90": None, "p95": None, "max": None}
    return {
        "count": len(cleaned),
        "min": round(cleaned[0], 4),
        "avg": round(statistics.fmean(cleaned), 4),
        "median": percentile(cleaned, 0.50),
        "p90": percentile(cleaned, 0.90),
        "p95": percentile(cleaned, 0.95),
        "max": round(cleaned[-1], 4),
    }


def pearson(pairs: Sequence[tuple[float, float]]) -> float | None:
    if len(pairs) < 2:
        return None
    xs = [item[0] for item in pairs]
    ys = [item[1] for item in pairs]
    mean_x = statistics.fmean(xs)
    mean_y = statistics.fmean(ys)
    numerator = sum((x - mean_x) * (y - mean_y) for x, y in pairs)
    denom_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    denom_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if denom_x == 0 or denom_y == 0:
        return None
    return round(numerator / (denom_x * denom_y), 4)


def write_csv(path: Path, rows: Sequence[Mapping[str, Any]], columns: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(columns), extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            normalized = {}
            for column in columns:
                value = row.get(column, "")
                if isinstance(value, (dict, list, tuple, set)):
                    value = json.dumps(value, ensure_ascii=False, default=iso)
                elif isinstance(value, (datetime, date, ObjectId)):
                    value = iso(value)
                normalized[column] = value
            writer.writerow(normalized)


def common_row(source: str, doc: Mapping[str, Any]) -> dict[str, Any]:
    analysis = doc.get("analysis") or {}
    job = doc.get("job_lifecycle") or {}
    graph = analysis.get("graph_summary") or {}
    critic = analysis.get("critic_review") or {}
    risk = number(analysis.get("risk_score"))
    confidence = number(analysis.get("confidence"))
    warnings = critic.get("warnings") or []
    issues = critic.get("issues") or []
    pipeline_version = analysis.get("pipeline_version") or nested(analysis, "persistence_meta.pipeline_version", "")
    return {
        "source": source,
        "entity_id": text_id(analysis.get("entity_id") or doc.get("_id") or doc.get("urlhaus_id") or doc.get("url") or doc.get("title")),
        "risk_score": risk,
        "risk_level": analysis.get("risk_level") or "MISSING",
        "confidence": confidence,
        "confidence_band": confidence_band(confidence),
        "processed": bool(doc.get("processed")),
        "job_state": job.get("state") or "missing",
        "job_attempt_count": integer(job.get("attempt_count")),
        "job_analysis_version": job.get("analysis_version") or "",
        "analyzed_at": iso(analysis.get("analyzed_at") or nested(analysis, "persistence_meta.persisted_at")),
        "pipeline_version": pipeline_version or "missing",
        "critic_status": critic.get("status") or "missing",
        "warning_count": len(warnings),
        "issue_count": len(issues),
        "recommendation_count": len(analysis.get("recommendations") or []),
        "graph_node_count": integer(graph.get("node_count")),
        "graph_edge_count": integer(graph.get("edge_count")),
        "graph_cross_source_edge_count": integer(graph.get("cross_source_edge_count")),
        "graph_centrality": number(graph.get("centrality_score"), 0.0),
        "graph_structural_strength": number(graph.get("structural_strength"), 0.0),
        "analysis_history_count": len(doc.get("analysis_history") or []),
        "diagnosis": analysis.get("diagnosis") or "",
    }


def match_stat(stats: Mapping[str, Any], preferred: str, fallback: str = "") -> int:
    value = stats.get(preferred)
    if value is None and fallback:
        value = stats.get(fallback)
    return integer(value)


def cve_row(doc: Mapping[str, Any]) -> dict[str, Any]:
    row = common_row("cve", doc)
    analysis = doc.get("analysis") or {}
    evidence = analysis.get("evidence") or {}
    features = analysis.get("feature_breakdown") or {}
    url_stats = evidence.get("urlhaus_match_stats") or {}
    dread_stats = evidence.get("dread_match_stats") or {}
    contributions = features.get("risk_signal_contributions") or {}
    risk = number(analysis.get("risk_score"))
    cvss = number(evidence.get("cvss_score"))
    row.update({
        "published": iso(doc.get("published")),
        "last_modified": iso(doc.get("last_modified") or doc.get("lastModified")),
        "cvss_score": cvss,
        "cvss_version": evidence.get("cvss_version") or "Unknown",
        "risk_minus_cvss": round(risk - cvss, 4) if risk is not None and cvss is not None else None,
        "age_days": integer(evidence.get("age_days"), default=-1),
        "epss_probability": number(evidence.get("epss_probability")),
        "epss_available": boolean(evidence.get("epss_available")),
        "kev_listed": boolean(evidence.get("kev_listed")),
        "kev_status_known": boolean(evidence.get("kev_status_known")),
        "validity_status": evidence.get("validity_status") or "valid_or_unspecified",
        "related_urlhaus_count": integer(evidence.get("related_urlhaus_count")),
        "related_dread_count": integer(evidence.get("related_dread_count")),
        "candidate_urlhaus_count": integer(evidence.get("candidate_urlhaus_count")),
        "candidate_dread_count": integer(evidence.get("candidate_dread_count")),
        "urlhaus_accepted": match_stat(url_stats, "accepted_evidence_count", "accepted_match_count"),
        "urlhaus_manual_review": match_stat(url_stats, "manual_review_evidence_count", "manual_review_match_count"),
        "urlhaus_rejected": match_stat(url_stats, "rejected_evidence_count", "rejected_match_count"),
        "urlhaus_ignored_low_signal": integer(url_stats.get("ignored_low_signal_count")),
        "urlhaus_exact_cve_hits": integer(url_stats.get("exact_cve_hits")),
        "urlhaus_high_signal_hits": integer(url_stats.get("high_signal_hits")),
        "dread_accepted": match_stat(dread_stats, "accepted_evidence_count", "accepted_match_count"),
        "dread_manual_review": match_stat(dread_stats, "manual_review_evidence_count", "manual_review_match_count"),
        "dread_rejected": match_stat(dread_stats, "rejected_evidence_count", "rejected_match_count"),
        "dread_ignored_low_signal": integer(dread_stats.get("ignored_low_signal_count")),
        "dread_exact_cve_hits": integer(dread_stats.get("exact_cve_hits")),
        "dread_high_signal_hits": integer(dread_stats.get("high_signal_hits")),
        "base_cvss_component": number(features.get("base_cvss_component"), 0.0),
        "recentness_bonus": number(features.get("recentness_bonus"), 0.0),
        "urlhaus_correlation_bonus": number(features.get("urlhaus_correlation_bonus"), 0.0),
        "dread_correlation_bonus": number(features.get("dread_correlation_bonus"), 0.0),
        "cross_source_bonus": number(features.get("cross_source_bonus"), 0.0),
        "nlp_context_bonus": number(features.get("nlp_context_bonus"), 0.0),
        "llm_context_bonus": number(features.get("llm_context_bonus"), 0.0),
        "age_penalty": number(features.get("age_penalty"), 0.0),
        "graph_bonus": number(features.get("graph_bonus"), 0.0),
        "pre_graph_score": number(features.get("pre_graph_score")),
        "raw_score_before_clamp": number(features.get("raw_score_before_clamp")),
        "risk_score_from_signals": number(features.get("risk_score_from_signals")),
        "severity_signal": number(features.get("severity_signal"), 0.0),
        "epss_signal": number(features.get("epss_signal"), 0.0),
        "kev_signal": number(features.get("kev_signal"), 0.0),
        "recency_signal": number(features.get("recency_signal"), 0.0),
        "correlation_signal": number(features.get("correlation_signal"), 0.0),
        "graph_signal": number(features.get("graph_signal"), 0.0),
        "nlp_context_signal": number(features.get("nlp_context_signal"), 0.0),
        "weighted_signal_score": number(features.get("weighted_signal_score"), 0.0),
        "risk_raw": number(features.get("risk_raw"), 0.0),
        "score_before_intrinsic_floor": number(features.get("score_before_intrinsic_floor"), 0.0),
        "intrinsic_criticality_floor_applied": bool(features.get("intrinsic_criticality_floor_applied")),
        "severity_contribution": number(contributions.get("severity_signal"), 0.0),
        "epss_contribution": number(contributions.get("epss_signal"), 0.0),
        "kev_contribution": number(contributions.get("kev_signal"), 0.0),
        "recency_contribution": number(contributions.get("recency_signal"), 0.0),
        "correlation_contribution": number(contributions.get("correlation_signal"), 0.0),
        "graph_contribution": number(contributions.get("graph_signal"), 0.0),
        "nlp_context_contribution": number(contributions.get("nlp_context_signal"), 0.0),
    })
    return row


def urlhaus_row(doc: Mapping[str, Any]) -> dict[str, Any]:
    row = common_row("urlhaus", doc)
    analysis = doc.get("analysis") or {}
    evidence = analysis.get("evidence") or {}
    features = analysis.get("feature_breakdown") or {}
    payload = evidence.get("payload_signals") or {}
    row.update({
        "urlhaus_id": doc.get("urlhaus_id") or "",
        "url": doc.get("url") or "",
        "threat": evidence.get("threat") or doc.get("threat") or "",
        "url_status": evidence.get("url_status") or doc.get("url_status") or "",
        "date_added": iso(doc.get("date_added")),
        "related_cve_count": integer(evidence.get("related_cve_count")),
        "related_dread_count": integer(evidence.get("related_dread_count")),
        "tags": list_text(evidence.get("tags")),
        "malware_families": list_text(evidence.get("malware_family_signals")),
        "script_payload": bool(payload.get("script_payload")),
        "binary_payload": bool(payload.get("binary_payload")),
        "archive_payload": bool(payload.get("archive_payload")),
        "living_off_land_delivery": bool(payload.get("living_off_land_delivery")),
        "base_feed_component": number(features.get("base_feed_component"), 0.0),
        "threat_type_score": number(features.get("threat_type_score"), 0.0),
        "status_score": number(features.get("status_score"), 0.0),
        "payload_score": number(features.get("payload_score"), 0.0),
        "malware_family_score": number(features.get("malware_family_score"), 0.0),
        "delivery_pattern_score": number(features.get("delivery_pattern_score"), 0.0),
        "tag_density_score": number(features.get("tag_density_score"), 0.0),
        "freshness_score": number(features.get("freshness_score"), 0.0),
        "cross_source_score": number(features.get("cross_source_score"), 0.0),
        "graph_bonus": number(features.get("graph_bonus"), 0.0),
        "pre_graph_score": number(features.get("pre_graph_score")),
    })
    return row


def dread_row(doc: Mapping[str, Any]) -> dict[str, Any]:
    row = common_row("dread", doc)
    analysis = doc.get("analysis") or {}
    evidence = analysis.get("evidence") or {}
    features = analysis.get("feature_breakdown") or {}
    row.update({
        "title": doc.get("title") or "",
        "category": doc.get("category") or "",
        "categories": list_text(evidence.get("categories")),
        "matched_terms": list_text(evidence.get("matched_terms")),
        "related_cve_count": integer(evidence.get("related_cve_count")),
        "related_urlhaus_count": integer(evidence.get("related_urlhaus_count")),
        "base_darkweb_component": number(features.get("base_darkweb_component"), 0.0),
        "category_bonus": number(features.get("category_bonus"), 0.0),
        "related_cve_bonus": number(features.get("related_cve_bonus"), 0.0),
        "related_urlhaus_bonus": number(features.get("related_urlhaus_bonus"), 0.0),
        "llm_bonus": number(features.get("llm_bonus"), 0.0),
        "graph_bonus": number(features.get("graph_bonus"), 0.0),
    })
    return row


def source_summary(collection: Any, rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    total = int(collection.count_documents({}))
    processed = int(collection.count_documents({"processed": True}))
    pending = int(collection.count_documents({"processed": False}))
    analyzed = len(rows)
    scores = [number(row.get("risk_score")) for row in rows]
    confidences = [number(row.get("confidence")) for row in rows]
    risk_levels = Counter(str(row.get("risk_level") or "MISSING") for row in rows)
    confidence_bands = Counter(str(row.get("confidence_band") or "MISSING") for row in rows)
    job_states = Counter(str(row.get("job_state") or "missing") for row in rows)
    critic_statuses = Counter(str(row.get("critic_status") or "missing") for row in rows)
    pipeline_versions = Counter(str(row.get("pipeline_version") or "missing") for row in rows)
    analyzed_times = sorted(str(row.get("analyzed_at")) for row in rows if row.get("analyzed_at"))
    return {
        "total_documents": total,
        "processed_documents": processed,
        "pending_documents": pending,
        "analyzed_documents": analyzed,
        "analysis_coverage": round(analyzed / max(total, 1), 6),
        "risk_score": numeric_summary(scores),
        "confidence": numeric_summary(confidences),
        "risk_level_distribution": dict(sorted(risk_levels.items())),
        "confidence_band_distribution": dict(sorted(confidence_bands.items())),
        "job_state_distribution": dict(sorted(job_states.items())),
        "critic_status_distribution": dict(sorted(critic_statuses.items())),
        "pipeline_version_distribution": dict(sorted(pipeline_versions.items())),
        "completed_with_warnings": job_states.get("completed_with_warnings", 0),
        "critic_needs_review": critic_statuses.get("needs-review", 0),
        "warning_bearing_records": sum(1 for row in rows if integer(row.get("warning_count")) > 0),
        "issue_bearing_records": sum(1 for row in rows if integer(row.get("issue_count")) > 0),
        "analysis_window": {
            "earliest": analyzed_times[0] if analyzed_times else None,
            "latest": analyzed_times[-1] if analyzed_times else None,
        },
    }


def cve_summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    analyzed = len(rows)
    valid_cvss_rows = [row for row in rows if number(row.get("cvss_score"), 0.0) > 0]
    cvss_risk_pairs = [
        (float(row["cvss_score"]), float(row["risk_score"]))
        for row in valid_cvss_rows
        if number(row.get("risk_score")) is not None
    ]
    risk_confidence_pairs = [
        (float(row["risk_score"]), float(row["confidence"]))
        for row in rows
        if number(row.get("risk_score")) is not None and number(row.get("confidence")) is not None
    ]
    related_counts = [integer(row.get("related_urlhaus_count")) + integer(row.get("related_dread_count")) for row in rows]
    accepted_counts = [integer(row.get("urlhaus_accepted")) + integer(row.get("dread_accepted")) for row in rows]
    manual_counts = [integer(row.get("urlhaus_manual_review")) + integer(row.get("dread_manual_review")) for row in rows]
    rejected_counts = [integer(row.get("urlhaus_rejected")) + integer(row.get("dread_rejected")) for row in rows]
    ignored_counts = [integer(row.get("urlhaus_ignored_low_signal")) + integer(row.get("dread_ignored_low_signal")) for row in rows]
    cvss_versions = Counter(str(row.get("cvss_version") or "Unknown") for row in rows)
    age_buckets = Counter()
    publication_years = Counter()
    level_mismatches = 0
    score_signal_mismatches = 0
    final_score_mismatches = 0
    out_of_range_scores = 0
    out_of_range_confidence = 0
    for row in rows:
        age = integer(row.get("age_days"), -1)
        if age < 0:
            age_buckets["unknown"] += 1
        elif age <= 30:
            age_buckets["0-30d"] += 1
        elif age <= 180:
            age_buckets["31-180d"] += 1
        elif age <= 365:
            age_buckets["181-365d"] += 1
        elif age <= 1825:
            age_buckets["1-5y"] += 1
        else:
            age_buckets[">5y"] += 1
        published = str(row.get("published") or "")
        match = re.match(r"^(\d{4})", published)
        publication_years[match.group(1) if match else "unknown"] += 1
        risk = number(row.get("risk_score"))
        confidence = number(row.get("confidence"))
        if risk is not None and str(row.get("risk_level")) != expected_risk_level(risk):
            level_mismatches += 1
        signal_score = number(row.get("risk_score_from_signals"))
        if risk is not None and signal_score is not None and abs(risk - signal_score) > 0.011:
            score_signal_mismatches += 1
        final_score = number(row.get("final_score"))
        if risk is not None and final_score is not None and abs(risk - final_score) > 0.011:
            final_score_mismatches += 1
        if risk is None or not 0.0 <= risk <= 10.0:
            out_of_range_scores += 1
        if confidence is None or not 0.0 <= confidence <= 1.0:
            out_of_range_confidence += 1

    epss_available = sum(1 for row in rows if row.get("epss_available") is True)
    kev_known = sum(1 for row in rows if row.get("kev_status_known") is True)
    kev_listed = sum(1 for row in rows if row.get("kev_listed") is True)
    with_external = sum(1 for count in related_counts if count > 0)
    with_accepted = sum(1 for count in accepted_counts if count > 0)
    high_risk_low_confidence = sum(
        1 for row in rows
        if (number(row.get("risk_score"), 0.0) or 0.0) >= SETTINGS.scoring.high_threshold
        and (number(row.get("confidence"), 0.0) or 0.0) < 0.55
    )
    critical_without_external = sum(
        1 for row, related in zip(rows, related_counts)
        if row.get("risk_level") == "CRITICAL" and related == 0
    )
    reprioritized = sum(
        1 for row in rows
        if number(row.get("risk_minus_cvss")) is not None and float(row["risk_minus_cvss"]) >= 1.5
    )
    invalid = sum(1 for row in rows if row.get("validity_status") == "invalid_or_rejected")
    return {
        "cvss_coverage": {"count": len(valid_cvss_rows), "ratio": round(len(valid_cvss_rows) / max(analyzed, 1), 6)},
        "epss_coverage": {"count": epss_available, "ratio": round(epss_available / max(analyzed, 1), 6)},
        "kev_status_coverage": {"count": kev_known, "ratio": round(kev_known / max(analyzed, 1), 6)},
        "kev_listed_count": kev_listed,
        "invalid_or_rejected_cve_count": invalid,
        "cross_source_supported_count": with_external,
        "accepted_external_evidence_count": with_accepted,
        "no_external_support_count": analyzed - with_external,
        "high_risk_low_confidence_count": high_risk_low_confidence,
        "critical_without_external_support_count": critical_without_external,
        "reprioritized_vs_cvss_delta_ge_1_5_count": reprioritized,
        "intrinsic_criticality_floor_applied_count": sum(1 for row in rows if row.get("intrinsic_criticality_floor_applied")),
        "graph_supported_count": sum(1 for row in rows if (number(row.get("graph_bonus"), 0.0) or 0.0) > 0),
        "cvss_risk_pearson_correlation": pearson(cvss_risk_pairs),
        "risk_confidence_pearson_correlation": pearson(risk_confidence_pairs),
        "risk_minus_cvss": numeric_summary(number(row.get("risk_minus_cvss")) for row in valid_cvss_rows),
        "accepted_evidence_per_cve": numeric_summary(accepted_counts),
        "manual_review_evidence_per_cve": numeric_summary(manual_counts),
        "rejected_evidence_per_cve": numeric_summary(rejected_counts),
        "ignored_low_signal_per_cve": numeric_summary(ignored_counts),
        "urlhaus_accepted_evidence_total": sum(integer(row.get("urlhaus_accepted")) for row in rows),
        "dread_accepted_evidence_total": sum(integer(row.get("dread_accepted")) for row in rows),
        "urlhaus_manual_review_total": sum(integer(row.get("urlhaus_manual_review")) for row in rows),
        "dread_manual_review_total": sum(integer(row.get("dread_manual_review")) for row in rows),
        "urlhaus_rejected_total": sum(integer(row.get("urlhaus_rejected")) for row in rows),
        "dread_rejected_total": sum(integer(row.get("dread_rejected")) for row in rows),
        "urlhaus_ignored_low_signal_total": sum(integer(row.get("urlhaus_ignored_low_signal")) for row in rows),
        "dread_ignored_low_signal_total": sum(integer(row.get("dread_ignored_low_signal")) for row in rows),
        "exact_cve_hit_total": sum(integer(row.get("urlhaus_exact_cve_hits")) + integer(row.get("dread_exact_cve_hits")) for row in rows),
        "high_signal_hit_total": sum(integer(row.get("urlhaus_high_signal_hits")) + integer(row.get("dread_high_signal_hits")) for row in rows),
        "cvss_version_distribution": dict(sorted(cvss_versions.items())),
        "age_bucket_distribution": dict(age_buckets),
        "publication_year_distribution": dict(sorted(publication_years.items())),
        "average_normalized_signals": {
            field: numeric_summary(number(row.get(field)) for row in rows).get("avg")
            for field in ("severity_signal", "epss_signal", "kev_signal", "recency_signal", "correlation_signal", "graph_signal", "nlp_context_signal")
        },
        "average_signal_contributions": {
            field: numeric_summary(number(row.get(field)) for row in rows).get("avg")
            for field in ("severity_contribution", "epss_contribution", "kev_contribution", "recency_contribution", "correlation_contribution", "graph_contribution", "nlp_context_contribution")
        },
        "integrity_checks": {
            "risk_level_threshold_mismatch_count": level_mismatches,
            "risk_vs_risk_score_from_signals_mismatch_count": score_signal_mismatches,
            "risk_vs_feature_final_score_mismatch_count": final_score_mismatches,
            "missing_or_out_of_range_risk_count": out_of_range_scores,
            "missing_or_out_of_range_confidence_count": out_of_range_confidence,
        },
    }


def parse_reanalysis_report(repo_root: Path) -> dict[str, Any] | None:
    report_dirs = sorted(repo_root.glob("reports/reanalysis-round-robin-*"), key=lambda path: path.stat().st_mtime, reverse=True)
    if not report_dirs:
        return None
    report_dir = report_dirs[0]
    metrics_path = report_dir / "source_metrics.csv"
    log_path = report_dir / "reanalysis.log"
    summary: dict[str, Any] = {"report_directory": str(report_dir)}
    if metrics_path.exists():
        by_source: dict[str, dict[str, Any]] = {}
        with metrics_path.open("r", encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                source = row.get("source") or "unknown"
                item = by_source.setdefault(source, {"batches": 0, "processed": 0, "elapsed_seconds": 0.0, "failed_batches": 0})
                status = row.get("status") or ""
                if status == "skipped":
                    continue
                item["batches"] += 1
                item["processed"] += integer(row.get("processed_delta"))
                item["elapsed_seconds"] += number(row.get("elapsed_seconds"), 0.0) or 0.0
                if status not in {"0", "completed", "success"}:
                    item["failed_batches"] += 1
        for item in by_source.values():
            elapsed = float(item["elapsed_seconds"])
            item["elapsed_seconds"] = round(elapsed, 4)
            item["effective_docs_per_second"] = round(item["processed"] / elapsed, 4) if elapsed > 0 else 0.0
        summary["source_metrics"] = by_source
    if log_path.exists():
        text = log_path.read_text(encoding="utf-8", errors="replace")
        for key in ("rounds", "total_elapsed_seconds", "total_elapsed_minutes"):
            matches = re.findall(rf"{key}=(\d+)", text)
            if matches:
                summary[key] = int(matches[-1])
        summary["completed"] = "REANALYSIS_COMPLETED" in text
        summary["log_file"] = str(log_path)
    return summary


def top_rows(rows: Sequence[Mapping[str, Any]], key, limit: int) -> list[Mapping[str, Any]]:
    return sorted(rows, key=key, reverse=True)[:limit]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate read-only corpus analysis audit reports.")
    parser.add_argument("--top", type=int, default=100, help="Rows to include in each focused top-list CSV.")
    parser.add_argument("--output-dir", default="", help="Optional explicit report directory.")
    parser.add_argument("--batch-size", type=int, default=1000, help="Mongo cursor batch size.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.top <= 0 or args.batch_size <= 0:
        raise SystemExit("--top and --batch-size must be greater than zero")
    repo_root = AGENT_PYTHON_ROOT.parent
    timestamp = datetime.now(timezone.utc).astimezone().strftime("%Y%m%d-%H%M%S")
    output_dir = Path(args.output_dir).expanduser().resolve() if args.output_dir else repo_root / "reports" / f"analysis-audit-{timestamp}"
    output_dir.mkdir(parents=True, exist_ok=True)

    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, connectTimeoutMS=5000)
    client.admin.command("ping")
    database = client[DB_NAME]

    rows_by_source: dict[str, list[dict[str, Any]]] = {}
    row_builders = {"cve": cve_row, "urlhaus": urlhaus_row, "dread": dread_row}
    columns_by_source = {"cve": CVE_COLUMNS, "urlhaus": URLHAUS_COLUMNS, "dread": DREAD_COLUMNS}

    for source, collection_name in SOURCE_COLLECTIONS.items():
        collection = database[collection_name]
        cursor = collection.find({"analysis": {"$exists": True}}, PROJECTION, batch_size=args.batch_size)
        rows = [row_builders[source](doc) for doc in cursor]
        rows.sort(key=lambda row: ((number(row.get("risk_score"), -1.0) or -1.0), (number(row.get("confidence"), -1.0) or -1.0)), reverse=True)
        rows_by_source[source] = rows
        write_csv(output_dir / f"{source}_all_scores.csv", rows, columns_by_source[source])
        write_csv(output_dir / f"{source}_top_by_risk.csv", rows[: args.top], columns_by_source[source])

    cve_rows = rows_by_source["cve"]
    high_risk_low_conf = [
        row for row in cve_rows
        if (number(row.get("risk_score"), 0.0) or 0.0) >= SETTINGS.scoring.high_threshold
        and (number(row.get("confidence"), 0.0) or 0.0) < 0.55
    ]
    reprioritized = [row for row in cve_rows if number(row.get("risk_minus_cvss")) is not None]
    reprioritized.sort(key=lambda row: (number(row.get("risk_minus_cvss"), -999.0) or -999.0, number(row.get("risk_score"), -1.0) or -1.0), reverse=True)
    external_supported = [row for row in cve_rows if integer(row.get("related_urlhaus_count")) + integer(row.get("related_dread_count")) > 0]
    external_supported.sort(key=lambda row: (
        integer(row.get("urlhaus_accepted")) + integer(row.get("dread_accepted")),
        integer(row.get("related_urlhaus_count")) + integer(row.get("related_dread_count")),
        number(row.get("risk_score"), -1.0) or -1.0,
    ), reverse=True)
    critical_no_external = [
        row for row in cve_rows
        if row.get("risk_level") == "CRITICAL"
        and integer(row.get("related_urlhaus_count")) + integer(row.get("related_dread_count")) == 0
    ]
    critic_review = [
        row for row in cve_rows
        if row.get("critic_status") == "needs-review" or integer(row.get("warning_count")) > 0 or integer(row.get("issue_count")) > 0
    ]

    write_csv(output_dir / "cve_high_risk_low_confidence.csv", high_risk_low_conf[: args.top], CVE_COLUMNS)
    write_csv(output_dir / "cve_top_reprioritized_vs_cvss.csv", reprioritized[: args.top], CVE_COLUMNS)
    write_csv(output_dir / "cve_top_cross_source_supported.csv", external_supported[: args.top], CVE_COLUMNS)
    write_csv(output_dir / "cve_critical_without_external_support.csv", critical_no_external[: args.top], CVE_COLUMNS)
    write_csv(output_dir / "cve_critic_review.csv", critic_review[: args.top], CVE_COLUMNS)

    summaries = {
        source: source_summary(database[collection_name], rows_by_source[source])
        for source, collection_name in SOURCE_COLLECTIONS.items()
    }
    all_rows = [row for rows in rows_by_source.values() for row in rows]
    global_summary = {
        "total_documents": sum(item["total_documents"] for item in summaries.values()),
        "processed_documents": sum(item["processed_documents"] for item in summaries.values()),
        "pending_documents": sum(item["pending_documents"] for item in summaries.values()),
        "analyzed_documents": sum(item["analyzed_documents"] for item in summaries.values()),
        "risk_score": numeric_summary(number(row.get("risk_score")) for row in all_rows),
        "confidence": numeric_summary(number(row.get("confidence")) for row in all_rows),
        "risk_level_distribution": dict(Counter(str(row.get("risk_level") or "MISSING") for row in all_rows)),
        "job_state_distribution": dict(Counter(str(row.get("job_state") or "missing") for row in all_rows)),
    }
    global_summary["analysis_coverage"] = round(global_summary["analyzed_documents"] / max(global_summary["total_documents"], 1), 6)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "database": DB_NAME,
        "mongo_uri_redacted": re.sub(r"//.*@", "//***@", MONGO_URI),
        "scoring_thresholds": {
            "medium": SETTINGS.scoring.medium_threshold,
            "high": SETTINGS.scoring.high_threshold,
            "critical": SETTINGS.scoring.critical_threshold,
        },
        "global": global_summary,
        "sources": summaries,
        "cve_analysis": cve_summary(cve_rows),
        "latest_reanalysis_performance": parse_reanalysis_report(repo_root),
        "focused_report_counts": {
            "cve_high_risk_low_confidence": len(high_risk_low_conf),
            "cve_reprioritized_with_cvss": len(reprioritized),
            "cve_cross_source_supported": len(external_supported),
            "cve_critical_without_external_support": len(critical_no_external),
            "cve_critic_review": len(critic_review),
        },
        "files": sorted(path.name for path in output_dir.iterdir() if path.is_file()),
    }

    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=iso) + "\n", encoding="utf-8")
    report["files"] = sorted(path.name for path in output_dir.iterdir() if path.is_file())
    summary_path.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=iso) + "\n", encoding="utf-8")

    print(json.dumps({
        "report_directory": str(output_dir),
        "summary_file": str(summary_path),
        "global": report["global"],
        "source_risk_levels": {source: data["risk_level_distribution"] for source, data in summaries.items()},
        "cve_key_findings": {
            "cvss_coverage": report["cve_analysis"]["cvss_coverage"],
            "epss_coverage": report["cve_analysis"]["epss_coverage"],
            "kev_status_coverage": report["cve_analysis"]["kev_status_coverage"],
            "cross_source_supported_count": report["cve_analysis"]["cross_source_supported_count"],
            "high_risk_low_confidence_count": report["cve_analysis"]["high_risk_low_confidence_count"],
            "critical_without_external_support_count": report["cve_analysis"]["critical_without_external_support_count"],
            "cvss_risk_pearson_correlation": report["cve_analysis"]["cvss_risk_pearson_correlation"],
            "integrity_checks": report["cve_analysis"]["integrity_checks"],
        },
        "latest_reanalysis_performance": report["latest_reanalysis_performance"],
    }, indent=2, ensure_ascii=False, default=iso))
    client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
