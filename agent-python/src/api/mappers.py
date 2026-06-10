from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from api.schemas import FindingDetail, FindingSummary


def serialize_datetime(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def evidence_summary(analysis: Dict[str, Any]) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) or {}
    stats = evidence.get("urlhaus_match_stats", {}) or {}
    accepted = int(stats.get("accepted_match_count") or evidence.get("related_urlhaus_count") or 0)
    rejected = int(stats.get("rejected_match_count") or 0)
    exact = int(stats.get("exact_cve_hits") or 0)
    high_signal = int(stats.get("high_signal_hits") or 0)
    shared_terms = stats.get("shared_terms") if isinstance(stats.get("shared_terms"), list) else []
    related_dread = int(evidence.get("related_dread_count") or 0)
    return {
        "cvss_score": evidence.get("cvss_score"),
        "age_days": evidence.get("age_days"),
        "urlhaus_accepted": accepted,
        "urlhaus_rejected": rejected,
        "exact_cve_hits": exact,
        "high_signal_hits": high_signal,
        "shared_terms_count": len(shared_terms),
        "related_dread_count": related_dread,
        "has_active_evidence": bool(accepted > 0 or exact > 0 or high_signal > 0 or related_dread > 0),
    }


def resolve_entity_id(source: str, doc: Dict[str, Any], analysis: Dict[str, Any]) -> str:
    if source == "cve":
        return str(doc.get("_id", analysis.get("entity_id", "unknown-cve")))
    if source == "urlhaus":
        return str(analysis.get("entity_id") or doc.get("urlhaus_id") or doc.get("url") or doc.get("_id", "unknown-urlhaus"))
    if source == "dread":
        return str(analysis.get("entity_id") or doc.get("title") or doc.get("_id", "unknown-dread"))
    return str(doc.get("_id", "unknown"))


def to_finding_summary(source: str, doc: Dict[str, Any]) -> FindingSummary:
    analysis = doc.get("analysis", {})
    summary = evidence_summary(analysis)
    return FindingSummary(
        source=source,
        entity_id=resolve_entity_id(source, doc, analysis),
        risk_level=str(analysis.get("risk_level", "UNKNOWN")),
        risk_score=float(analysis.get("risk_score", 0.0)),
        confidence=float(analysis.get("confidence", 0.0)),
        diagnosis=str(analysis.get("diagnosis", "")),
        analyzed_at=serialize_datetime(analysis.get("analyzed_at")),
        pipeline_version=analysis.get("pipeline_version") or (analysis.get("persistence_meta") or {}).get("pipeline_version"),
        persistence_meta=dict(analysis.get("persistence_meta", {})),
        cvss_score=summary.get("cvss_score"),
        age_days=summary.get("age_days"),
        published=serialize_datetime(doc.get("published") or doc.get("date_added")),
        evidence_summary=summary,
    )


def to_finding_detail(source: str, doc: Dict[str, Any]) -> FindingDetail:
    analysis = doc.get("analysis", {})
    return FindingDetail(
        source=source,
        entity_id=resolve_entity_id(source, doc, analysis),
        risk_level=str(analysis.get("risk_level", "UNKNOWN")),
        risk_score=float(analysis.get("risk_score", 0.0)),
        confidence=float(analysis.get("confidence", 0.0)),
        diagnosis=str(analysis.get("diagnosis", "")),
        explanation=list(analysis.get("explanation", [])),
        recommendations=list(analysis.get("recommendations", [])),
        evidence=dict(analysis.get("evidence", {})),
        feature_breakdown=dict(analysis.get("feature_breakdown", {})),
        graph_summary=dict(analysis.get("graph_summary", {})),
        graph_edges=list(analysis.get("graph_edges", [])),
        counterfactuals=dict(analysis.get("counterfactuals", {})),
        source_contributions=dict(analysis.get("source_contributions", {})),
        relation_summary=dict(analysis.get("relation_summary", {})),
        orchestration_trace=list(analysis.get("orchestration_trace", [])),
        execution_plan=list(analysis.get("execution_plan", [])),
        critic_review=dict(analysis.get("critic_review", {})),
        agent_outputs=dict(analysis.get("agent_outputs", {})),
        confidence_breakdown=dict(
            analysis.get("confidence_breakdown", {}) or (analysis.get("agent_outputs", {}) or {}).get("confidence_breakdown", {})
        ),
        analyzed_at=serialize_datetime(analysis.get("analyzed_at")),
        pipeline_version=analysis.get("pipeline_version") or (analysis.get("persistence_meta") or {}).get("pipeline_version"),
        persistence_meta=dict(analysis.get("persistence_meta", {})),
    )
