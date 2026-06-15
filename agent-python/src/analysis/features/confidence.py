from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from analysis.features.cve_temporal import calculate_age_days
from analysis.scoring_signals import calculate_confidence_signal_components, normalize_recency
from config import get_settings


SETTINGS = get_settings()
AgeCalculator = Callable[[Optional[Any]], Optional[int]]


@dataclass(frozen=True)
class ConfidenceResult:
    confidence: float
    breakdown: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {"confidence": self.confidence, "breakdown": self.breakdown}


def calculate_cve_confidence(
    *,
    has_cvss: bool,
    urlhaus_match_count: int,
    dread_match_count: int,
    keyword_count: int,
    llm_fields_count: int,
    graph_score: float,
    cvss_score: float = 0.0,
    cvss_version: str = "Unknown",
    description: str = "",
    age_days: Optional[int] = None,
    nlp_entities: Optional[Dict[str, Any]] = None,
    urlhaus_stats: Optional[Dict[str, Any]] = None,
    dread_stats: Optional[Dict[str, Any]] = None,
    epss_available: bool = False,
    kev_status_known: bool = False,
    kev_listed: bool = False,
) -> ConfidenceResult:
    """Return component-based confidence for CVE risk assessment."""
    urlhaus_stats = urlhaus_stats or {}
    dread_stats = dread_stats or {}
    nlp_entities = nlp_entities or {}

    accepted_external = urlhaus_match_count + dread_match_count
    rejected_correlations = int(urlhaus_stats.get("rejected_match_count", 0) or 0) + int(dread_stats.get("rejected_match_count", 0) or 0)
    exact_hits = int(urlhaus_stats.get("exact_cve_hits", 0) or 0) + int(dread_stats.get("exact_cve_hits", 0) or 0)
    high_signal_hits = int(urlhaus_stats.get("high_signal_hits", 0) or 0) + int(dread_stats.get("high_signal_hits", 0) or 0)
    entity_hits = int(urlhaus_stats.get("entity_overlap_hits", 0) or 0) + int(dread_stats.get("entity_overlap_hits", 0) or 0)
    shared_terms = set(urlhaus_stats.get("shared_terms") or []) | set(dread_stats.get("shared_terms") or [])
    acceptance_reasons = set(urlhaus_stats.get("acceptance_reasons") or []) | set(dread_stats.get("acceptance_reasons") or [])
    semantic_signal = max(
        float(urlhaus_stats.get("avg_semantic_score", 0.0) or 0.0),
        float(dread_stats.get("avg_semantic_score", 0.0) or 0.0),
    )
    entity_alignment_only = bool(
        accepted_external > 0
        and acceptance_reasons
        and acceptance_reasons <= {"entity_alignment"}
        and exact_hits == 0
        and high_signal_hits == 0
    )

    base_confidence = 0.12

    metadata_confidence = 0.0
    if has_cvss:
        metadata_confidence += 0.22
        if cvss_version in {"CVSS v4.0", "CVSS v3.1", "CVSS v3.0"}:
            metadata_confidence += 0.04
        elif cvss_version == "CVSS v2.0":
            metadata_confidence += 0.02
        if cvss_score >= 9.0:
            metadata_confidence += 0.02
    desc_len = len((description or "").strip())
    if desc_len >= 180:
        metadata_confidence += 0.10
    elif desc_len >= 80:
        metadata_confidence += 0.07
    elif desc_len >= 30:
        metadata_confidence += 0.03
    if age_days is not None:
        metadata_confidence += 0.04
    metadata_confidence = min(metadata_confidence, 0.42)

    entity_confidence = 0.0
    products = nlp_entities.get("products") or []
    vuln_types = nlp_entities.get("vuln_types") or []
    impacts = nlp_entities.get("impacts") or []
    threat_terms = nlp_entities.get("threat_terms") or []
    cve_ids = nlp_entities.get("cve_ids") or []
    if products:
        entity_confidence += min(len(products) * 0.012, 0.07)
    if vuln_types:
        entity_confidence += 0.05
    if impacts:
        entity_confidence += 0.04
    if threat_terms:
        entity_confidence += 0.04
    if cve_ids:
        entity_confidence += 0.02
    entity_confidence += min(keyword_count * 0.003, 0.03)
    entity_confidence += min(llm_fields_count * 0.02, 0.05)
    entity_confidence = min(entity_confidence, 0.18)

    external_evidence_confidence = 0.0
    if accepted_external:
        if entity_alignment_only:
            external_evidence_confidence += min(accepted_external * 0.025, 0.07)
        else:
            external_evidence_confidence += min(accepted_external * 0.055, 0.16)
    if exact_hits:
        external_evidence_confidence += min(exact_hits * 0.16, 0.26)
    if high_signal_hits:
        external_evidence_confidence += min(high_signal_hits * 0.05, 0.12)
    if entity_hits:
        external_evidence_confidence += min(entity_hits * (0.015 if entity_alignment_only else 0.035), 0.08)
    if shared_terms:
        external_evidence_confidence += min(len(shared_terms) * (0.008 if entity_alignment_only else 0.015), 0.06)
    if semantic_signal >= SETTINGS.semantic.similarity_floor:
        external_evidence_confidence += min(semantic_signal * (0.045 if entity_alignment_only else 0.10), 0.08)
    external_evidence_confidence = min(external_evidence_confidence, 0.38)

    correlation_confidence = 0.0
    if accepted_external > 0:
        correlation_confidence += min(graph_score * 0.04, 0.05)
    if accepted_external > 0 and (exact_hits or high_signal_hits or shared_terms or semantic_signal >= SETTINGS.semantic.similarity_floor):
        correlation_confidence += 0.02 if entity_alignment_only else 0.04
    correlation_confidence = min(correlation_confidence, 0.09)

    freshness_confidence = 0.0
    if age_days is not None:
        if age_days <= 30:
            freshness_confidence += 0.04
        elif age_days <= 365:
            freshness_confidence += 0.02

    external_signal_components = calculate_confidence_signal_components(
        epss_available=epss_available,
        kev_status_known=kev_status_known,
        kev_listed=kev_listed,
        accepted_external_evidence_count=accepted_external,
        evidence_freshness_signal=normalize_recency(age_days),
        rejected_correlation_count=rejected_correlations,
        dread_only=dread_match_count > 0 and urlhaus_match_count == 0 and not exact_hits,
    )
    source_reliability_confidence = external_signal_components["source_reliability_confidence"]
    external_signal_penalties = external_signal_components["external_signal_penalties"]

    penalties = 0.0
    if accepted_external == 0:
        penalties -= 0.08
        if exact_hits == 0 and high_signal_hits == 0 and entity_hits == 0 and semantic_signal == 0:
            penalties -= 0.03
    if not has_cvss:
        penalties -= 0.12
    if desc_len < 30:
        penalties -= 0.05
    if not products and not vuln_types and not impacts and not threat_terms:
        penalties -= 0.04
    if entity_alignment_only and semantic_signal < 0.30:
        penalties -= 0.03
    if age_days is not None and age_days > 3650 and accepted_external == 0:
        penalties -= 0.04
    penalties += external_signal_penalties

    raw_confidence = (
        base_confidence
        + metadata_confidence
        + entity_confidence
        + external_evidence_confidence
        + correlation_confidence
        + freshness_confidence
        + source_reliability_confidence
        + penalties
    )

    if not has_cvss and accepted_external == 0:
        raw_confidence = min(raw_confidence, 0.35)
        if keyword_count <= 3 and llm_fields_count == 0:
            raw_confidence = min(raw_confidence, 0.28)
    if dread_match_count > 0 and urlhaus_match_count == 0 and not exact_hits and not kev_listed:
        raw_confidence = min(raw_confidence, 0.68 if high_signal_hits else 0.55)

    confidence = round(max(0.05, min(raw_confidence, 0.95)), 3)
    breakdown = {
        "base_confidence": round(base_confidence, 3),
        "metadata_confidence": round(metadata_confidence, 3),
        "entity_confidence": round(entity_confidence, 3),
        "external_evidence_confidence": round(external_evidence_confidence, 3),
        "correlation_confidence": round(correlation_confidence, 3),
        "freshness_confidence": round(freshness_confidence, 3),
        "source_reliability_confidence": round(source_reliability_confidence, 3),
        "penalties": round(penalties, 3),
        "raw_confidence": round(raw_confidence, 3),
        "final_confidence": confidence,
        "signals": {
            "has_cvss": has_cvss,
            "cvss_version": cvss_version,
            "description_length": desc_len,
            "accepted_external_evidence": accepted_external,
            "exact_hits": exact_hits,
            "high_signal_hits": high_signal_hits,
            "entity_hits": entity_hits,
            "shared_term_count": len(shared_terms),
            "acceptance_reasons": sorted(acceptance_reasons),
            "entity_alignment_only": entity_alignment_only,
            "semantic_signal": round(semantic_signal, 4),
            "epss_available": bool(epss_available),
            "kev_status_known": bool(kev_status_known),
            "kev_listed": bool(kev_listed),
            "rejected_correlation_count": rejected_correlations,
            "dread_only": dread_match_count > 0 and urlhaus_match_count == 0 and not exact_hits,
        },
    }
    return ConfidenceResult(confidence=confidence, breakdown=breakdown)


def calculate_rejected_cve_confidence() -> ConfidenceResult:
    return ConfidenceResult(
        confidence=0.25,
        breakdown={
            "base_confidence": 0.0,
            "metadata_confidence": 0.0,
            "entity_confidence": 0.0,
            "external_evidence_confidence": 0.0,
            "correlation_confidence": 0.0,
            "freshness_confidence": 0.0,
            "penalties": -0.25,
            "raw_confidence": 0.25,
            "final_confidence": 0.25,
            "signals": {"validity_status": "invalid_or_rejected"},
        },
    )


def calculate_urlhaus_confidence(
    *,
    threat: str,
    tags: List[str],
    status: str,
    date_added: Any,
    related_cves: int,
    related_dread: int,
    graph_summary: Dict[str, Any],
    payload_signals: Dict[str, bool],
    family_signals: List[str],
    age_calculator: Optional[AgeCalculator] = None,
) -> ConfidenceResult:
    feed_confidence = 0.22
    status_confidence = 0.10 if status in {"online", "offline"} else 0.0
    threat_label_confidence = 0.12 if threat and threat != "unknown" else 0.0
    tag_confidence = min(len(tags) * 0.035, 0.16)
    payload_confidence = min(sum(1 for value in payload_signals.values() if value) * 0.045, 0.14)
    family_confidence = min(len(family_signals) * 0.055, 0.16)
    freshness_confidence = 0.0
    get_age_days = age_calculator or calculate_age_days
    age_days = get_age_days(str(date_added)) if date_added else None
    if age_days is not None:
        freshness_confidence = 0.08 if age_days <= 14 else 0.04 if age_days <= 30 else 0.0
    cross_source_confidence = min((related_cves * 0.025) + (related_dread * 0.05), 0.12)
    graph_confidence = min(float(graph_summary.get("structural_strength", 0.0) or 0.0) * 0.06, 0.06)
    penalties = 0.0
    if not tags:
        penalties -= 0.08
    if status == "offline":
        penalties -= 0.04
    if not date_added:
        penalties -= 0.05
    raw = (
        feed_confidence
        + status_confidence
        + threat_label_confidence
        + tag_confidence
        + payload_confidence
        + family_confidence
        + freshness_confidence
        + cross_source_confidence
        + graph_confidence
        + penalties
    )
    final = round(min(max(raw, 0.25), 0.92), 3)
    breakdown = {
        "feed_confidence": round(feed_confidence, 3),
        "status_confidence": round(status_confidence, 3),
        "threat_label_confidence": round(threat_label_confidence, 3),
        "tag_confidence": round(tag_confidence, 3),
        "payload_confidence": round(payload_confidence, 3),
        "family_confidence": round(family_confidence, 3),
        "freshness_confidence": round(freshness_confidence, 3),
        "cross_source_confidence": round(cross_source_confidence, 3),
        "graph_confidence": round(graph_confidence, 3),
        "penalties": round(penalties, 3),
        "raw_confidence": round(raw, 3),
        "final_confidence": final,
        "signals": {
            "url_status": status or "unknown",
            "tag_count": len(tags),
            "payload_signals": payload_signals,
            "malware_family_signals": family_signals,
            "related_cves": related_cves,
            "related_dread": related_dread,
            "date_added_present": bool(date_added),
        },
    }
    return ConfidenceResult(confidence=final, breakdown=breakdown)
