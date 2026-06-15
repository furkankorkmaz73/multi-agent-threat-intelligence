from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

from analysis.evidence_models import Evidence, EvidenceSource, EvidenceType, Provenance


class CorrelationDecisionStatus(str, Enum):
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    MANUAL_REVIEW = "manual_review"


@dataclass(frozen=True)
class CorrelationCandidate:
    source_identifier: str
    target_identifier: str
    relation_type: str
    evidence: tuple[Evidence, ...]
    lexical_score: float
    semantic_score: float
    temporal_score: float
    entity_score: float
    shared_term_count: int
    exact_cve: bool
    high_signal_term_hits: int
    entity_matches: Mapping[str, List[str]] = field(default_factory=dict)
    source: str = "unknown"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_identifier": self.source_identifier,
            "target_identifier": self.target_identifier,
            "relation_type": self.relation_type,
            "evidence": [item.to_dict() for item in self.evidence],
            "lexical_score": round(float(self.lexical_score), 4),
            "semantic_score": round(float(self.semantic_score), 4),
            "temporal_score": round(float(self.temporal_score), 4),
            "entity_score": round(float(self.entity_score), 4),
            "shared_term_count": int(self.shared_term_count),
            "exact_cve": bool(self.exact_cve),
            "high_signal_term_hits": int(self.high_signal_term_hits),
            "entity_matches": {key: list(value) for key, value in self.entity_matches.items()},
            "source": self.source,
        }


@dataclass(frozen=True)
class CorrelationDecision:
    status: CorrelationDecisionStatus
    source_identifier: str
    target_identifier: str
    relation_type: str
    final_confidence: float
    evidence_references: tuple[Evidence, ...]
    reasons: tuple[str, ...]
    provenance_summary: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "final_confidence", max(0.0, min(float(self.final_confidence), 1.0)))

    @property
    def primary_reason(self) -> str:
        return self.reasons[0] if self.reasons else ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "source_identifier": self.source_identifier,
            "target_identifier": self.target_identifier,
            "relation_type": self.relation_type,
            "final_confidence": round(float(self.final_confidence), 4),
            "evidence_references": [item.to_dict() for item in self.evidence_references],
            "reasons": list(self.reasons),
            "provenance_summary": dict(self.provenance_summary),
        }


def decide_correlation_candidate(candidate: CorrelationCandidate, *, min_shared_terms: int, min_lexical_overlap: float, min_semantic_support: float) -> CorrelationDecision:
    reason = _accepted_reason(
        source=candidate.source,
        lexical=candidate.lexical_score,
        semantic=candidate.semantic_score,
        temporal=candidate.temporal_score,
        entity_score=candidate.entity_score,
        shared_term_count=candidate.shared_term_count,
        exact_cve=candidate.exact_cve,
        high_signal_term_hits=candidate.high_signal_term_hits,
        entity_matches=candidate.entity_matches,
        min_shared_terms=min_shared_terms,
        min_lexical_overlap=min_lexical_overlap,
        min_semantic_support=min_semantic_support,
    )
    if reason:
        return _decision(candidate, CorrelationDecisionStatus.ACCEPTED, reason)

    if _requires_manual_review(candidate):
        return _decision(candidate, CorrelationDecisionStatus.MANUAL_REVIEW, "ambiguous_support")
    return _decision(candidate, CorrelationDecisionStatus.REJECTED, "weak_support")


def correlation_decision_row(candidate: CorrelationCandidate, decision: CorrelationDecision) -> Dict[str, Any]:
    return {
        "source_identifier": candidate.source_identifier,
        "target_identifier": candidate.target_identifier,
        "source": candidate.source,
        "lexical_score": round(float(candidate.lexical_score), 4),
        "semantic_score": round(float(candidate.semantic_score), 4),
        "temporal_score": round(float(candidate.temporal_score), 4),
        "entity_score": round(float(candidate.entity_score), 4),
        "shared_term_count": int(candidate.shared_term_count),
        "exact_cve": bool(candidate.exact_cve),
        "high_signal_term_hits": int(candidate.high_signal_term_hits),
        "decision": decision.status.value,
        "primary_reason": decision.primary_reason,
        "final_confidence": round(float(decision.final_confidence), 4),
        "evidence_types": ",".join(decision.provenance_summary.get("evidence_types", [])),
        "provenance_sources": ",".join(decision.provenance_summary.get("sources", [])),
    }


def build_correlation_candidate(
    *,
    source: str,
    source_identifier: str,
    target_identifier: str,
    relation_type: str,
    lexical: float,
    semantic: float,
    temporal: float,
    entity_score: float,
    shared_term_count: int,
    exact_cve: bool,
    high_signal_term_hits: int,
    entity_matches: Optional[Mapping[str, List[str]]] = None,
    observed_at: Optional[str] = None,
    raw_reference: Optional[str] = None,
) -> CorrelationCandidate:
    evidence = build_candidate_evidence(
        source=source,
        source_identifier=source_identifier,
        target_identifier=target_identifier,
        lexical=lexical,
        semantic=semantic,
        temporal=temporal,
        entity_score=entity_score,
        exact_cve=exact_cve,
        high_signal_term_hits=high_signal_term_hits,
        observed_at=observed_at,
        raw_reference=raw_reference,
    )
    return CorrelationCandidate(
        source_identifier=source_identifier,
        target_identifier=target_identifier,
        relation_type=relation_type,
        evidence=tuple(evidence),
        lexical_score=lexical,
        semantic_score=semantic,
        temporal_score=temporal,
        entity_score=entity_score,
        shared_term_count=shared_term_count,
        exact_cve=exact_cve,
        high_signal_term_hits=high_signal_term_hits,
        entity_matches=dict(entity_matches or {}),
        source=source,
    )


def build_candidate_evidence(
    *,
    source: str,
    source_identifier: str,
    target_identifier: str,
    lexical: float,
    semantic: float,
    temporal: float,
    entity_score: float,
    exact_cve: bool,
    high_signal_term_hits: int,
    observed_at: Optional[str],
    raw_reference: Optional[str],
) -> List[Evidence]:
    provenance = Provenance(
        source=EvidenceSource(source) if source in {item.value for item in EvidenceSource} else EvidenceSource.CORRELATION,
        method="hybrid_correlation",
        metadata={"source": source},
    )
    evidence: List[Evidence] = []
    if exact_cve:
        evidence.append(_evidence(EvidenceType.CVE_REFERENCE, source_identifier, target_identifier, 1.0, "exact_cve", provenance, observed_at, raw_reference))
    if high_signal_term_hits:
        evidence.append(
            _evidence(
                EvidenceType.HIGH_SIGNAL_TERMS,
                source_identifier,
                target_identifier,
                min(1.0, high_signal_term_hits / 3.0),
                "high_signal_terms",
                provenance,
                observed_at,
                raw_reference,
            )
        )
    if lexical > 0:
        evidence.append(_evidence(EvidenceType.KEYWORD_OVERLAP, source_identifier, target_identifier, lexical, "lexical_overlap", provenance, observed_at, raw_reference))
    if semantic > 0:
        evidence.append(_evidence(EvidenceType.SEMANTIC_SIMILARITY, source_identifier, target_identifier, semantic, "semantic_similarity", provenance, observed_at, raw_reference))
    if temporal > 0:
        evidence.append(_evidence(EvidenceType.TEMPORAL_PROXIMITY, source_identifier, target_identifier, temporal, "temporal_proximity", provenance, observed_at, raw_reference))
    if entity_score > 0:
        evidence.append(_evidence(EvidenceType.ENTITY_ALIGNMENT, source_identifier, target_identifier, entity_score, "entity_alignment", provenance, observed_at, raw_reference))
    if not evidence:
        evidence.append(_evidence(EvidenceType.CROSS_SOURCE_CORRELATION, source_identifier, target_identifier, 0.0, "weak_support", provenance, observed_at, raw_reference))
    return evidence


def _accepted_reason(
    *,
    source: str,
    lexical: float,
    semantic: float,
    temporal: float,
    entity_score: float,
    shared_term_count: int,
    exact_cve: bool,
    high_signal_term_hits: int,
    entity_matches: Mapping[str, List[str]],
    min_shared_terms: int,
    min_lexical_overlap: float,
    min_semantic_support: float,
) -> str:
    if exact_cve:
        return "exact_cve"

    if source == "urlhaus":
        strong_entity_group = bool(
            entity_matches.get("cve_ids")
            or entity_matches.get("domains")
            or entity_matches.get("threat_terms")
        )
        has_meaningful_support = shared_term_count >= 1 or high_signal_term_hits >= 1 or strong_entity_group
        if entity_score >= 0.35 and has_meaningful_support and (semantic >= 0.18 or lexical >= 0.08):
            return "entity_alignment"
    elif source == "dread":
        if entity_score >= 0.45 and high_signal_term_hits >= 1 and shared_term_count >= 1 and (semantic >= 0.22 or lexical >= 0.12):
            return "entity_alignment"
    elif entity_score >= 0.30 and (semantic >= 0.10 or lexical >= 0.04):
        return "entity_alignment"

    if source == "dread":
        if high_signal_term_hits >= 2 and (shared_term_count >= 1 or temporal >= 0.2) and (lexical >= 0.06 or semantic >= 0.18):
            return "high_signal_terms"
        if shared_term_count >= max(min_shared_terms + 1, 3) and high_signal_term_hits >= 1 and lexical >= max(min_lexical_overlap * 1.5, 0.14):
            return "lexical_overlap"
        if semantic >= max(min_semantic_support, 0.34) and temporal >= 0.3 and shared_term_count >= 1 and high_signal_term_hits >= 1:
            return "semantic_temporal_support"
        return ""

    if high_signal_term_hits >= 2 and (lexical >= 0.06 or semantic >= 0.18):
        return "high_signal_terms"
    if shared_term_count >= min_shared_terms and lexical >= min_lexical_overlap:
        return "lexical_overlap"
    if semantic >= max(min_semantic_support, 0.30) and temporal >= 0.2 and shared_term_count >= 1:
        return "semantic_temporal_support"
    return ""


def _requires_manual_review(candidate: CorrelationCandidate) -> bool:
    if candidate.exact_cve:
        return False
    if candidate.source == "urlhaus" and candidate.entity_score >= 0.30 and candidate.semantic_score >= 0.12:
        return True
    if candidate.source == "dread" and candidate.high_signal_term_hits >= 1 and max(candidate.lexical_score, candidate.semantic_score) >= 0.12:
        return True
    if candidate.source == "dread" and candidate.entity_score >= 0.35 and candidate.shared_term_count >= 1:
        return True
    if candidate.high_signal_term_hits == 1 and max(candidate.lexical_score, candidate.semantic_score) >= 0.12:
        return True
    if candidate.shared_term_count > 0 and candidate.semantic_score >= 0.25:
        return True
    return False


def _decision(candidate: CorrelationCandidate, status: CorrelationDecisionStatus, reason: str) -> CorrelationDecision:
    provenance_sources = sorted({item.provenance.source.value for item in candidate.evidence})
    evidence_types = sorted({item.evidence_type.value for item in candidate.evidence})
    final_confidence = max((item.confidence for item in candidate.evidence), default=0.0)
    return CorrelationDecision(
        status=status,
        source_identifier=candidate.source_identifier,
        target_identifier=candidate.target_identifier,
        relation_type=candidate.relation_type,
        final_confidence=final_confidence,
        evidence_references=candidate.evidence,
        reasons=(reason,),
        provenance_summary={
            "sources": provenance_sources,
            "evidence_types": evidence_types,
            "evidence_count": len(candidate.evidence),
        },
    )


def _evidence(
    evidence_type: EvidenceType,
    subject_identifier: str,
    related_object_identifier: str,
    confidence: float,
    reason: str,
    provenance: Provenance,
    observed_at: Optional[str],
    raw_reference: Optional[str],
) -> Evidence:
    return Evidence(
        source=provenance.source,
        evidence_type=evidence_type,
        subject_identifier=subject_identifier,
        related_object_identifier=related_object_identifier,
        observed_at=observed_at,
        confidence=confidence,
        provenance=provenance,
        reason=reason,
        raw_reference=raw_reference,
    )
