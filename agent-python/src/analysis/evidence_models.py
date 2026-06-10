from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Mapping, Optional


class EvidenceSource(str, Enum):
    CVE = "cve"
    URLHAUS = "urlhaus"
    DREAD = "dread"
    CORRELATION = "correlation"
    DERIVED = "derived"


class EvidenceType(str, Enum):
    CVE_REFERENCE = "cve_reference"
    IOC = "ioc"
    DARKWEB_POST = "darkweb_post"
    KEYWORD_OVERLAP = "keyword_overlap"
    SEMANTIC_SIMILARITY = "semantic_similarity"
    TEMPORAL_PROXIMITY = "temporal_proximity"
    ENTITY_ALIGNMENT = "entity_alignment"
    HIGH_SIGNAL_TERMS = "high_signal_terms"
    CROSS_SOURCE_CORRELATION = "cross_source_correlation"


@dataclass(frozen=True)
class Provenance:
    source: EvidenceSource
    method: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "method": self.method,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class Evidence:
    source: EvidenceSource
    evidence_type: EvidenceType
    subject_identifier: str
    provenance: Provenance
    confidence: float
    reason: str
    related_object_identifier: Optional[str] = None
    observed_at: Optional[str] = None
    raw_reference: Optional[str] = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", max(0.0, min(float(self.confidence), 1.0)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source.value,
            "evidence_type": self.evidence_type.value,
            "subject_identifier": self.subject_identifier,
            "related_object_identifier": self.related_object_identifier,
            "observed_at": self.observed_at,
            "confidence": self.confidence,
            "provenance": self.provenance.to_dict(),
            "reason": self.reason,
            "raw_reference": self.raw_reference,
        }
