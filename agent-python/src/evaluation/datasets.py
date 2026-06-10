from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, Mapping, Optional


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)


def normalize_cve_id(value: Any) -> Optional[str]:
    text = str(value or "").strip().upper()
    return text if CVE_RE.fullmatch(text) else None


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def clamp(value: Any, low: float = 0.0, high: float = 1.0, default: float = 0.0) -> float:
    return max(low, min(safe_float(value, default), high))


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    date_added: Optional[str] = None
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    known_ransomware_campaign_use: Optional[str] = None
    due_date: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "date_added": self.date_added,
            "vendor_project": self.vendor_project,
            "product": self.product,
            "vulnerability_name": self.vulnerability_name,
            "known_ransomware_campaign_use": self.known_ransomware_campaign_use,
            "due_date": self.due_date,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class EpssEntry:
    cve_id: str
    epss: float
    percentile: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "epss", clamp(self.epss))
        object.__setattr__(self, "percentile", clamp(self.percentile))

    def to_dict(self) -> Dict[str, Any]:
        return {"cve_id": self.cve_id, "epss": self.epss, "percentile": self.percentile}


@dataclass(frozen=True)
class EvaluationRecord:
    cve_id: str
    model_risk_score: float
    model_confidence: float
    cvss_score: float
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False
    exploitation_evidence: Mapping[str, bool] = field(default_factory=dict)
    feature_breakdown: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        normalized = normalize_cve_id(self.cve_id)
        if normalized is None:
            raise ValueError(f"Invalid CVE identifier: {self.cve_id}")
        object.__setattr__(self, "cve_id", normalized)
        object.__setattr__(self, "model_risk_score", max(0.0, min(safe_float(self.model_risk_score), 10.0)))
        object.__setattr__(self, "model_confidence", clamp(self.model_confidence))
        object.__setattr__(self, "cvss_score", max(0.0, min(safe_float(self.cvss_score), 10.0)))
        if self.epss_score is not None:
            object.__setattr__(self, "epss_score", clamp(self.epss_score))
        if self.epss_percentile is not None:
            object.__setattr__(self, "epss_percentile", clamp(self.epss_percentile))

    @property
    def exploited_label(self) -> bool:
        return bool(self.is_kev or any(bool(value) for value in self.exploitation_evidence.values()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "model_risk_score": self.model_risk_score,
            "model_confidence": self.model_confidence,
            "cvss_score": self.cvss_score,
            "epss_score": self.epss_score,
            "epss_percentile": self.epss_percentile,
            "is_kev": self.is_kev,
            "exploited_label": self.exploited_label,
            "exploitation_evidence": dict(self.exploitation_evidence),
            "feature_breakdown": dict(self.feature_breakdown),
        }


@dataclass(frozen=True)
class ParseResult:
    items: Mapping[str, Any]
    total_rows: int
    valid_rows: int
    duplicate_rows: int
    malformed_rows: int
    missing_required_rows: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "valid_rows": self.valid_rows,
            "duplicate_rows": self.duplicate_rows,
            "malformed_rows": self.malformed_rows,
            "missing_required_rows": self.missing_required_rows,
        }


def records_from_model_results(rows: Iterable[Mapping[str, Any]]) -> tuple[list[EvaluationRecord], Dict[str, int]]:
    records: list[EvaluationRecord] = []
    seen: set[str] = set()
    stats = {"total_rows": 0, "valid_rows": 0, "duplicate_rows": 0, "malformed_rows": 0}
    for row in rows:
        stats["total_rows"] += 1
        cve_id = normalize_cve_id(row.get("cve_id") or row.get("entity_id") or row.get("_id"))
        if not cve_id:
            stats["malformed_rows"] += 1
            continue
        if cve_id in seen:
            stats["duplicate_rows"] += 1
            continue
        seen.add(cve_id)
        feature_breakdown = dict(row.get("feature_breakdown") or {})
        evidence = dict(row.get("evidence") or {})
        related_urlhaus_count = safe_float(row.get("related_urlhaus_count", evidence.get("related_urlhaus_count")))
        related_dread_count = safe_float(row.get("related_dread_count", evidence.get("related_dread_count")))
        flags = {
            "urlhaus": bool(related_urlhaus_count > 0),
            "dread": bool(related_dread_count > 0),
        }
        try:
            records.append(
                EvaluationRecord(
                    cve_id=cve_id,
                    model_risk_score=safe_float(row.get("risk_score", row.get("model_risk_score"))),
                    model_confidence=safe_float(row.get("confidence", row.get("model_confidence"))),
                    cvss_score=safe_float(row.get("cvss_score", evidence.get("cvss_score"))),
                    exploitation_evidence=flags,
                    feature_breakdown=feature_breakdown,
                )
            )
        except ValueError:
            stats["malformed_rows"] += 1
            continue
        stats["valid_rows"] += 1
    return records, stats


def join_external_signals(
    records: Iterable[EvaluationRecord],
    kev_entries: Mapping[str, KevEntry],
    epss_entries: Mapping[str, EpssEntry],
) -> list[EvaluationRecord]:
    joined: list[EvaluationRecord] = []
    for record in records:
        epss = epss_entries.get(record.cve_id)
        joined.append(
            EvaluationRecord(
                cve_id=record.cve_id,
                model_risk_score=record.model_risk_score,
                model_confidence=record.model_confidence,
                cvss_score=record.cvss_score,
                epss_score=epss.epss if epss else None,
                epss_percentile=epss.percentile if epss else None,
                is_kev=record.cve_id in kev_entries,
                exploitation_evidence=record.exploitation_evidence,
                feature_breakdown=record.feature_breakdown,
            )
        )
    return joined


def dataset_metadata(
    records: Iterable[EvaluationRecord],
    *,
    model_stats: Optional[Mapping[str, int]] = None,
    kev_stats: Optional[Mapping[str, Any]] = None,
    epss_stats: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    rows = list(records)
    return {
        "record_count": len(rows),
        "kev_count": sum(1 for row in rows if row.is_kev),
        "epss_available_count": sum(1 for row in rows if row.epss_score is not None),
        "missing_epss_count": sum(1 for row in rows if row.epss_score is None),
        "missing_cvss_count": sum(1 for row in rows if row.cvss_score <= 0),
        "positive_label_count": sum(1 for row in rows if row.exploited_label),
        "model_parse": dict(model_stats or {}),
        "kev_parse": dict(kev_stats or {}),
        "epss_parse": dict(epss_stats or {}),
    }


ScoreCallback = Callable[[EvaluationRecord], float]
