from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def clamp01(value: Any, default: float = 0.0) -> float:
    return max(0.0, min(safe_float(value, default), 1.0))


def clamp_score(value: Any) -> float:
    return max(0.0, min(safe_float(value), 10.0))


def normalize_cvss(cvss_score: Any) -> float:
    return round(clamp_score(cvss_score) / 10.0, 4)


def normalize_epss(epss_probability: Any) -> float:
    return round(clamp01(epss_probability), 4)


def normalize_kev(is_known_exploited: Any) -> float:
    return 1.0 if bool(is_known_exploited) else 0.0


def normalize_recency(age_days: Optional[int]) -> float:
    if age_days is None:
        return 0.20
    if age_days <= 7:
        return 1.0
    if age_days <= 30:
        return 0.80
    if age_days <= 180:
        return 0.45
    if age_days <= 365:
        return 0.30
    if age_days <= 1825:
        return 0.15
    return 0.05


def normalize_correlation(*, urlhaus_score: Any = 0.0, dread_score: Any = 0.0, cap: float = 3.5) -> float:
    if cap <= 0:
        return 0.0
    return round(clamp01((safe_float(urlhaus_score) + safe_float(dread_score)) / cap), 4)


def normalize_graph(graph_centrality: Any) -> float:
    return round(clamp01(graph_centrality), 4)


def normalize_nlp_context(nlp_context_score: Any, *, cap: float = 1.2) -> float:
    if cap <= 0:
        return 0.0
    return round(clamp01(safe_float(nlp_context_score) / cap), 4)


@dataclass(frozen=True)
class ExternalRiskSignals:
    epss_probability: float | None = None
    kev_listed: bool | None = None

    @property
    def epss_available(self) -> bool:
        return self.epss_probability is not None

    @property
    def kev_status_known(self) -> bool:
        return self.kev_listed is not None


@dataclass(frozen=True)
class RiskSignalInputs:
    cvss_score: float
    epss_probability: float | None
    kev_listed: bool | None
    age_days: Optional[int]
    urlhaus_score: float
    dread_score: float
    graph_centrality: float
    nlp_context_score: float


RISK_SIGNAL_NAMES = (
    "severity_signal",
    "epss_signal",
    "kev_signal",
    "recency_signal",
    "correlation_signal",
    "graph_signal",
    "nlp_context_signal",
)

DEFAULT_RISK_SIGNAL_WEIGHTS: Mapping[str, float] = {
    "severity_signal": 0.68,
    "epss_signal": 0.12,
    "kev_signal": 0.12,
    "recency_signal": 0.05,
    "correlation_signal": 0.12,
    "graph_signal": 0.03,
    "nlp_context_signal": 0.06,
}


def extract_external_risk_signals(data: Mapping[str, Any], explicit: Mapping[str, Any] | None = None) -> ExternalRiskSignals:
    payload = {**dict(data or {}), **dict(explicit or {})}
    epss_raw = _first_present(payload, "epss_probability", "epss_score", "epss")
    kev_raw = _first_present(payload, "kev_listed", "is_kev", "known_exploited", "cisa_kev")
    epss_probability = normalize_epss(epss_raw) if epss_raw is not None else None
    kev_listed = _parse_optional_bool(kev_raw)
    return ExternalRiskSignals(epss_probability=epss_probability, kev_listed=kev_listed)


def calculate_risk_signal_breakdown(inputs: RiskSignalInputs, *, weights: Mapping[str, float] = DEFAULT_RISK_SIGNAL_WEIGHTS) -> dict[str, Any]:
    signals = {
        "severity_signal": normalize_cvss(inputs.cvss_score),
        "epss_signal": normalize_epss(inputs.epss_probability) if inputs.epss_probability is not None else 0.0,
        "kev_signal": normalize_kev(inputs.kev_listed is True),
        "recency_signal": normalize_recency(inputs.age_days),
        "correlation_signal": normalize_correlation(urlhaus_score=inputs.urlhaus_score, dread_score=inputs.dread_score),
        "graph_signal": normalize_graph(inputs.graph_centrality),
        "nlp_context_signal": normalize_nlp_context(inputs.nlp_context_score),
    }
    breakdown = calculate_risk_score_from_normalized_signals(signals, weights=weights)
    return {
        **breakdown,
        "epss_available": inputs.epss_probability is not None,
        "kev_status_known": inputs.kev_listed is not None,
    }


def calculate_risk_score_from_normalized_signals(signals: Mapping[str, Any], *, weights: Mapping[str, float] = DEFAULT_RISK_SIGNAL_WEIGHTS) -> dict[str, Any]:
    normalized = {name: round(clamp01(signals.get(name, 0.0)), 4) for name in RISK_SIGNAL_NAMES}
    contributions = {name: round(normalized[name] * float(weights.get(name, 0.0)), 6) for name in RISK_SIGNAL_NAMES}
    risk_raw_01 = round(sum(contributions.values()), 6)
    risk_raw = round(risk_raw_01 * 10.0, 4)
    risk_score = round(clamp_score(risk_raw), 2)
    return {
        **normalized,
        "risk_signal_weights": {name: round(float(weights.get(name, 0.0)), 4) for name in RISK_SIGNAL_NAMES},
        "risk_signal_contributions": contributions,
        "weighted_signal_score": risk_raw_01,
        "risk_raw": risk_raw,
        "risk_score_from_signals": risk_score,
    }


def calculate_confidence_signal_components(
    *,
    epss_available: bool,
    kev_status_known: bool,
    kev_listed: bool,
    accepted_external_evidence_count: int,
    evidence_freshness_signal: float,
    rejected_correlation_count: int = 0,
    dread_only: bool = False,
) -> dict[str, Any]:
    source_reliability = 0.0
    if epss_available:
        source_reliability += 0.03
    if kev_status_known:
        source_reliability += 0.03
    if kev_listed:
        source_reliability += 0.08
    if accepted_external_evidence_count:
        source_reliability += min(accepted_external_evidence_count * 0.025, 0.08)
    if dread_only:
        source_reliability -= 0.04

    evidence_freshness = min(clamp01(evidence_freshness_signal) * 0.05, 0.05)
    penalties = 0.0
    if not epss_available:
        penalties -= 0.025
    if not kev_status_known:
        penalties -= 0.02
    if rejected_correlation_count:
        penalties -= min(rejected_correlation_count * 0.01, 0.05)

    return {
        "source_reliability_confidence": round(max(source_reliability, -0.05), 3),
        "evidence_freshness_confidence": round(evidence_freshness, 3),
        "external_signal_penalties": round(penalties, 3),
        "signals": {
            "epss_available": bool(epss_available),
            "kev_status_known": bool(kev_status_known),
            "kev_listed": bool(kev_listed),
            "accepted_external_evidence_count": int(accepted_external_evidence_count),
            "rejected_correlation_count": int(rejected_correlation_count),
            "dread_only": bool(dread_only),
        },
    }


def _first_present(payload: Mapping[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload and payload[key] is not None:
            return payload[key]
    return None


def _parse_optional_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "known", "listed"}:
        return True
    if text in {"0", "false", "no", "n", "unknown", "not_listed"}:
        return False
    return None
