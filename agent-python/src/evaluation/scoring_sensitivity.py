from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from analysis.scoring_signals import (
    DEFAULT_RISK_SIGNAL_WEIGHTS,
    RISK_SIGNAL_NAMES,
    calculate_risk_score_from_normalized_signals,
)
from evaluation.baselines import rank_records
from evaluation.datasets import EvaluationRecord
from evaluation.metrics import evaluate_ranking


SENSITIVITY_VARIANTS = (
    ("baseline", "", "baseline", {}),
    ("severity_plus", "severity_signal", "plus", {"severity_signal": 1.10}),
    ("severity_minus", "severity_signal", "minus", {"severity_signal": 0.90}),
    ("epss_plus", "epss_signal", "plus", {"epss_signal": 1.10}),
    ("epss_minus", "epss_signal", "minus", {"epss_signal": 0.90}),
    ("kev_plus", "kev_signal", "plus", {"kev_signal": 1.10}),
    ("kev_minus", "kev_signal", "minus", {"kev_signal": 0.90}),
    ("correlation_plus", "correlation_signal", "plus", {"correlation_signal": 1.10}),
    ("correlation_minus", "correlation_signal", "minus", {"correlation_signal": 0.90}),
    (
        "external_evidence_plus",
        "epss_signal,kev_signal,correlation_signal",
        "plus",
        {"epss_signal": 1.075, "kev_signal": 1.075, "correlation_signal": 1.075},
    ),
    (
        "external_evidence_minus",
        "epss_signal,kev_signal,correlation_signal",
        "minus",
        {"epss_signal": 0.925, "kev_signal": 0.925, "correlation_signal": 0.925},
    ),
)


@dataclass(frozen=True)
class SensitivityScore:
    cve_id: str
    score: float


def sensitivity_weight_variants(
    base_weights: Mapping[str, float] = DEFAULT_RISK_SIGNAL_WEIGHTS,
) -> dict[str, dict[str, Any]]:
    """Return deterministic bounded perturbations without mutating defaults."""
    variants: dict[str, dict[str, Any]] = {}
    for name, changed_weight, direction, multipliers in SENSITIVITY_VARIANTS:
        weights = {signal: float(base_weights[signal]) for signal in RISK_SIGNAL_NAMES}
        for signal, multiplier in multipliers.items():
            weights[signal] = round(weights[signal] * float(multiplier), 6)
        variants[name] = {
            "changed_weight": changed_weight,
            "direction": direction,
            "weights": weights,
        }
    return variants


def build_scoring_sensitivity_report(
    records: Sequence[EvaluationRecord],
    *,
    k_values: Sequence[int],
) -> dict[str, Any]:
    variants = sensitivity_weight_variants()
    baseline_scores = _variant_scores(records, variants["baseline"]["weights"])
    baseline_ranked = _rank_by_scores(records, baseline_scores)
    baseline_top5 = [record.cve_id for record in baseline_ranked[:5]]
    rows = []
    scores_by_variant = {}

    for name, metadata in variants.items():
        scores = _variant_scores(records, metadata["weights"])
        scores_by_variant[name] = [score.__dict__ for score in scores]
        ranked = _rank_by_scores(records, scores)
        top5 = [record.cve_id for record in ranked[:5]]
        guardrails = _guardrail_results(records, scores)
        metrics = evaluate_ranking(ranked, records, k_values=k_values)
        rows.append(
            {
                "variant": name,
                "changed_weight": metadata["changed_weight"],
                "direction": metadata["direction"],
                "weights": metadata["weights"],
                "ranking": [record.cve_id for record in ranked],
                "top5_cves": top5,
                "top5_overlap_with_baseline": len(set(top5) & set(baseline_top5)),
                "metrics": metrics,
                "guardrails": guardrails,
                "guardrails_passed": all(guardrails.values()),
                "notes": _variant_notes(name, guardrails),
            }
        )

    return {
        "variants": rows,
        "scores_by_variant": scores_by_variant,
        "baseline_top5": baseline_top5,
        "weight_policy": "bounded_multiplier_no_renormalization",
    }


def recompute_record_score(record: EvaluationRecord, weights: Mapping[str, float]) -> float:
    signals = {name: record.feature_breakdown.get(name, 0.0) for name in RISK_SIGNAL_NAMES}
    return float(calculate_risk_score_from_normalized_signals(signals, weights=weights)["risk_score_from_signals"])


def _variant_scores(records: Sequence[EvaluationRecord], weights: Mapping[str, float]) -> list[SensitivityScore]:
    return [
        SensitivityScore(cve_id=record.cve_id, score=recompute_record_score(record, weights))
        for record in records
    ]


def _rank_by_scores(records: Sequence[EvaluationRecord], scores: Sequence[SensitivityScore]) -> list[EvaluationRecord]:
    score_by_cve = {score.cve_id: score.score for score in scores}
    return rank_records(records, lambda record: score_by_cve[record.cve_id])


def _guardrail_results(records: Sequence[EvaluationRecord], scores: Sequence[SensitivityScore]) -> dict[str, bool]:
    by_id = {record.cve_id: record for record in records}
    score_by_id = {score.cve_id: score.score for score in scores}
    required = {"CVE-2026-9002", "CVE-2026-9005", "CVE-2026-9006", "CVE-2026-9007", "CVE-2026-9017"}
    if not required <= set(by_id):
        return {
            "fixture_guardrail_ids_present": False,
            "all_scores_bounded": all(0.0 <= score <= 10.0 for score in score_by_id.values()),
        }
    high_cvss_weak = by_id["CVE-2026-9007"]
    return {
        "medium_epss_kev_outranks_high_cvss_weak": score_by_id["CVE-2026-9002"] > score_by_id["CVE-2026-9007"],
        "high_cvss_weak_meaningful_not_critical": score_by_id["CVE-2026-9007"] >= 4.0 and score_by_id["CVE-2026-9007"] < 8.5,
        "accepted_correlation_beats_weak_rejected": score_by_id["CVE-2026-9005"] > score_by_id["CVE-2026-9006"],
        "dread_manual_review_bounded": (
            score_by_id["CVE-2026-9006"] < 8.5
            and score_by_id["CVE-2026-9017"] < 8.5
            and by_id["CVE-2026-9006"].model_confidence < 0.7
            and by_id["CVE-2026-9017"].model_confidence < 0.7
        ),
        "all_scores_bounded": all(0.0 <= score <= 10.0 for score in score_by_id.values()),
        "high_cvss_weak_has_expected_profile": (
            high_cvss_weak.cvss_score >= 9.0
            and (high_cvss_weak.epss_score or 0.0) <= 0.05
            and not high_cvss_weak.is_kev
        ),
    }


def _variant_notes(name: str, guardrails: Mapping[str, bool]) -> str:
    failed = [key for key, passed in guardrails.items() if not passed]
    if failed:
        return f"Qualitative guardrail changed: {', '.join(failed)}."
    if name == "baseline":
        return "Canonical fixture ranking recomputed from exported normalized signals."
    return "All qualitative guardrails remained stable under bounded perturbation."
