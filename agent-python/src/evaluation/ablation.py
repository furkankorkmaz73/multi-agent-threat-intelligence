from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional

from evaluation.baselines import RankingStrategy, rank_records
from evaluation.datasets import EvaluationRecord
from evaluation.metrics import evaluate_ranking


AblationScoreFn = Callable[[EvaluationRecord], float]


@dataclass(frozen=True)
class AblationVariant:
    name: str
    score_fn: AblationScoreFn


def feature_score_variant(feature_name: str, *, fallback: str = "model_risk_score") -> AblationVariant:
    def score(record: EvaluationRecord) -> float:
        if feature_name in record.feature_breakdown:
            return float(record.feature_breakdown.get(feature_name) or 0.0)
        return float(getattr(record, fallback, 0.0) or 0.0)

    return AblationVariant(feature_name, score)


def evaluate_ablations(
    records: Iterable[EvaluationRecord],
    variants: Iterable[AblationVariant],
    *,
    k_values: Iterable[int],
    baseline: Optional[RankingStrategy] = None,
) -> dict:
    rows = list(records)
    result = {}
    if baseline is not None:
        ranked = baseline.rank(rows)
        result[baseline.name] = evaluate_ranking(ranked, rows, k_values=k_values)
    for variant in variants:
        ranked = rank_records(rows, variant.score_fn)
        result[variant.name] = evaluate_ranking(ranked, rows, k_values=k_values)
    return result


def variants_from_score_columns(score_columns: Mapping[str, str]) -> list[AblationVariant]:
    return [feature_score_variant(column, fallback="model_risk_score") for column in score_columns.values()]
