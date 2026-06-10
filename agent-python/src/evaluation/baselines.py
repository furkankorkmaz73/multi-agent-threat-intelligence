from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterable, List

from evaluation.datasets import EvaluationRecord


ScoreFn = Callable[[EvaluationRecord], float]


@dataclass(frozen=True)
class RankingStrategy:
    name: str
    score_fn: ScoreFn

    def score(self, record: EvaluationRecord) -> float:
        return float(self.score_fn(record) or 0.0)

    def rank(self, records: Iterable[EvaluationRecord]) -> List[EvaluationRecord]:
        return rank_records(records, self.score_fn)


def rank_records(records: Iterable[EvaluationRecord], score_fn: ScoreFn) -> List[EvaluationRecord]:
    return sorted(records, key=lambda record: (-float(score_fn(record) or 0.0), record.cve_id))


def cvss_score(record: EvaluationRecord) -> float:
    return record.cvss_score


def epss_score(record: EvaluationRecord) -> float:
    return (record.epss_score or 0.0) * 10.0


def cvss_epss_score(record: EvaluationRecord) -> float:
    return round((record.cvss_score * 0.6) + (epss_score(record) * 0.4), 6)


def model_risk_score(record: EvaluationRecord) -> float:
    return record.model_risk_score


def model_confidence_weighted_score(record: EvaluationRecord) -> float:
    return round(record.model_risk_score * record.model_confidence, 6)


def model_confidence_filtered_score(record: EvaluationRecord, *, threshold: float = 0.6) -> float:
    return record.model_risk_score if record.model_confidence >= threshold else 0.0


def default_ranking_strategies(*, confidence_threshold: float = 0.6) -> List[RankingStrategy]:
    return [
        RankingStrategy("cvss_only", cvss_score),
        RankingStrategy("epss_only", epss_score),
        RankingStrategy("cvss_epss", cvss_epss_score),
        RankingStrategy("model_risk", model_risk_score),
        RankingStrategy("model_confidence_weighted", model_confidence_weighted_score),
        RankingStrategy(
            "model_confidence_filtered",
            lambda record: model_confidence_filtered_score(record, threshold=confidence_threshold),
        ),
    ]
