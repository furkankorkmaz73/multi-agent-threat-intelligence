from __future__ import annotations

import math
from typing import Callable, Iterable, List, Sequence

from evaluation.datasets import EvaluationRecord


LabelFn = Callable[[EvaluationRecord], bool]


def precision_at_k(ranked: Sequence[EvaluationRecord], k: int, label_fn: LabelFn = lambda record: record.exploited_label) -> float:
    top = _top_k(ranked, k)
    if not top:
        return 0.0
    return round(sum(1 for record in top if label_fn(record)) / len(top), 6)


def recall_at_k(ranked: Sequence[EvaluationRecord], all_records: Sequence[EvaluationRecord], k: int, label_fn: LabelFn = lambda record: record.exploited_label) -> float:
    positives = sum(1 for record in all_records if label_fn(record))
    if positives <= 0:
        return 0.0
    hits = sum(1 for record in _top_k(ranked, k) if label_fn(record))
    return round(hits / positives, 6)


def ndcg_at_k(ranked: Sequence[EvaluationRecord], k: int, label_fn: LabelFn = lambda record: record.exploited_label) -> float:
    top = _top_k(ranked, k)
    if not top:
        return 0.0
    gains = [1.0 if label_fn(record) else 0.0 for record in top]
    ideal = sorted([1.0 if label_fn(record) else 0.0 for record in ranked], reverse=True)[: len(top)]
    ideal_dcg = _dcg(ideal)
    if ideal_dcg <= 0:
        return 0.0
    return round(_dcg(gains) / ideal_dcg, 6)


def mean_reciprocal_rank(ranked: Sequence[EvaluationRecord], label_fn: LabelFn = lambda record: record.exploited_label) -> float:
    for index, record in enumerate(ranked, start=1):
        if label_fn(record):
            return round(1.0 / index, 6)
    return 0.0


def kev_hit_rate_at_k(ranked: Sequence[EvaluationRecord], k: int) -> float:
    return precision_at_k(ranked, k, label_fn=lambda record: record.is_kev)


def spearman_rank_correlation(
    records: Sequence[EvaluationRecord],
    score_a: Callable[[EvaluationRecord], float],
    score_b: Callable[[EvaluationRecord], float],
) -> float:
    rows = list(records)
    if len(rows) < 2:
        return 0.0
    ranks_a = _average_ranks([float(score_a(record) or 0.0) for record in rows])
    ranks_b = _average_ranks([float(score_b(record) or 0.0) for record in rows])
    mean_a = sum(ranks_a) / len(ranks_a)
    mean_b = sum(ranks_b) / len(ranks_b)
    numerator = sum((a - mean_a) * (b - mean_b) for a, b in zip(ranks_a, ranks_b))
    denom_a = math.sqrt(sum((a - mean_a) ** 2 for a in ranks_a))
    denom_b = math.sqrt(sum((b - mean_b) ** 2 for b in ranks_b))
    if denom_a <= 0 or denom_b <= 0:
        return 0.0
    return round(numerator / (denom_a * denom_b), 6)


def evaluate_ranking(
    ranked: Sequence[EvaluationRecord],
    all_records: Sequence[EvaluationRecord],
    *,
    k_values: Iterable[int],
) -> dict:
    return {
        f"precision_at_{k}": precision_at_k(ranked, k)
        for k in k_values
    } | {
        f"recall_at_{k}": recall_at_k(ranked, all_records, k)
        for k in k_values
    } | {
        f"ndcg_at_{k}": ndcg_at_k(ranked, k)
        for k in k_values
    } | {
        f"kev_hit_rate_at_{k}": kev_hit_rate_at_k(ranked, k)
        for k in k_values
    } | {"mrr": mean_reciprocal_rank(ranked)}


def _top_k(ranked: Sequence[EvaluationRecord], k: int) -> List[EvaluationRecord]:
    if k <= 0:
        return []
    return list(ranked[: min(k, len(ranked))])


def _dcg(values: Sequence[float]) -> float:
    return sum(float(value) / math.log2(index + 2) for index, value in enumerate(values))


def _average_ranks(values: Sequence[float]) -> List[float]:
    indexed = sorted(enumerate(values), key=lambda item: (item[1], item[0]))
    ranks = [0.0] * len(values)
    index = 0
    while index < len(indexed):
        end = index + 1
        while end < len(indexed) and indexed[end][1] == indexed[index][1]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        for original_index, _ in indexed[index:end]:
            ranks[original_index] = average_rank
        index = end
    return ranks
