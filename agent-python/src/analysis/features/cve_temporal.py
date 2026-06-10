from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from config import get_settings


SETTINGS = get_settings()
AgeCalculator = Callable[[Optional[Any]], Optional[int]]


@dataclass(frozen=True)
class CveTemporalFeatures:
    age_days: Optional[int]
    recentness_bonus: float
    raw_age_penalty: float
    age_penalty: float

    @property
    def temporal_score(self) -> float:
        return self.recentness_bonus - self.age_penalty


def calculate_age_days(published_value: Optional[Any], *, reference_time: Optional[datetime] = None) -> Optional[int]:
    if not published_value:
        return None
    try:
        normalized = str(published_value).replace("Z", "+00:00")
        published_dt = datetime.fromisoformat(normalized)
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)
        now = reference_time or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return max((now - published_dt).days, 0)
    except Exception:
        return None


def calculate_recentness_bonus(age_days: Optional[int]) -> float:
    weights = SETTINGS.scoring
    if age_days is None:
        return 0.0
    if age_days <= 3:
        return weights.recentness_0_3_days
    if age_days <= 14:
        return weights.recentness_4_14_days
    if age_days <= 30:
        return weights.recentness_15_30_days
    return 0.0


def calculate_age_penalty(age_days: Optional[int]) -> float:
    weights = SETTINGS.scoring
    if age_days is None:
        return 0.0
    if age_days > 3650:
        return weights.age_penalty_3650_plus
    if age_days > 1825:
        return weights.age_penalty_1825_plus
    if age_days > 365:
        return weights.age_penalty_365_plus
    if age_days > 90:
        return weights.age_penalty_90_plus
    return 0.0


def adjust_age_penalty(raw_penalty: float, *, active_evidence_count: int) -> float:
    if raw_penalty <= 0:
        return 0.0
    if active_evidence_count > 0:
        return round(min(raw_penalty * 0.35, 0.35), 2)
    return round(min(raw_penalty, 1.0), 2)


def evaluate_cve_temporal_features(
    published_value: Optional[Any],
    *,
    active_evidence_count: int,
    reference_time: Optional[datetime] = None,
    age_calculator: Optional[AgeCalculator] = None,
) -> CveTemporalFeatures:
    if age_calculator is not None:
        age_days = age_calculator(published_value)
    else:
        age_days = calculate_age_days(published_value, reference_time=reference_time)
    recentness_bonus = calculate_recentness_bonus(age_days)
    raw_age_penalty = calculate_age_penalty(age_days)
    age_penalty = adjust_age_penalty(raw_age_penalty, active_evidence_count=active_evidence_count)
    return CveTemporalFeatures(
        age_days=age_days,
        recentness_bonus=recentness_bonus,
        raw_age_penalty=raw_age_penalty,
        age_penalty=age_penalty,
    )
