from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Tuple

from config import get_settings


SETTINGS = get_settings()


def extract_cvss_score(metrics: dict) -> Tuple[float, str]:
    metric_order = [
        ("cvss_metric_v40", "CVSS v4.0"),
        ("cvss_metric_v31", "CVSS v3.1"),
        ("cvss_metric_v30", "CVSS v3.0"),
        ("cvss_metric_v2", "CVSS v2.0"),
    ]

    for metric_key, metric_label in metric_order:
        metric_values = metrics.get(metric_key) or []
        if metric_values:
            cvss_data = metric_values[0].get("cvss_data", {})
            score = float(cvss_data.get("base_score", 0.0) or 0.0)
            return score, metric_label

    return 0.0, "Unknown"


def calculate_age_days(published_value: Optional[str]) -> Optional[int]:
    if not published_value:
        return None
    try:
        normalized = str(published_value).replace("Z", "+00:00")
        published_dt = datetime.fromisoformat(normalized)
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
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


def level_from_score(score: float) -> str:
    weights = SETTINGS.scoring
    if score >= weights.critical_threshold:
        return "CRITICAL"
    if score >= weights.high_threshold:
        return "HIGH"
    if score >= weights.medium_threshold:
        return "MEDIUM"
    return "LOW"
