from __future__ import annotations

from typing import Any, Optional, Tuple

from analysis.features.cve_temporal import (
    calculate_age_days as calculate_cve_age_days,
    calculate_age_penalty as calculate_cve_age_penalty,
    calculate_recentness_bonus as calculate_cve_recentness_bonus,
)
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


def calculate_age_days(published_value: Optional[Any]) -> Optional[int]:
    return calculate_cve_age_days(published_value)


def calculate_recentness_bonus(age_days: Optional[int]) -> float:
    return calculate_cve_recentness_bonus(age_days)


def calculate_age_penalty(age_days: Optional[int]) -> float:
    return calculate_cve_age_penalty(age_days)


def level_from_score(score: float) -> str:
    weights = SETTINGS.scoring
    if score >= weights.critical_threshold:
        return "CRITICAL"
    if score >= weights.high_threshold:
        return "HIGH"
    if score >= weights.medium_threshold:
        return "MEDIUM"
    return "LOW"
