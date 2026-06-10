from datetime import datetime, timezone

from analysis.features.cve_temporal import (
    calculate_age_days,
    evaluate_cve_temporal_features,
)


REFERENCE_TIME = datetime(2026, 6, 10, tzinfo=timezone.utc)


def test_recent_cve_gets_highest_recentness_bonus():
    features = evaluate_cve_temporal_features(
        "2026-06-08T00:00:00+00:00",
        active_evidence_count=0,
        reference_time=REFERENCE_TIME,
    )

    assert features.age_days == 2
    assert features.recentness_bonus == 1.2
    assert features.raw_age_penalty == 0.0
    assert features.age_penalty == 0.0
    assert features.temporal_score == 1.2


def test_medium_age_cve_gets_recentness_without_penalty():
    features = evaluate_cve_temporal_features(
        "2026-05-27T00:00:00+00:00",
        active_evidence_count=0,
        reference_time=REFERENCE_TIME,
    )

    assert features.age_days == 14
    assert features.recentness_bonus == 0.8
    assert features.raw_age_penalty == 0.0
    assert features.age_penalty == 0.0


def test_old_cve_gets_age_penalty():
    features = evaluate_cve_temporal_features(
        "2015-06-10T00:00:00+00:00",
        active_evidence_count=0,
        reference_time=REFERENCE_TIME,
    )

    assert features.age_days == 4018
    assert features.recentness_bonus == 0.0
    assert features.raw_age_penalty == 1.0
    assert features.age_penalty == 1.0
    assert features.temporal_score == -1.0


def test_missing_publication_date_has_no_temporal_score():
    features = evaluate_cve_temporal_features(
        None,
        active_evidence_count=0,
        reference_time=REFERENCE_TIME,
    )

    assert features.age_days is None
    assert features.recentness_bonus == 0.0
    assert features.raw_age_penalty == 0.0
    assert features.age_penalty == 0.0


def test_invalid_publication_date_has_no_temporal_score():
    features = evaluate_cve_temporal_features(
        "not-a-date",
        active_evidence_count=0,
        reference_time=REFERENCE_TIME,
    )

    assert features.age_days is None
    assert features.recentness_bonus == 0.0
    assert features.raw_age_penalty == 0.0
    assert features.age_penalty == 0.0


def test_recency_bonus_boundaries_are_inclusive():
    def features_for_age(age_days):
        return evaluate_cve_temporal_features(
            "ignored",
            active_evidence_count=0,
            age_calculator=lambda _value: age_days,
        )

    assert features_for_age(3).recentness_bonus == 1.2
    assert features_for_age(4).recentness_bonus == 0.8
    assert features_for_age(14).recentness_bonus == 0.8
    assert features_for_age(15).recentness_bonus == 0.4
    assert features_for_age(30).recentness_bonus == 0.4
    assert features_for_age(31).recentness_bonus == 0.0


def test_age_penalty_boundaries_and_active_evidence_cap():
    def features_for_age(age_days, active_evidence_count=0):
        return evaluate_cve_temporal_features(
            "ignored",
            active_evidence_count=active_evidence_count,
            age_calculator=lambda _value: age_days,
        )

    assert features_for_age(90).raw_age_penalty == 0.0
    assert features_for_age(91).raw_age_penalty == 0.15
    assert features_for_age(365).raw_age_penalty == 0.15
    assert features_for_age(366).raw_age_penalty == 0.45
    assert features_for_age(1825).raw_age_penalty == 0.45
    assert features_for_age(1826).raw_age_penalty == 0.75
    assert features_for_age(3650).raw_age_penalty == 0.75
    assert features_for_age(3651).raw_age_penalty == 1.0
    assert features_for_age(3651, active_evidence_count=1).age_penalty == 0.35


def test_future_publication_dates_clamp_age_to_zero():
    assert calculate_age_days("2026-06-11T00:00:00+00:00", reference_time=REFERENCE_TIME) == 0
