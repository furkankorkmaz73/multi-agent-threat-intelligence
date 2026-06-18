from analysis.scoring_signals import (
    DEFAULT_RISK_SIGNAL_WEIGHTS,
    RISK_SIGNAL_NAMES,
    RiskSignalInputs,
    calculate_risk_score_from_normalized_signals,
    calculate_risk_signal_breakdown,
    clamp01,
    extract_external_risk_signals,
    normalize_cvss,
    normalize_epss,
    normalize_kev,
    normalize_recency,
)


def test_normalized_signal_values_are_bounded():
    values = [
        clamp01(2.0),
        clamp01(-1.0),
        normalize_cvss(12.0),
        normalize_epss("1.5"),
        normalize_kev(True),
        normalize_kev(False),
        normalize_recency(None),
        normalize_recency(9999),
    ]

    assert all(0.0 <= value <= 1.0 for value in values)
    assert normalize_cvss(9.8) == 0.98
    assert normalize_epss(None) == 0.0


def test_risk_signal_breakdown_is_bounded_and_explainable():
    breakdown = calculate_risk_signal_breakdown(
        RiskSignalInputs(
            cvss_score=9.8,
            epss_probability=0.94,
            kev_listed=True,
            age_days=5,
            urlhaus_score=1.2,
            dread_score=0.2,
            graph_centrality=0.4,
            nlp_context_score=0.8,
        )
    )

    for key in (
        "severity_signal",
        "epss_signal",
        "kev_signal",
        "recency_signal",
        "correlation_signal",
        "graph_signal",
        "nlp_context_signal",
    ):
        assert 0.0 <= breakdown[key] <= 1.0
    assert 0.0 <= breakdown["risk_score_from_signals"] <= 10.0
    assert breakdown["risk_raw"] >= breakdown["risk_score_from_signals"]
    assert set(breakdown["risk_signal_weights"]) == set(RISK_SIGNAL_NAMES)
    assert breakdown["risk_signal_weights"] == dict(DEFAULT_RISK_SIGNAL_WEIGHTS)
    assert round(sum(breakdown["risk_signal_contributions"].values()), 6) == breakdown["weighted_signal_score"]


def test_normalized_signal_helper_uses_canonical_weights():
    breakdown = calculate_risk_score_from_normalized_signals(
        {
            "severity_signal": 0.65,
            "epss_signal": 0.91,
            "kev_signal": 1.0,
            "recency_signal": 0.45,
            "correlation_signal": 0.0,
            "graph_signal": 0.0,
            "nlp_context_signal": 1.0,
        }
    )

    assert breakdown["risk_signal_weights"] == dict(DEFAULT_RISK_SIGNAL_WEIGHTS)
    expected_weighted = round(
        sum(breakdown[name] * DEFAULT_RISK_SIGNAL_WEIGHTS[name] for name in RISK_SIGNAL_NAMES),
        6,
    )
    assert breakdown["weighted_signal_score"] == expected_weighted
    assert breakdown["risk_score_from_signals"] == round(expected_weighted * 10.0, 2)


def test_intrinsic_criticality_floor_is_bounded_and_explainable():
    breakdown = calculate_risk_score_from_normalized_signals(
        {
            "severity_signal": 1.0,
            "epss_signal": 0.0,
            "kev_signal": 0.0,
            "recency_signal": 0.8,
            "correlation_signal": 0.0,
            "graph_signal": 0.0,
            "nlp_context_signal": 1.0,
        }
    )

    assert breakdown["score_before_intrinsic_floor"] == 7.8
    assert breakdown["intrinsic_criticality_floor_applied"] is True
    assert breakdown["intrinsic_criticality_floor_value"] == 8.1
    assert breakdown["risk_score_from_signals"] == 8.1
    assert breakdown["risk_raw"] == 7.8


def test_intrinsic_criticality_floor_requires_all_thresholds():
    base = {
        "severity_signal": 1.0,
        "epss_signal": 0.0,
        "kev_signal": 0.0,
        "recency_signal": 0.8,
        "correlation_signal": 0.0,
        "graph_signal": 0.0,
        "nlp_context_signal": 1.0,
    }

    for changed_signal, value in (
        ("severity_signal", 0.97),
        ("nlp_context_signal", 0.79),
        ("recency_signal", 0.49),
    ):
        signals = {**base, changed_signal: value}
        breakdown = calculate_risk_score_from_normalized_signals(signals)

        assert breakdown["intrinsic_criticality_floor_applied"] is False
        assert breakdown["risk_score_from_signals"] == breakdown["score_before_intrinsic_floor"]


def test_old_low_recency_high_context_does_not_receive_intrinsic_floor():
    breakdown = calculate_risk_score_from_normalized_signals(
        {
            "severity_signal": 1.0,
            "epss_signal": 0.0,
            "kev_signal": 0.0,
            "recency_signal": 0.05,
            "correlation_signal": 0.0,
            "graph_signal": 0.0,
            "nlp_context_signal": 1.0,
        }
    )

    assert breakdown["intrinsic_criticality_floor_applied"] is False
    assert breakdown["risk_score_from_signals"] == breakdown["score_before_intrinsic_floor"]
    assert breakdown["risk_score_from_signals"] < 8.1


def test_intrinsic_criticality_floor_does_not_inflate_scores_above_floor():
    breakdown = calculate_risk_score_from_normalized_signals(
        {
            "severity_signal": 1.0,
            "epss_signal": 1.0,
            "kev_signal": 1.0,
            "recency_signal": 1.0,
            "correlation_signal": 1.0,
            "graph_signal": 1.0,
            "nlp_context_signal": 1.0,
        }
    )

    assert breakdown["score_before_intrinsic_floor"] > 8.1
    assert breakdown["intrinsic_criticality_floor_applied"] is False
    assert breakdown["risk_score_from_signals"] == breakdown["score_before_intrinsic_floor"]


def test_intrinsic_criticality_floor_does_not_affect_medium_severity():
    breakdown = calculate_risk_score_from_normalized_signals(
        {
            "severity_signal": 0.65,
            "epss_signal": 0.0,
            "kev_signal": 0.0,
            "recency_signal": 1.0,
            "correlation_signal": 0.0,
            "graph_signal": 0.0,
            "nlp_context_signal": 1.0,
        }
    )

    assert breakdown["intrinsic_criticality_floor_applied"] is False
    assert breakdown["risk_score_from_signals"] == breakdown["score_before_intrinsic_floor"]


def test_external_signal_extraction_preserves_unknown_kev():
    missing = extract_external_risk_signals({})
    present = extract_external_risk_signals({"epss_score": "0.42", "is_kev": "true"})

    assert missing.epss_probability is None
    assert missing.kev_listed is None
    assert present.epss_probability == 0.42
    assert present.kev_listed is True


def test_external_signal_extraction_reads_nested_cve_enrichment():
    signals = extract_external_risk_signals(
        {
            "enrichment": {
                "epss": {"available": True, "probability": "0.91", "percentile": "0.99"},
                "kev": {"status_known": True, "listed": False},
            }
        }
    )

    assert signals.epss_probability == 0.91
    assert signals.epss_available is True
    assert signals.kev_listed is False
    assert signals.kev_status_known is True


def test_external_signal_extraction_preserves_missing_nested_data_semantics():
    unavailable = extract_external_risk_signals(
        {
            "enrichment": {
                "epss": {"available": False},
                "kev": {"status_known": False, "listed": False},
            }
        }
    )
    listed = extract_external_risk_signals({"enrichment": {"kev": {"status_known": True, "listed": True}}})

    assert unavailable.epss_probability is None
    assert unavailable.kev_listed is None
    assert listed.kev_listed is True
