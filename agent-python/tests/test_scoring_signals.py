from analysis.scoring_signals import (
    RiskSignalInputs,
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


def test_external_signal_extraction_preserves_unknown_kev():
    missing = extract_external_risk_signals({})
    present = extract_external_risk_signals({"epss_score": "0.42", "is_kev": "true"})

    assert missing.epss_probability is None
    assert missing.kev_listed is None
    assert present.epss_probability == 0.42
    assert present.kev_listed is True
