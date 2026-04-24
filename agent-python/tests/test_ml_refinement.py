from evaluation.ml_refinement import apply_refinement_delta, attach_refinement_preview, build_refinement_feature_frame


def test_build_refinement_feature_frame_adds_proxy_features():
    rows = [{
        "cve_id": "CVE-1",
        "risk_score": 7.5,
        "graph_bonus": 0.8,
        "related_urlhaus_count": 2,
        "related_dread_count": 1,
        "age_days": 2,
    }]

    df = build_refinement_feature_frame(rows)

    assert len(df) == 1
    assert "proxy_high_risk_label" in df.columns
    assert "graph_support_ratio" in df.columns
    assert int(df.iloc[0]["proxy_high_risk_label"]) == 1


def test_apply_refinement_delta_returns_small_bounded_adjustment():
    delta = apply_refinement_delta({
        "graph_bonus": 0.9,
        "urlhaus_correlation_bonus": 1.2,
        "dread_correlation_bonus": 0.6,
        "centrality_score": 0.7,
        "confidence": 0.85,
        "age_days": 3,
    })

    assert delta > 0
    assert delta < 1


def test_attach_refinement_preview_adds_preview_scores():
    rows = [{"cve_id": "CVE-2", "risk_score": 6.0, "graph_bonus": 0.5}]
    preview = attach_refinement_preview(rows)

    assert "ml_refinement_delta_preview" in preview[0]
    assert preview[0]["refined_risk_score_preview"] >= 6.0
