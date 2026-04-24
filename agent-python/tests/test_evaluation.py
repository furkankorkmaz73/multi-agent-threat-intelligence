from evaluation.comparative import build_comparison_summary, build_cve_comparison_frame


def test_build_cve_comparison_frame_derives_baselines_and_lifts():
    rows = [
        {
            "cve_id": "CVE-1",
            "cvss_score": 9.8,
            "base_cvss_component": 5.39,
            "recentness_bonus": 0.8,
            "urlhaus_correlation_bonus": 0.7,
            "dread_correlation_bonus": 0.5,
            "graph_bonus": 0.6,
            "risk_score": 8.0,
        }
    ]

    df = build_cve_comparison_frame(rows)

    assert len(df) == 1
    assert float(df.iloc[0]["baseline_cvss_only_score"]) == 5.39
    assert float(df.iloc[0]["baseline_plus_correlation"]) == 7.39
    assert float(df.iloc[0]["baseline_plus_graph"]) == 7.99
    assert float(df.iloc[0]["lift_from_cvss_only"]) == 2.61
    assert float(df.iloc[0]["graph_only_delta"]) == 0.6


def test_build_comparison_summary_reports_overlap_and_reprioritization():
    rows = [
        {
            "cve_id": "CVE-A",
            "cvss_score": 9.8,
            "base_cvss_component": 5.39,
            "recentness_bonus": 0.2,
            "urlhaus_correlation_bonus": 1.0,
            "dread_correlation_bonus": 0.8,
            "graph_bonus": 0.5,
            "risk_score": 7.89,
        },
        {
            "cve_id": "CVE-B",
            "cvss_score": 4.0,
            "base_cvss_component": 2.2,
            "recentness_bonus": 1.0,
            "urlhaus_correlation_bonus": 1.6,
            "dread_correlation_bonus": 0.9,
            "graph_bonus": 0.7,
            "risk_score": 6.4,
        },
        {
            "cve_id": "CVE-C",
            "cvss_score": 8.0,
            "base_cvss_component": 4.4,
            "recentness_bonus": 0.0,
            "urlhaus_correlation_bonus": 0.0,
            "dread_correlation_bonus": 0.0,
            "graph_bonus": 0.0,
            "risk_score": 4.4,
        },
    ]

    summary = build_comparison_summary(rows, top_k=2)

    assert summary["record_count"] == 3
    assert summary["graph_supported_count"] == 2
    assert summary["reprioritized_count_lift_ge_1_5"] >= 1
    assert summary["top_k"] == 2
    assert isinstance(summary["reprioritized_examples"], list)
