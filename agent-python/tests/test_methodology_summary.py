from reporting.technical_summary import build_methodology_summary


def test_methodology_summary_contains_expected_sections():
    rows = [{
        "cve_id": "CVE-2026-1000",
        "cvss_score": 9.0,
        "base_cvss_component": 4.95,
        "recentness_bonus": 1.1,
        "urlhaus_correlation_bonus": 0.8,
        "dread_correlation_bonus": 0.5,
        "graph_bonus": 0.4,
        "risk_score": 8.2,
        "urlhaus_avg_semantic_score": 0.6,
        "dread_avg_semantic_score": 0.3,
        "related_urlhaus_count": 1,
        "related_dread_count": 1,
        "age_days": 2,
        "risk_level": "HIGH",
        "confidence": 0.9,
        "description": "demo vulnerability",
    }]
    payload = build_methodology_summary(rows, top_k=5)
    assert payload["methodology"]["pipeline_version"]
    assert "semantic similarity" in payload["methodology"]["analysis_layers"]
    assert payload["summary"]["record_count"] == 1
    assert payload["markdown"].startswith("# Technical Methodology Summary")
