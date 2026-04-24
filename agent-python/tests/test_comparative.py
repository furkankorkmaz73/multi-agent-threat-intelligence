from evaluation.comparative import build_case_study_rows, build_comparison_summary
from reporting.narrative import build_report_brief


def _rows():
    return [
        {
            "cve_id": "CVE-1",
            "cvss_score": 9.0,
            "base_cvss_component": 4.95,
            "recentness_bonus": 1.2,
            "urlhaus_correlation_bonus": 1.0,
            "dread_correlation_bonus": 0.8,
            "urlhaus_avg_semantic_score": 0.6,
            "dread_avg_semantic_score": 0.5,
            "graph_bonus": 0.9,
            "risk_score": 8.8,
            "related_urlhaus_count": 2,
            "related_dread_count": 1,
            "age_days": 5,
            "description": "vpn rce",
        },
        {
            "cve_id": "CVE-2",
            "cvss_score": 5.0,
            "base_cvss_component": 2.75,
            "recentness_bonus": 0.4,
            "urlhaus_correlation_bonus": 0.0,
            "dread_correlation_bonus": 0.2,
            "urlhaus_avg_semantic_score": 0.1,
            "dread_avg_semantic_score": 0.2,
            "graph_bonus": 0.1,
            "risk_score": 3.5,
            "related_urlhaus_count": 0,
            "related_dread_count": 1,
            "age_days": 40,
            "description": "minor issue",
        },
    ]


def test_comparison_summary_and_case_studies():
    summary = build_comparison_summary(_rows(), top_k=2)
    assert summary["record_count"] == 2
    assert "avg_semantic_only_delta" in summary
    rows = build_case_study_rows(_rows(), limit=1)
    assert len(rows) == 1
    assert rows[0]["cve_id"] == "CVE-1"


def test_report_brief_contains_markdown_and_refinement_block():
    brief = build_report_brief(_rows(), top_k=2)
    assert "markdown" in brief
    assert "hybrid model" in brief["markdown"].lower()
