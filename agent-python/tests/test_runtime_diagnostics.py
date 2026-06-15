import json

from evaluation.runtime_diagnostics import build_runtime_diagnostics, write_runtime_diagnostics


def test_runtime_diagnostics_reports_urlhaus_candidate_accounting(tmp_path):
    docs = [
        {
            "_id": "CVE-2026-1001",
            "analysis": {
                "entity_id": "CVE-2026-1001",
                "risk_score": 7.2,
                "risk_level": "HIGH",
                "confidence": 0.58,
                "evidence": {
                    "cvss_score": 9.0,
                    "epss_available": False,
                    "kev_status_known": False,
                    "urlhaus_match_stats": {
                        "raw_candidate_count": 10,
                        "ignored_low_signal_count": 8,
                        "evaluated_candidate_count": 2,
                        "signal_candidate_count": 2,
                        "accepted_match_count": 0,
                        "manual_review_match_count": 1,
                        "rejected_match_count": 1,
                    },
                },
                "confidence_breakdown": {
                    "final_confidence": 0.58,
                    "assessment_confidence": 0.61,
                    "data_completeness": 0.42,
                    "coverage_limitations": ["epss_unavailable", "kev_status_unknown"],
                },
            },
        }
    ]

    report = build_runtime_diagnostics(cve_docs=docs, urlhaus_docs=[{"processed": True}], generated_at="2026-06-15T00:00:00+00:00")
    diagnostics = report["urlhaus_correlation_diagnostics"]

    assert diagnostics["raw_candidate_count"] == 10
    assert diagnostics["ignored_low_signal_count"] == 8
    assert diagnostics["signal_candidate_count"] == 2
    assert diagnostics["manual_review_match_count"] == 1
    assert diagnostics["rejected_match_count"] == 1
    assert report["external_signal_coverage"]["epss_missing_count"] == 1
    assert report["high_risk_low_confidence_cases"][0]["cve_id"] == "CVE-2026-1001"

    paths = write_runtime_diagnostics(report, tmp_path)
    assert "live_reanalysis_summary_md" in paths
    assert json.loads((tmp_path / "urlhaus_correlation_diagnostics.json").read_text())["ignored_low_signal_count"] == 8
    assert "Ignored low-signal candidates are raw retrieval noise" in (tmp_path / "live_reanalysis_summary.md").read_text()
