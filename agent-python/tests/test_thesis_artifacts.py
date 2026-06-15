import json

from evaluation.thesis_artifacts import generate_thesis_artifacts


def test_thesis_artifact_generation_produces_deterministic_files(tmp_path):
    scenario = {
        "source_results": [
            {
                "source": "cve",
                "entity_id": "CVE-2026-9001",
                "risk_score": 8.5,
                "risk_level": "CRITICAL",
                "confidence": 0.82,
                "evidence_summary": {"related_urlhaus_count": 1, "related_dread_count": 0},
            }
        ],
        "evaluation": {
            "metric_config": {"k_values": [1]},
            "baselines": {
                "model_risk": {
                    "ranking": ["CVE-2026-9001"],
                    "metrics": {
                        "precision_at_1": 1.0,
                        "precision_at_5": 1.0,
                        "recall_at_1": 1.0,
                        "recall_at_5": 1.0,
                        "ndcg_at_1": 1.0,
                        "ndcg_at_5": 1.0,
                        "kev_hit_rate_at_1": 1.0,
                        "mrr": 1.0,
                        "mean_kev_rank": 1.0,
                    },
                }
            },
            "records": [
                {
                    "cve_id": "CVE-2026-9001",
                    "model_risk_score": 8.5,
                    "model_confidence": 0.82,
                    "cvss_score": 9.8,
                    "epss_score": 0.94,
                    "epss_percentile": 0.99,
                    "is_kev": True,
                    "exploitation_evidence": {},
                    "feature_breakdown": {
                        "risk_raw": 8.5,
                        "risk_signal_weights": {"epss_signal": 0.12, "kev_signal": 0.12, "correlation_signal": 0.07, "graph_signal": 0.03, "recency_signal": 0.05},
                        "epss_signal": 0.94,
                        "kev_signal": 1.0,
                        "correlation_signal": 0.5,
                        "graph_signal": 0.2,
                        "recency_signal": 1.0,
                    },
                }
            ],
        },
        "correlation_decisions": [
            {
                "source_identifier": "CVE-2026-9001",
                "target_identifier": "UH-9001",
                "source": "urlhaus",
                "lexical_score": 0.5,
                "semantic_score": 0.4,
                "temporal_score": 0.8,
                "entity_score": 0.6,
                "shared_term_count": 3,
                "exact_cve": True,
                "high_signal_term_hits": 2,
                "decision": "accepted",
                "primary_reason": "exact_cve",
                "final_confidence": 1.0,
            }
        ],
        "notable_cases": [{"case": "high_risk_correlated", "entity_id": "CVE-2026-9001"}],
    }
    report_path = tmp_path / "scenario.json"
    report_path.write_text(json.dumps(scenario, sort_keys=True), encoding="utf-8")

    first = generate_thesis_artifacts(scenario_report_path=report_path, output_dir=tmp_path / "first")
    second = generate_thesis_artifacts(scenario_report_path=report_path, output_dir=tmp_path / "second")

    expected = {
        "scoring_summary.md",
        "scoring_distribution.csv",
        "scoring_distribution.md",
        "benchmark_summary.csv",
        "benchmark_summary.md",
        "ablation_summary.csv",
        "ablation_summary.md",
        "correlation_decisions.csv",
        "case_studies.json",
        "methodology_summary.md",
        "manifest.json",
    }
    assert {path.name for path in (tmp_path / "first").iterdir()} == expected
    assert first["record_count"] == second["record_count"] == 1
    assert "scoring_distribution" in first["generated_files"]
    assert "scoring_distribution_md" in first["generated_files"]
    assert (tmp_path / "first" / "benchmark_summary.csv").read_text(encoding="utf-8") == (
        tmp_path / "second" / "benchmark_summary.csv"
    ).read_text(encoding="utf-8")
    assert "Top 10 Model-Risk CVEs" in (tmp_path / "first" / "scoring_summary.md").read_text(encoding="utf-8")
    assert "| Strategy | Top 5 CVEs | Precision@5 | Recall@5 | NDCG@5 | Mean KEV Rank |" in (
        tmp_path / "first" / "benchmark_summary.md"
    ).read_text(encoding="utf-8")


def test_real_thesis_scenario_artifacts_meet_acceptance_criteria(tmp_path):
    from integration.thesis_scenario import run_thesis_scenario

    report_path = tmp_path / "scenario.json"
    run_thesis_scenario(report_path)
    manifest = generate_thesis_artifacts(scenario_report_path=report_path, output_dir=tmp_path / "out")

    assert manifest["record_count"] >= 20
    assert manifest["correlation_decision_count"] >= 5
    benchmark_csv = (tmp_path / "out" / "benchmark_summary.csv").read_text(encoding="utf-8")
    for strategy in ("cvss_only", "epss_only", "cvss_epss", "kev_first", "model_risk", "model_confidence_weighted", "signal_based_model"):
        assert strategy in benchmark_csv
    ablation_csv = (tmp_path / "out" / "ablation_summary.csv").read_text(encoding="utf-8")
    for variant in ("without_epss", "without_kev", "without_correlation", "without_graph", "without_recency", "without_confidence_weighting"):
        assert variant in ablation_csv
    correlation_csv = (tmp_path / "out" / "correlation_decisions.csv").read_text(encoding="utf-8")
    assert "accepted" in correlation_csv
    assert "manual_review" in correlation_csv
    assert "rejected" in correlation_csv
    cases = json.loads((tmp_path / "out" / "case_studies.json").read_text(encoding="utf-8"))["cases"]
    case_names = {case["case"] for case in cases}
    assert {
        "high_risk_correlated",
        "medium_cvss_high_epss_kev",
        "high_cvss_low_external_evidence",
        "dread_only_manual_review",
        "asset_applicability_difference",
    } <= case_names
    benchmark_md = (tmp_path / "out" / "benchmark_summary.md").read_text(encoding="utf-8")
    ablation_md = (tmp_path / "out" / "ablation_summary.md").read_text(encoding="utf-8")
    assert "Mean KEV Rank" in benchmark_md
    assert "Mean KEV Rank" in ablation_md
    assert "Mean KEVRank" not in ablation_md
    assert "1.0| 5.714286" not in ablation_md
    for line in benchmark_md.splitlines() + ablation_md.splitlines():
        if line.startswith("|"):
            assert line.startswith("| ")
            assert line.endswith(" |")
