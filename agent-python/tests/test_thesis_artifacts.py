import json
from pathlib import Path

from evaluation.thesis_artifacts import generate_thesis_artifacts


RESULTS_ABLATION_HEADER = "| Variant | Status | Precision@5 | Recall@5 | NDCG@5 | Mean KEV Rank | Reason |"
BAD_RESULTS_SUMMARY_FORMATTING = (
    "likelihood,KEV",
    "fixture,while",
    "evidence,graph",
    "confidence,while",
    "donot",
    "deterministicanalysis",
    "acceptedcorrelation",
    "toinfer",
    "representsreliability",
    "analysisperturbs",
    "casesin",
    "notto",
    "doesnot",
    "orsimilar",
    "fieldperformance",
    "operational-riskexamples",
    "fixtureto",
    "Mean KEVRank",
    "1.0|",
    "7.571429|",
    "removalrequires",
)
BAD_SENSITIVITY_FORMATTING = (
    "boundedperturbation",
    "stableunder",
    "Variantweights",
    "Recall@5|",
    "6.714286|",
    "hand-pickedweight",
)


def _assert_markdown_tables_have_consistent_pipe_counts(markdown: str) -> None:
    table_counts: list[int] = []
    for line in [*markdown.splitlines(), ""]:
        if line.startswith("|"):
            assert line.startswith("| ")
            assert line.endswith(" |")
            table_counts.append(_unescaped_pipe_count(line))
            continue

        if table_counts:
            assert len(set(table_counts)) == 1
            table_counts = []


def _unescaped_pipe_count(line: str) -> int:
    count = 0
    for index, character in enumerate(line):
        if character == "|" and (index == 0 or line[index - 1] != "\\"):
            count += 1
    return count


def _assert_results_ablation_table_is_well_formed(markdown: str) -> None:
    lines = markdown.splitlines()
    heading_index = lines.index("## Ablation Findings")
    table = []
    for line in lines[heading_index + 1 :]:
        if line.startswith("|"):
            table.append(line)
        elif table:
            break

    assert table
    assert table[0] == RESULTS_ABLATION_HEADER
    assert len({_unescaped_pipe_count(line) for line in table}) == 1
    assert _unescaped_pipe_count(table[0]) == 8
    for row in table[2:]:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        assert len(cells) == 7
        if cells[0] == "without_external_evidence":
            assert cells[1] == "unsupported"
            assert cells[2:6] == ["", "", "", ""]
            assert cells[6].startswith("Removing external evidence")
        else:
            assert cells[6] == ""


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
        "scoring_sensitivity.csv",
        "scoring_sensitivity.md",
        "benchmark_summary.csv",
        "benchmark_summary.md",
        "ablation_summary.csv",
        "ablation_summary.md",
        "correlation_decisions.csv",
        "case_studies.json",
        "evidence_policy_matrix.md",
        "evidence_diagnostics_summary.md",
        "urlhaus_dread_case_studies.md",
        "weak_source_handling_table.json",
        "risk_explanation_traces.json",
        "risk_explanation_traces.md",
        "demo_walkthrough.md",
        "results_summary.md",
        "thesis_results_section.md",
        "limitations_and_validity.md",
        "thesis_defense_pack.md",
        "methodology_summary.md",
        "manifest.json",
    }
    assert {path.name for path in (tmp_path / "first").iterdir()} == expected
    assert first["record_count"] == second["record_count"] == 1
    assert "scoring_distribution" in first["generated_files"]
    assert "scoring_distribution_md" in first["generated_files"]
    assert "scoring_sensitivity" in first["generated_files"]
    assert "scoring_sensitivity_md" in first["generated_files"]
    assert "results_summary" in first["generated_files"]
    assert "evidence_policy_matrix" in first["generated_files"]
    assert "evidence_diagnostics_summary" in first["generated_files"]
    assert "urlhaus_dread_case_studies" in first["generated_files"]
    assert "weak_source_handling_table" in first["generated_files"]
    assert "risk_explanation_traces" in first["generated_files"]
    assert "risk_explanation_traces_md" in first["generated_files"]
    assert "demo_walkthrough" in first["generated_files"]
    assert "thesis_results_section" in first["generated_files"]
    assert "limitations_and_validity" in first["generated_files"]
    assert "thesis_defense_pack" in first["generated_files"]
    assert "thesis_results_section_tr" not in first["generated_files"]
    assert (tmp_path / "first" / "benchmark_summary.csv").read_text(encoding="utf-8") == (
        tmp_path / "second" / "benchmark_summary.csv"
    ).read_text(encoding="utf-8")
    assert "Top 10 Model-Risk CVEs" in (tmp_path / "first" / "scoring_summary.md").read_text(encoding="utf-8")
    assert "# Scoring Sensitivity Analysis" in (tmp_path / "first" / "scoring_sensitivity.md").read_text(encoding="utf-8")
    assert "# Risk Explanation Traces" in (tmp_path / "first" / "risk_explanation_traces.md").read_text(encoding="utf-8")
    assert "# Evidence Policy Matrix" in (tmp_path / "first" / "evidence_policy_matrix.md").read_text(encoding="utf-8")
    assert "# Evidence Diagnostics Summary" in (tmp_path / "first" / "evidence_diagnostics_summary.md").read_text(encoding="utf-8")
    assert "# URLhaus and Dread Case Studies" in (tmp_path / "first" / "urlhaus_dread_case_studies.md").read_text(encoding="utf-8")
    weak_table = json.loads((tmp_path / "first" / "weak_source_handling_table.json").read_text(encoding="utf-8"))
    assert weak_table["claim_boundary"].startswith("Diagnostics explain current evidence handling")
    assert any(
        row["source"] == "dread"
        and row["candidate_status"] == "accepted"
        and row["risk_score_effect"] == "not_enabled"
        for row in weak_table["rows"]
    )
    assert "# Thesis Demo Walkthrough" in (tmp_path / "first" / "demo_walkthrough.md").read_text(encoding="utf-8")
    assert "| Strategy | Top 5 CVEs | Precision@5 | Recall@5 | NDCG@5 | Mean KEV Rank |" in (
        tmp_path / "first" / "benchmark_summary.md"
    ).read_text(encoding="utf-8")
    assert "## Evaluation Setup" in (tmp_path / "first" / "results_summary.md").read_text(encoding="utf-8")
    assert "## Experimental Setup" in (tmp_path / "first" / "thesis_results_section.md").read_text(encoding="utf-8")
    assert "## Claim Scope" in (tmp_path / "first" / "limitations_and_validity.md").read_text(encoding="utf-8")
    assert "## Suggested Defense Q&A" in (tmp_path / "first" / "thesis_defense_pack.md").read_text(encoding="utf-8")
    scoring_distribution_header = (tmp_path / "first" / "scoring_distribution.csv").read_text(encoding="utf-8").splitlines()[0]
    assert "urlhaus_ignored_low_signal_count" in scoring_distribution_header
    assert "assessment_confidence" in scoring_distribution_header
    assert "data_completeness" in scoring_distribution_header
    assert not (tmp_path / "first" / "thesis_results_section_tr.md").exists()


def test_thesis_manifest_uses_repo_root_relative_report_paths(tmp_path):
    output_dir = tmp_path / "reports" / "thesis" / "deterministic"
    output_dir.mkdir(parents=True)
    report_path = output_dir / "thesis_scenario_report.json"
    report_path.write_text(
        json.dumps(
            {
                "source_results": [],
                "evaluation": {"metric_config": {"k_values": [1]}, "baselines": {}, "records": []},
                "correlation_decisions": [],
                "notable_cases": [],
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    manifest = generate_thesis_artifacts(scenario_report_path=report_path, output_dir=output_dir)

    assert manifest["scenario_report_path"] == "reports/thesis/deterministic/thesis_scenario_report.json"
    assert manifest["output_dir"] == "reports/thesis/deterministic"
    for path in manifest["generated_files"].values():
        assert not path.startswith("../")
        assert path.startswith("reports/thesis/deterministic/")


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
    assert "evidence_reliability" in correlation_csv
    assert "dread_only_evidence" in correlation_csv
    assert "corroborated_dread_evidence" in correlation_csv
    assert "confidence_cap_reason" in correlation_csv
    assert "evidence_gate_passed" in correlation_csv
    assert "accepted_evidence_count" in correlation_csv
    assert "false_positive_control" in correlation_csv
    assert "UH-FP-KEYWORD" in correlation_csv
    assert "UH-FP-STALE" in correlation_csv
    assert "UH-FP-PRODUCT" in correlation_csv
    cases = json.loads((tmp_path / "out" / "case_studies.json").read_text(encoding="utf-8"))["cases"]
    policy_md = (tmp_path / "out" / "evidence_policy_matrix.md").read_text(encoding="utf-8")
    diagnostics_md = (tmp_path / "out" / "evidence_diagnostics_summary.md").read_text(encoding="utf-8")
    source_case_md = (tmp_path / "out" / "urlhaus_dread_case_studies.md").read_text(encoding="utf-8")
    weak_table = json.loads((tmp_path / "out" / "weak_source_handling_table.json").read_text(encoding="utf-8"))
    assert Path(manifest["generated_files"]["evidence_policy_matrix"]) == tmp_path / "out" / "evidence_policy_matrix.md"
    assert Path(manifest["generated_files"]["evidence_diagnostics_summary"]) == tmp_path / "out" / "evidence_diagnostics_summary.md"
    assert Path(manifest["generated_files"]["urlhaus_dread_case_studies"]) == tmp_path / "out" / "urlhaus_dread_case_studies.md"
    assert Path(manifest["generated_files"]["weak_source_handling_table"]) == tmp_path / "out" / "weak_source_handling_table.json"
    assert "Accepted Dread scoring evidence is not enabled" in policy_md
    assert "Dread accepted scoring evidence count is expected to be zero" in diagnostics_md
    assert "No accepted Dread scoring-evidence case is present" in source_case_md
    assert weak_table["status_counts"]["dread"]["manual_review"] >= 1
    assert weak_table["status_counts"]["urlhaus"]["accepted"] >= 1
    assert any(row["source"] == "dread" and row["candidate_status"] == "accepted" and row["observed_decision_count"] == 0 for row in weak_table["rows"])
    assert any(row["source"] == "urlhaus" and row["candidate_status"] == "accepted" and row["case_available"] is True for row in weak_table["rows"])
    case_names = {case["case"] for case in cases}
    assert {
        "high_risk_correlated",
        "medium_cvss_high_epss_kev",
        "high_cvss_low_external_evidence",
        "dread_only_manual_review",
        "dread_corroborated_by_urlhaus_or_kev",
        "weak_dread_rejected",
        "keyword_only_false_positive_rejected",
        "stale_evidence_rejected_or_capped",
        "unrelated_product_overlap_rejected",
        "manual_review_not_risk_boost",
        "asset_applicability_difference",
        "patched_asset_reduction",
        "compensating_control_reduction",
    } <= case_names
    benchmark_md = (tmp_path / "out" / "benchmark_summary.md").read_text(encoding="utf-8")
    ablation_md = (tmp_path / "out" / "ablation_summary.md").read_text(encoding="utf-8")
    sensitivity_csv = (tmp_path / "out" / "scoring_sensitivity.csv").read_text(encoding="utf-8")
    sensitivity_md = (tmp_path / "out" / "scoring_sensitivity.md").read_text(encoding="utf-8")
    trace_path = tmp_path / "out" / "risk_explanation_traces.json"
    trace_md_path = tmp_path / "out" / "risk_explanation_traces.md"
    demo_path = tmp_path / "out" / "demo_walkthrough.md"
    traces = json.loads(trace_path.read_text(encoding="utf-8"))["traces"]
    traces_by_cve = {trace["cve_id"]: trace for trace in traces}
    assert trace_path == Path(manifest["generated_files"]["risk_explanation_traces"])
    assert trace_md_path == Path(manifest["generated_files"]["risk_explanation_traces_md"])
    assert demo_path == Path(manifest["generated_files"]["demo_walkthrough"])
    required_traces = {
        "CVE-2026-9001",
        "CVE-2026-9002",
        "CVE-2026-9007",
        "CVE-2026-9017",
        "CVE-2015-0001",
    }
    assert required_traces <= set(traces_by_cve)
    for cve_id in required_traces:
        trace = traces_by_cve[cve_id]
        assert "generic_cve_risk_score" in trace
        assert "confidence" in trace
        assert "risk_level" in trace
        assert isinstance(trace["top_positive_risk_contributors"], list)
        assert "top_evidence_decisions" in trace
        assert "asset_operational_risk_examples" in trace
        assert trace["explanation"]
    dread_trace = traces_by_cve["CVE-2026-9017"]
    assert dread_trace["dread_evidence_present"] is True
    assert dread_trace["confidence_cap_reason"] == "dread_manual_review_cap"
    assert dread_trace["manual_review_evidence_count"] >= 1
    high_trace = traces_by_cve["CVE-2026-9001"]
    assert any(item["asset_applicable"] is True for item in high_trace["asset_operational_risk_examples"])
    assert any(item["asset_applicable"] is False for item in high_trace["asset_operational_risk_examples"])
    trace_md = trace_md_path.read_text(encoding="utf-8")
    demo_md = demo_path.read_text(encoding="utf-8")
    assert "# Risk Explanation Traces" in trace_md
    for cve_id in required_traces:
        assert f"## {cve_id}" in trace_md
    _assert_markdown_tables_have_consistent_pipe_counts(trace_md)
    for heading in (
        "# Thesis Demo Walkthrough",
        "## What This Demo Runs",
        "## Output Files",
        "## Key Demonstrated Capabilities",
        "## How to Read the Results",
        "## Asset-Aware Operational Risk Example",
        "## Evidence-Gating and False-Positive Handling",
        "## Reproducibility Notes",
        "## Claim Boundaries",
    ):
        assert heading in demo_md
    for expected in (
        "deterministic controlled fixture",
        "behavioral validation",
        "artifact quality gate",
        "Baseline ranking comparison",
        "Ablation analysis",
        "Bounded sensitivity analysis",
        "Explanation traces",
        "evidence-gated correlation",
        "Asset-aware operational-risk examples",
        "Dread is optional, experimental, bounded, default-off",
        "No live Dread access",
    ):
        assert expected in demo_md
    _assert_markdown_tables_have_consistent_pipe_counts(demo_md)
    results_path = tmp_path / "out" / "results_summary.md"
    assert results_path == Path(manifest["generated_files"]["results_summary"])
    results_md = results_path.read_text(encoding="utf-8")
    thesis_path = tmp_path / "out" / "thesis_results_section.md"
    assert thesis_path == Path(manifest["generated_files"]["thesis_results_section"])
    limitations_path = tmp_path / "out" / "limitations_and_validity.md"
    defense_path = tmp_path / "out" / "thesis_defense_pack.md"
    methodology_path = tmp_path / "out" / "methodology_summary.md"
    assert limitations_path == Path(manifest["generated_files"]["limitations_and_validity"])
    assert defense_path == Path(manifest["generated_files"]["thesis_defense_pack"])
    assert "thesis_results_section_tr" not in manifest["generated_files"]
    assert not (tmp_path / "out" / "thesis_results_section_tr.md").exists()
    thesis_md = thesis_path.read_text(encoding="utf-8")
    limitations_md = limitations_path.read_text(encoding="utf-8")
    defense_md = defense_path.read_text(encoding="utf-8")
    methodology_md = methodology_path.read_text(encoding="utf-8")
    assert "Mean KEV Rank" in benchmark_md
    assert "Mean KEV Rank" in ablation_md
    assert "Variant weights" in sensitivity_md
    assert "hand-picked weight" in sensitivity_md
    assert "Mean KEVRank" not in ablation_md
    assert "1.0| 5.714286" not in ablation_md
    for regression in BAD_SENSITIVITY_FORMATTING:
        assert regression not in sensitivity_csv
        assert regression not in sensitivity_md
    _assert_markdown_tables_have_consistent_pipe_counts(benchmark_md)
    _assert_markdown_tables_have_consistent_pipe_counts(ablation_md)
    _assert_markdown_tables_have_consistent_pipe_counts(sensitivity_md)
    for heading in (
        "## Evaluation Setup",
        "## Benchmark Findings",
        "## Scoring Distribution Findings",
        "## Ablation Findings",
        "## Correlation Decision Findings",
        "## Case Study Highlights",
        "## Limitations",
    ):
        assert heading in results_md
    for strategy in (
        "cvss_only",
        "epss_only",
        "cvss_epss",
        "kev_first",
        "model_risk",
        "model_confidence_weighted",
        "model_confidence_filtered",
        "signal_based_model",
    ):
        assert strategy in results_md
    for variant in (
        "without_epss",
        "without_kev",
        "without_correlation",
        "without_graph",
        "without_recency",
        "without_confidence_weighting",
        "without_external_evidence",
    ):
        assert variant in results_md
    assert "not a live operational benchmark" in results_md
    assert "statistical significance" in results_md
    for case in (
        "high_risk_correlated",
        "medium_cvss_high_epss_kev",
        "high_cvss_low_external_evidence",
        "dread_only_manual_review",
        "dread_corroborated_by_urlhaus_or_kev",
        "weak_dread_rejected",
        "keyword_only_false_positive_rejected",
        "stale_evidence_rejected_or_capped",
        "unrelated_product_overlap_rejected",
        "manual_review_not_risk_boost",
        "asset_applicability_difference",
    ):
        assert case in results_md
    assert RESULTS_ABLATION_HEADER in results_md
    assert "| without_external_evidence | unsupported |  |  |  |  | Removing external evidence" in results_md
    for expected_spacing in (
        "likelihood, KEV",
        "fixture, while",
        "evidence, graph",
        "confidence, while",
        "do not",
    ):
        assert expected_spacing in results_md
    for regression in BAD_RESULTS_SUMMARY_FORMATTING:
        assert regression not in results_md
    _assert_markdown_tables_have_consistent_pipe_counts(results_md)
    _assert_results_ablation_table_is_well_formed(results_md)
    for heading in (
        "## Experimental Setup",
        "## Prioritization Results",
        "## Scoring Distribution",
        "## Ablation Analysis",
        "## Correlation Decision Analysis",
        "## Case Study Highlights",
        "## Threats to Validity and Limitations",
    ):
        assert heading in thesis_md
    for strategy in (
        "cvss_only",
        "epss_only",
        "cvss_epss",
        "kev_first",
        "model_risk",
        "model_confidence_weighted",
        "model_confidence_filtered",
        "signal_based_model",
    ):
        assert strategy in thesis_md
    for variant in (
        "without_epss",
        "without_kev",
        "without_correlation",
        "without_graph",
        "without_recency",
        "without_confidence_weighting",
        "without_external_evidence",
    ):
        assert variant in thesis_md
    assert "not be interpreted as a live benchmark" in thesis_md
    assert "does not support statistical significance claims" in thesis_md
    assert "requires larger real-world datasets from NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context sources" in thesis_md
    for case in (
        "high_risk_correlated",
        "medium_cvss_high_epss_kev",
        "high_cvss_low_external_evidence",
        "dread_only_manual_review",
        "dread_corroborated_by_urlhaus_or_kev",
        "weak_dread_rejected",
        "keyword_only_false_positive_rejected",
        "stale_evidence_rejected_or_capped",
        "unrelated_product_overlap_rejected",
        "manual_review_not_risk_boost",
        "asset_applicability_difference",
    ):
        assert case in thesis_md
    assert "| Method | Precision@5 | Recall@5 | NDCG@5 | Mean KEV Rank |" in thesis_md
    assert "| Variant | Status | Precision@5 | Recall@5 | NDCG@5 | Mean KEV Rank | Explanation |" in thesis_md
    for regression in BAD_RESULTS_SUMMARY_FORMATTING:
        assert regression not in thesis_md
    _assert_markdown_tables_have_consistent_pipe_counts(thesis_md)
    for heading in (
        "## Claim Scope",
        "## Multi-Agent Interpretation",
        "## Controlled Fixture Limitation",
        "## Heuristic Scoring Weights Limitation",
        "## Sensitivity Analysis Limitation",
        "## Dread Evidence Limitation",
        "## Asset-Aware Operational Risk Limitation",
        "## Graph Persistence Limitation",
        "## Real-World Generalization Limitation",
        "## Future Work",
    ):
        assert heading in limitations_md
    for expected in (
        "multi-agent-inspired",
        "not a fully autonomous LLM-agent system",
        "deterministic controlled fixture",
        "not a live CTI benchmark",
        "not learned parameters",
        "not statistically optimized",
        "not treated as ground truth",
        "Neo4j or other persistent graph databases are future work",
    ):
        assert expected in limitations_md
    for heading in (
        "## One-Paragraph Thesis Claim",
        "## Contributions",
        "## What the System Does Not Claim",
        "## Methodology Summary",
        "## Evaluation Summary",
        "## Key Limitations",
        "## Suggested Defense Q&A",
    ):
        assert heading in defense_md
    for expected in (
        "multi-agent-inspired",
        "controlled deterministic fixture",
        "not to claim live operational generalization",
        "does not claim learned or statistically optimized scoring weights",
        "Why are the weights heuristic?",
        "Why is Dread included if it is unreliable?",
        "Why not use Neo4j?",
    ):
        assert expected in defense_md
    for expected in (
        "deterministic controlled fixture",
        "behavioral validation",
        "not a live CTI benchmark",
        "not statistical calibration",
        "heuristic engineering choices",
        "Dread cases in thesis artifacts are local deterministic fixtures",
        "do not require live Dread access",
        "False-positive stress cases",
        "Explanation traces",
        "Asset-aware examples",
    ):
        assert expected in methodology_md
    for markdown in (limitations_md, defense_md, methodology_md):
        _assert_markdown_tables_have_consistent_pipe_counts(markdown)
