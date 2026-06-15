import csv
import json

from analysis.scoring_signals import DEFAULT_RISK_SIGNAL_WEIGHTS, RISK_SIGNAL_NAMES, calculate_risk_score_from_normalized_signals
from evaluation.thesis_artifacts import SCORING_DISTRIBUTION_FIELDS, generate_thesis_artifacts
from integration.thesis_scenario import run_thesis_scenario


def _build_artifacts(tmp_path):
    report_path = tmp_path / "scenario.json"
    run_thesis_scenario(report_path)
    output_dir = tmp_path / "thesis"
    manifest = generate_thesis_artifacts(scenario_report_path=report_path, output_dir=output_dir)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return report, manifest, output_dir


def _records_by_id(report):
    return {record["cve_id"]: record for record in report["evaluation"]["records"]}


def _model_ranks(report):
    ranked = sorted(report["evaluation"]["records"], key=lambda record: (-record["model_risk_score"], record["cve_id"]))
    return {record["cve_id"]: index + 1 for index, record in enumerate(ranked)}


def _cvss_ranks(report):
    ranked = sorted(report["evaluation"]["records"], key=lambda record: (-record["cvss_score"], record["cve_id"]))
    return {record["cve_id"]: index + 1 for index, record in enumerate(ranked)}


def test_scoring_distribution_artifacts_are_generated_with_expected_columns(tmp_path):
    _report, manifest, output_dir = _build_artifacts(tmp_path)

    assert manifest["generated_files"]["scoring_distribution"].endswith("scoring_distribution.csv")
    assert manifest["generated_files"]["scoring_distribution_md"].endswith("scoring_distribution.md")

    csv_path = output_dir / "scoring_distribution.csv"
    rows = list(csv.DictReader(csv_path.open(encoding="utf-8")))
    assert rows
    assert list(rows[0].keys()) == SCORING_DISTRIBUTION_FIELDS
    assert len(rows) == manifest["record_count"] == 24
    for column in (
        "severity_weighted_contribution",
        "epss_weighted_contribution",
        "kev_weighted_contribution",
        "recency_weighted_contribution",
        "correlation_weighted_contribution",
        "graph_weighted_contribution",
        "nlp_context_weighted_contribution",
        "weighted_signal_score",
    ):
        assert column in rows[0]

    markdown = (output_dir / "scoring_distribution.md").read_text(encoding="utf-8")
    assert "Risk level distribution" in markdown
    assert "Top 10 By Model Risk" in markdown
    assert "Top 10 By CVSS" in markdown
    assert "Model-Vs-CVSS Ranking Disagreements" in markdown
    assert "Sanity Check Notes" in markdown


def test_scoring_distribution_bounds_and_bucket_diversity(tmp_path):
    report, _manifest, _output_dir = _build_artifacts(tmp_path)
    records = report["evaluation"]["records"]

    levels = {_risk_level(record["model_risk_score"]) for record in records}
    assert {"LOW", "MEDIUM", "HIGH", "CRITICAL"} <= levels

    for record in records:
        assert 0.0 <= record["model_risk_score"] <= 10.0
        assert 0.0 <= record["model_confidence"] <= 1.0
        for signal in (
            "severity_signal",
            "epss_signal",
            "kev_signal",
            "recency_signal",
            "correlation_signal",
            "graph_signal",
            "nlp_context_signal",
        ):
            assert 0.0 <= float(record["feature_breakdown"][signal]) <= 1.0


def test_signal_scoring_calibration_guardrails(tmp_path):
    report, _manifest, _output_dir = _build_artifacts(tmp_path)
    records = _records_by_id(report)
    model_rank = _model_ranks(report)
    cvss_rank = _cvss_ranks(report)

    high_cvss_weak = records["CVE-2026-9007"]
    assert high_cvss_weak["cvss_score"] >= 9.0
    assert high_cvss_weak["epss_score"] <= 0.05
    assert high_cvss_weak["is_kev"] is False
    assert high_cvss_weak["feature_breakdown"]["correlation_signal"] == 0.0
    assert high_cvss_weak["model_risk_score"] >= 6.0
    assert _risk_level(high_cvss_weak["model_risk_score"]) != "CRITICAL"
    assert high_cvss_weak["model_confidence"] < 0.6

    medium_cvss_kev = records["CVE-2026-9002"]
    assert 4.0 <= medium_cvss_kev["cvss_score"] < 7.0
    assert medium_cvss_kev["epss_score"] >= 0.85
    assert medium_cvss_kev["is_kev"] is True
    assert medium_cvss_kev["model_risk_score"] > high_cvss_weak["model_risk_score"]
    assert model_rank[medium_cvss_kev["cve_id"]] < model_rank[high_cvss_weak["cve_id"]]

    kev_medium = records["CVE-2026-9014"]
    comparable_non_kev = records["CVE-2026-9016"]
    assert kev_medium["is_kev"] is True
    assert comparable_non_kev["is_kev"] is False
    assert kev_medium["model_risk_score"] > comparable_non_kev["model_risk_score"]

    accepted_correlation = records["CVE-2026-9005"]
    rejected_or_weak = records["CVE-2026-9006"]
    assert accepted_correlation["feature_breakdown"]["correlation_signal"] > 0
    assert rejected_or_weak["feature_breakdown"]["correlation_signal"] == 0
    assert accepted_correlation["model_risk_score"] > rejected_or_weak["model_risk_score"]
    assert model_rank[accepted_correlation["cve_id"]] < model_rank[rejected_or_weak["cve_id"]]

    assert records["CVE-2026-9006"]["model_confidence"] < 0.7
    assert records["CVE-2026-9017"]["model_confidence"] < 0.7

    assert all(abs(record["model_risk_score"] - record["model_confidence"]) > 1.0 for record in records.values())
    disagreements = [cve_id for cve_id in records if abs(model_rank[cve_id] - cvss_rank[cve_id]) >= 5]
    assert len(disagreements) >= 5


def test_thesis_fixture_scores_are_formula_derived_from_canonical_weights(tmp_path):
    report, _manifest, _output_dir = _build_artifacts(tmp_path)
    records = report["evaluation"]["records"]

    for record in records:
        breakdown = record["feature_breakdown"]
        signals = {name: breakdown[name] for name in RISK_SIGNAL_NAMES}
        recomputed = calculate_risk_score_from_normalized_signals(signals)

        assert breakdown["risk_signal_weights"] == dict(DEFAULT_RISK_SIGNAL_WEIGHTS)
        assert record["model_risk_score"] == breakdown["final_score"]
        assert breakdown["final_score"] == breakdown["risk_score_from_signals"]
        assert record["model_risk_score"] == recomputed["risk_score_from_signals"]
        assert breakdown["weighted_signal_score"] == recomputed["weighted_signal_score"]
        assert breakdown["risk_raw"] == recomputed["risk_raw"]

        contributions = breakdown["risk_signal_contributions"]
        assert set(contributions) == set(RISK_SIGNAL_NAMES)
        assert contributions == recomputed["risk_signal_contributions"]
        assert round(sum(contributions.values()), 6) == breakdown["weighted_signal_score"]

        for name in RISK_SIGNAL_NAMES:
            assert 0.0 <= float(breakdown[name]) <= 1.0
        assert 0.0 <= record["model_risk_score"] <= 10.0


def _risk_level(score: float) -> str:
    if score >= 8.5:
        return "CRITICAL"
    if score >= 6.5:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"
