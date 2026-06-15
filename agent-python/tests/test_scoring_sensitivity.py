import csv
import json

from analysis.scoring_signals import DEFAULT_RISK_SIGNAL_WEIGHTS
from evaluation.scoring_sensitivity import build_scoring_sensitivity_report, sensitivity_weight_variants
from evaluation.thesis_artifacts import generate_thesis_artifacts
from integration.thesis_scenario import run_thesis_scenario


EXPECTED_VARIANTS = {
    "baseline",
    "severity_plus",
    "severity_minus",
    "epss_plus",
    "epss_minus",
    "kev_plus",
    "kev_minus",
    "correlation_plus",
    "correlation_minus",
    "external_evidence_plus",
    "external_evidence_minus",
}

BAD_SENSITIVITY_FORMATTING = (
    "boundedperturbation",
    "stableunder",
    "Variantweights",
    "Recall@5|",
    "6.714286|",
    "hand-pickedweight",
)


def _records_from_report(report):
    from evaluation.thesis_artifacts import _evaluation_records

    return _evaluation_records(report["evaluation"]["records"])


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


def test_sensitivity_variants_are_deterministic_and_do_not_mutate_defaults():
    before = dict(DEFAULT_RISK_SIGNAL_WEIGHTS)

    first = sensitivity_weight_variants()
    second = sensitivity_weight_variants()

    assert first == second
    assert set(first) == EXPECTED_VARIANTS
    assert dict(DEFAULT_RISK_SIGNAL_WEIGHTS) == before
    assert first["baseline"]["weights"] == before
    assert first["severity_plus"]["weights"]["severity_signal"] > before["severity_signal"]
    assert first["severity_minus"]["weights"]["severity_signal"] < before["severity_signal"]


def test_sensitivity_report_recomputes_baseline_from_fixture_signals(tmp_path):
    report_path = tmp_path / "scenario.json"
    report = run_thesis_scenario(report_path)
    records = _records_from_report(report)

    sensitivity = build_scoring_sensitivity_report(records, k_values=[1, 3, 5, 10])
    variants = {item["variant"]: item for item in sensitivity["variants"]}
    baseline = variants["baseline"]
    current_model_ranking = [
        record.cve_id
        for record in sorted(records, key=lambda item: (-item.model_risk_score, item.cve_id))
    ]

    assert baseline["ranking"] == current_model_ranking
    assert baseline["top5_cves"] == current_model_ranking[:5]
    assert baseline["top5_overlap_with_baseline"] == 5
    assert baseline["guardrails_passed"] is True
    assert all(item["guardrails_passed"] for item in sensitivity["variants"])
    for scores in sensitivity["scores_by_variant"].values():
        assert all(0.0 <= item["score"] <= 10.0 for item in scores)


def test_sensitivity_artifacts_are_generated_and_listed_in_manifest(tmp_path):
    report_path = tmp_path / "scenario.json"
    run_thesis_scenario(report_path)
    output_dir = tmp_path / "thesis"

    manifest = generate_thesis_artifacts(scenario_report_path=report_path, output_dir=output_dir)

    assert manifest["generated_files"]["scoring_sensitivity"].endswith("scoring_sensitivity.csv")
    assert manifest["generated_files"]["scoring_sensitivity_md"].endswith("scoring_sensitivity.md")
    rows = list(csv.DictReader((output_dir / "scoring_sensitivity.csv").open(encoding="utf-8")))
    assert {row["variant"] for row in rows} == EXPECTED_VARIANTS
    assert all(row["top5_overlap_with_baseline"] != "" for row in rows)
    assert all(row["guardrails_passed"] in {"True", "False"} for row in rows)
    assert all(row["notes"] for row in rows)

    csv_text = (output_dir / "scoring_sensitivity.csv").read_text(encoding="utf-8")
    markdown = (output_dir / "scoring_sensitivity.md").read_text(encoding="utf-8")
    assert "# Scoring Sensitivity Analysis" in markdown
    assert "not statistical calibration" in markdown
    assert "## Variant Summary" in markdown
    assert "## Qualitative Changes" in markdown
    assert "bounded perturbation" in csv_text
    assert "Variant weights" in markdown
    assert "hand-picked weight" in markdown
    for variant in EXPECTED_VARIANTS:
        assert variant in markdown
    for regression in BAD_SENSITIVITY_FORMATTING:
        assert regression not in csv_text
        assert regression not in markdown
    _assert_markdown_tables_have_consistent_pipe_counts(markdown)

    manifest_json = json.loads((output_dir / "manifest.json").read_text(encoding="utf-8"))
    assert "scoring_sensitivity" in manifest_json["generated_files"]
    assert "scoring_sensitivity_md" in manifest_json["generated_files"]
