from pathlib import Path


def test_thesis_reproducibility_doc_contains_required_commands_and_artifacts():
    repo_root = Path(__file__).resolve().parents[2]
    doc_path = repo_root / "docs" / "thesis_reproducibility.md"

    assert doc_path.exists()
    text = doc_path.read_text(encoding="utf-8")

    for required in (
        "make thesis-artifacts",
        "make thesis-artifact-quality",
        "make thesis-demo",
        "make thesis-runtime-diagnostics",
        "PYTHONDONTWRITEBYTECODE=1",
        "risk_explanation_traces.json",
        "scoring_sensitivity.csv",
        "correlation_decisions.csv",
        "limitations_and_validity.md",
        "thesis_defense_pack.md",
        "demo_walkthrough.md",
        "docs/thesis_limitations.md",
        "docs/thesis_claim_evidence_map.md",
        "docs/thesis_chapter_blueprint.md",
        "docs/learned_calibration.md",
        "make thesis-learned-calibration",
        "learned_calibration_dataset.csv",
        "learned_calibration_labels.csv",
        "learned_calibration_leakage_checks.json",
        "learned_calibration_thesis_section.md",
        "deterministic",
        "live network access",
        "no live network",
    ):
        assert required in text


def test_thesis_limitations_doc_contains_required_sections():
    repo_root = Path(__file__).resolve().parents[2]
    doc_path = repo_root / "docs" / "thesis_limitations.md"

    assert doc_path.exists()
    text = doc_path.read_text(encoding="utf-8")

    for heading in (
        "## Scope of Claims",
        "## Multi-Agent Interpretation",
        "## Controlled Evaluation Fixture",
        "## Scoring Weights and Sensitivity Analysis",
        "## Dread and Unreliable Intelligence Handling",
        "## Asset-Aware Operational Risk Limitations",
        "## Graph Context Limitations",
        "## Generalization Limits",
        "## Future Work",
    ):
        assert heading in text
    for required in (
        "not a fully autonomous LLM-agent system",
        "multi-agent-inspired",
        "deterministic controlled fixture",
        "does not support statistical significance",
        "heuristic engineering choices",
        "not learned parameters",
        "not statistically optimized",
        "not treated as ground truth",
        "Neo4j or other persistent graph databases are future work",
        "larger curated NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets",
    ):
        assert required in text


def test_thesis_claim_evidence_map_contains_required_claim_boundaries():
    repo_root = Path(__file__).resolve().parents[2]
    doc_path = repo_root / "docs" / "thesis_claim_evidence_map.md"

    assert doc_path.exists()
    text = doc_path.read_text(encoding="utf-8")

    for required in (
        "controlled behavioral validation",
        "multi-agent-inspired",
        "| Thesis claim | Supporting artifact / file | What it demonstrates | Limitation / non-claim |",
        "full autonomy",
        "production readiness",
        "statistical significance",
        "real-world validation",
        "optimized or learned weights",
        "Dread as ground truth",
        "persistent graph database implementation",
    ):
        assert required in text


def test_thesis_chapter_blueprint_contains_required_english_writing_plan():
    repo_root = Path(__file__).resolve().parents[2]
    doc_path = repo_root / "docs" / "thesis_chapter_blueprint.md"

    assert doc_path.exists()
    text = doc_path.read_text(encoding="utf-8")

    for required in (
        "multi-agent-inspired",
        "controlled behavioral validation",
        "heuristic engineering choices",
        "bounded sensitivity analysis",
        "Dread is optional, experimental, bounded, default-off",
        "Neo4j are future work",
        "### System Architecture",
        "### Risk Scoring Model",
        "### Evaluation Methodology",
        "### Results",
        "### Limitations and Threats to Validity",
        "## Final Defense Checklist",
    ):
        assert required in text

    for forbidden in (
        "Bulgular",
        "Değerlendirme",
        "Türkçe",
        "çeviri",
        "translation",
        "translate",
    ):
        assert forbidden not in text


def test_makefile_exposes_thesis_demo_target():
    repo_root = Path(__file__).resolve().parents[2]
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")

    for required in (
        "thesis-demo:",
        "$(MAKE) thesis-artifacts",
        "$(MAKE) thesis-artifact-quality",
        "Demo walkthrough: agent-python/reports/thesis/demo_walkthrough.md",
    ):
        assert required in makefile


def test_makefile_exposes_runtime_diagnostics_target():
    repo_root = Path(__file__).resolve().parents[2]
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")

    for required in (
        "thesis-runtime-diagnostics:",
        "evaluation.runtime_diagnostics",
        "--output-dir ../reports/runtime",
    ):
        assert required in makefile


def test_learned_calibration_doc_contains_safe_experimental_framing():
    repo_root = Path(__file__).resolve().parents[2]
    doc_path = repo_root / "docs" / "learned_calibration.md"

    assert doc_path.exists()
    text = doc_path.read_text(encoding="utf-8")

    for required in (
        "make thesis-learned-calibration",
        "Proxy labels are not ground truth",
        "production `risk_score`",
        "URLhaus/Dread evidence gates",
        "Dread live crawling is not used",
        "confidence remains separate from risk",
        "diagnostic thesis material",
        "learned_calibration_leakage_checks.json",
        "legacy_high_risk_diagnostics.json",
        "legacy_dampening_counterfactual.json",
        "not a production scoring change",
        "Preserving old CVSS 10 severity can be defensible for intrinsic technical severity",
        "lack of EPSS, KEV, or accepted external evidence limits operational interpretation",
        "future age-aware dampening",
    ):
        assert required in text
