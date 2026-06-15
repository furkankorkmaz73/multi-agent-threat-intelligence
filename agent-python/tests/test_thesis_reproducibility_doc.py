from pathlib import Path


def test_thesis_reproducibility_doc_contains_required_commands_and_artifacts():
    repo_root = Path(__file__).resolve().parents[2]
    doc_path = repo_root / "docs" / "thesis_reproducibility.md"

    assert doc_path.exists()
    text = doc_path.read_text(encoding="utf-8")

    for required in (
        "make thesis-artifacts",
        "make thesis-artifact-quality",
        "PYTHONDONTWRITEBYTECODE=1",
        "risk_explanation_traces.json",
        "scoring_sensitivity.csv",
        "correlation_decisions.csv",
        "limitations_and_validity.md",
        "thesis_defense_pack.md",
        "docs/thesis_limitations.md",
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
