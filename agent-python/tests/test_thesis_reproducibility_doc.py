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
        "deterministic",
        "live network access",
        "no live network",
    ):
        assert required in text
