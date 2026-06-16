from pathlib import Path
import re


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
        "Python 3.11",
        "Go 1.24.x",
        "Node 24.x",
        "MongoDB 7.x",
        "agent-python/.venv",
        "deterministic",
        "live network access",
        "no live network",
    ):
        assert required in text
    assert "reports/thesis/" in text
    assert "reports/runtime/" in text
    assert "agent-python/reports/runtime/" not in text


def test_thesis_reproducibility_doc_splits_artifact_inventories():
    repo_root = Path(__file__).resolve().parents[2]
    doc = (repo_root / "docs" / "thesis_reproducibility.md").read_text(encoding="utf-8")

    assert "### A. Deterministic Thesis Bundle" in doc
    assert "### B. Optional Learned Calibration Bundle" in doc
    assert "produced by different Makefile targets" in doc
    assert "Contains deterministic fixture outputs only" in doc
    assert "Contains experimental learned-calibration" in doc
    assert "make thesis-demo produces `learned_calibration_dataset.csv`" not in doc


def test_readme_uses_root_level_thesis_report_paths():
    repo_root = Path(__file__).resolve().parents[2]
    readme = (repo_root / "README.md").read_text(encoding="utf-8")

    for required in (
        "reports/thesis/",
        "reports/runtime/",
        "reports/thesis/demo_walkthrough.md",
        "reports/thesis/manifest.json",
    ):
        assert required in readme

    for stale in (
        "agent-python/reports/thesis/",
        "agent-python/reports/runtime/",
    ):
        assert stale not in readme


def test_readme_docker_section_documents_env_file_setup():
    repo_root = Path(__file__).resolve().parents[2]
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    compose = (repo_root / "docker-compose.yml").read_text(encoding="utf-8")

    assert "env_file:" in compose
    assert "- .env" in compose
    assert "cp .env.example .env" in readme
    assert "Review `.env` before non-local use" in readme
    assert "docker compose up -d" in readme


def test_agent_python_env_example_matches_current_scoring_default():
    repo_root = Path(__file__).resolve().parents[2]
    env_text = (repo_root / "agent-python" / ".env.example").read_text(encoding="utf-8")
    config_text = (repo_root / "agent-python" / "src" / "config.py").read_text(encoding="utf-8")

    config_match = re.search(r'base_cvss_multiplier: float = _float_env\("BASE_CVSS_MULTIPLIER", ([0-9.]+)\)', config_text)
    assert config_match is not None
    expected = config_match.group(1)

    assert "BASE_CVSS_MULTIPLIER=0.55" not in env_text
    assert f"BASE_CVSS_MULTIPLIER={expected}" in env_text


def test_llm_environment_docs_match_enablement_gate():
    repo_root = Path(__file__).resolve().parents[2]
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    root_env = (repo_root / ".env.example").read_text(encoding="utf-8")
    python_env = (repo_root / "agent-python" / ".env.example").read_text(encoding="utf-8")

    for env_text in (root_env, python_env):
        assert "LLM_ENABLED=0" in env_text
        assert "LLM_API_KEY=" in env_text
        assert "LLM_BASE_URL" in env_text
        assert "OPENAI_API_KEY=" in env_text
        assert "OPENAI_BASE_URL=" in env_text
        assert "API keys alone do not enable LLM calls" in env_text

    for required in (
        "LLM_ENABLED=1",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "An API key alone does not enable LLM calls",
    ):
        assert required in readme


def test_frontend_dockerfile_matches_documented_node_runtime():
    repo_root = Path(__file__).resolve().parents[2]
    dockerfile = (repo_root / "agent-python" / "frontend" / "Dockerfile").read_text(encoding="utf-8")
    workflow = (repo_root / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    readme = (repo_root / "README.md").read_text(encoding="utf-8")

    assert "FROM node:24-alpine" in dockerfile
    assert 'node-version: "24"' in workflow
    assert "Node 24.x" in readme


def test_readme_does_not_claim_auth_is_absent():
    repo_root = Path(__file__).resolve().parents[2]
    readme = (repo_root / "README.md").read_text(encoding="utf-8")

    assert "No authentication or authorization layer" not in readme
    assert "API-key authentication and role-based authorization are implemented for controlled deployments" in readme
    assert "not hardened as a production SOC platform" in readme
    assert "MongoDB runs without access control in local development" in readme


def test_readme_front_matter_has_thesis_claim_boundaries():
    repo_root = Path(__file__).resolve().parents[2]
    readme = (repo_root / "README.md").read_text(encoding="utf-8")

    for required in (
        "multi-agent-inspired / agent-supported",
        "not as a fully autonomous LLM-agent system",
        "Scoring, confidence estimation, and evidence-gate decisions are deterministic and explainable",
        "behavioral validation, not real-world statistical validation",
        "research prototype, not a production SOC platform",
    ):
        assert required in readme


def test_readme_roadmap_frames_epss_kev_as_coverage_validation():
    repo_root = Path(__file__).resolve().parents[2]
    readme = (repo_root / "README.md").read_text(encoding="utf-8")

    assert "**CISA KEV integration**" not in readme
    assert "**EPSS integration**" not in readme
    assert "Broader EPSS/KEV coverage validation" in readme
    assert "Validate with larger local EPSS and CISA KEV exports" in readme
    assert "Keep EPSS/KEV unavailable cases explicit in confidence limitations" in readme


def test_readme_roadmap_numbering_is_sequential():
    repo_root = Path(__file__).resolve().parents[2]
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    roadmap = readme.split("## Roadmap", 1)[1].split("## Engineering Notes", 1)[0]

    numbers = [int(match) for match in re.findall(r"^([0-9]+)\. \*\*", roadmap, flags=re.MULTILINE)]
    assert numbers
    assert numbers == list(range(1, len(numbers) + 1))


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


def test_scoring_docs_explain_bounded_additive_weight_semantics():
    repo_root = Path(__file__).resolve().parents[2]
    scoring_model = (repo_root / "docs" / "scoring_model.md").read_text(encoding="utf-8")
    scoring_calibration = (repo_root / "docs" / "scoring_calibration.md").read_text(encoding="utf-8")

    for text in (scoring_model, scoring_calibration):
        assert "not probability mixture coefficients" in text
        assert "not required to sum to 1.0" in text
        assert "bounded additive priority contributions" in text
    assert "A higher generic CVE risk score does not imply confirmed exploitation in the local environment." in scoring_model


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
        "Scenario report: reports/thesis_scenario_report.json",
        "Artifact directory: reports/thesis",
        "Manifest: reports/thesis/manifest.json",
        "Demo walkthrough: reports/thesis/demo_walkthrough.md",
    ):
        assert required in makefile


def test_makefile_setup_python_creates_expected_virtualenv():
    repo_root = Path(__file__).resolve().parents[2]
    makefile = (repo_root / "Makefile").read_text(encoding="utf-8")
    doc = (repo_root / "docs" / "thesis_reproducibility.md").read_text(encoding="utf-8")

    for required in (
        "setup-python:",
        "python3 -m venv .venv",
        ".venv/bin/python -m pip install --upgrade pip",
        ".venv/bin/python -m pip install -r requirements.txt",
    ):
        assert required in makefile

    assert "make setup-python" in doc
    assert "creates `agent-python/.venv`" in doc


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
