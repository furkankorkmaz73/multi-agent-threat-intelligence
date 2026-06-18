# Thesis Reproducibility Guide

This repository implements the thesis prototype for a multi-source cyber threat intelligence and risk-prioritization platform. In the thesis context, the generated artifacts demonstrate deterministic behavior of CVE scoring, confidence estimation, evidence gating, source sensitivity, and asset-aware operational risk.

The thesis artifact bundle is generated from a controlled deterministic fixture. It is not a live threat-intelligence benchmark and does not require live network access. The fixture is used to validate ranking behavior, ablation behavior, explanation traces, and artifact structure. Real-world validation still requires larger NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets.

## Environment Assumptions

- Repository root: `~/Coding/multi-agent-threat-intelligence`
- Tested Python runtime: Python 3.11
- Tested Go runtime: Go 1.24.x
- Tested Node runtime: Node 24.x
- Tested local database: MongoDB 7.x
- Python virtual environment: `agent-python/.venv`
- Python imports use `PYTHONPATH=src`
- Thesis artifacts have a no live network requirement and are generated without live network calls
- Dread remains optional, bounded, and disabled for deterministic thesis artifact generation

## Local Python Setup

From the repository root, create the expected Python virtual environment and install dependencies with:

```bash
make setup-python
```

This command creates `agent-python/.venv` and installs `agent-python/requirements.txt` into that environment. It is safe to rerun when dependencies change.

For thesis reproducibility from the pinned snapshot, use:

```bash
make setup-python-locked
```

`setup-python` is the normal development setup from `requirements.txt`. `setup-python-locked` is the thesis reproducibility setup from `requirements.lock` and runs `pip check` after installation.

Optional no-skip local test runs use `agent-python/requirements-test.txt`. That file extends the normal requirements with scikit-learn for the gated learned-calibration tests. It is not a production runtime dependency file.

`agent-python/requirements.txt` is the human-maintained dependency input used by setup and CI. `agent-python/requirements.lock` is a thesis reproducibility snapshot generated from the tested Python 3.11 virtual environment with:

```bash
cd agent-python
.venv/bin/python -m pip freeze --exclude-editable > requirements.lock
.venv/bin/python -m pip check
```

Regenerate the lock file only from a clean project virtual environment. It should not contain editable installs, local filesystem paths, or newly installed packages that are not part of the project environment.

## Final Validation Sequence

Run this sequence from a clean checkout or before freezing thesis artifacts:

```bash
cd ~/Coding/multi-agent-threat-intelligence

cd agent-python
PATH=.venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src pytest -q -p no:ddtrace

cd ..
make thesis-artifacts
make thesis-artifact-quality
git status --short
```

Expected result:

- The Python test suite passes.
- `make thesis-artifacts` regenerates `reports/thesis/deterministic/`.
- `make thesis-artifact-quality` returns a passing JSON summary.
- `git status --short` shows only intentional working-tree changes, if any.

Default `make test-python` does not require scikit-learn. Optional learned-calibration ML tests require `SKLEARN_OPTIONAL_TESTS=1` and scikit-learn installed:

```bash
make test-python-optional-ml
```

For a full local Python test profile with no skipped tests, install the optional test dependencies and run:

```bash
cd agent-python
.venv/bin/python -m pip install -r requirements-test.txt
./scripts/run_full_python_tests.sh
```

or from the repository root:

```bash
make test-python-full
```

The full profile enables `RUN_E2E_SYSTEM=1` and `SKLEARN_OPTIONAL_TESTS=1`, starts only the `mongodb` Docker Compose service when MongoDB is not already reachable, verifies MongoDB ping, verifies scikit-learn imports, runs `pytest tests -rs -q`, and fails if pytest still reports skipped tests. It requires Docker, Go, the Python virtual environment, MongoDB 7.x through Compose, and the optional scikit-learn test dependency.

For a demo-oriented flow that runs artifact generation and the quality gate together, use:

```bash
make thesis-demo
```

For read-only diagnostics after a live local re-analysis, use:

```bash
make thesis-runtime-diagnostics
```

This writes `reports/runtime/` and summarizes risk, confidence, EPSS/KEV coverage, URLhaus candidate accounting, and high-risk moderate-confidence cases. It is an operational sanity check, not the deterministic thesis benchmark.

For the experimental learned-calibration export, use:

```bash
make thesis-learned-calibration
```

This reads existing analyzed CVE records and writes proxy-label, baseline, optional model, leakage-check, and narrative artifacts. It does not change production `risk_score`, does not alter evidence gates, does not use live Dread crawling, and does not treat proxy labels as ground truth.

## Report Root Strategy

Generated report outputs use root-level directories:

```text
reports/thesis/deterministic/          deterministic thesis fixture artifacts
reports/thesis/learned_calibration/    optional learned-calibration artifacts
reports/runtime/                       read-only runtime diagnostics
reports/real_benchmark/                optional real/curated benchmark experiments
```

The `agent-python/.cache/real_benchmark/` directory is reserved for ignored local official-format input caches used by optional real/curated benchmark commands.

## Generated Artifact Inventory

The two bundles use separate subdirectories under root-level `reports/thesis/`, and they are produced by different Makefile targets.

### A. Deterministic Thesis Bundle

Generated by:

```bash
make thesis-artifacts
make thesis-demo
```

Output:

```text
reports/thesis/deterministic/
```

Contains deterministic fixture outputs only:

```text
reports/thesis/deterministic/manifest.json
reports/thesis/deterministic/scoring_summary.md
reports/thesis/deterministic/scoring_distribution.csv
reports/thesis/deterministic/scoring_distribution.md
reports/thesis/deterministic/scoring_sensitivity.csv
reports/thesis/deterministic/scoring_sensitivity.md
reports/thesis/deterministic/benchmark_summary.csv
reports/thesis/deterministic/benchmark_summary.md
reports/thesis/deterministic/ablation_summary.csv
reports/thesis/deterministic/ablation_summary.md
reports/thesis/deterministic/correlation_decisions.csv
reports/thesis/deterministic/case_studies.json
reports/thesis/deterministic/risk_explanation_traces.json
reports/thesis/deterministic/risk_explanation_traces.md
reports/thesis/deterministic/demo_walkthrough.md
reports/thesis/deterministic/results_summary.md
reports/thesis/deterministic/thesis_results_section.md
reports/thesis/deterministic/limitations_and_validity.md
reports/thesis/deterministic/thesis_defense_pack.md
reports/thesis/deterministic/methodology_summary.md
```

`manifest.json` lists the generated deterministic files, record count, and correlation-decision count. It is the first file to inspect when checking that the deterministic bundle is complete.

### B. Optional Learned Calibration Bundle

Generated by:

```bash
make thesis-learned-calibration
make thesis-learned-calibration-quality
```

Output:

```text
reports/thesis/learned_calibration/
```

Contains experimental learned-calibration, no-overclaim, appendix, reviewer, runtime-snapshot, and legacy diagnostic artifacts:

```text
reports/thesis/learned_calibration/learned_calibration_dataset.csv
reports/thesis/learned_calibration/learned_calibration_labels.csv
reports/thesis/learned_calibration/learned_calibration_report.json
reports/thesis/learned_calibration/learned_calibration_summary.md
reports/thesis/learned_calibration/learned_calibration_baseline_metrics.json
reports/thesis/learned_calibration/learned_calibration_baseline_metrics.md
reports/thesis/learned_calibration/learned_calibration_predictions.csv
reports/thesis/learned_calibration/learned_calibration_model_report.json
reports/thesis/learned_calibration/learned_calibration_model_summary.md
reports/thesis/learned_calibration/learned_vs_heuristic_comparison.json
reports/thesis/learned_calibration/learned_vs_heuristic_comparison.md
reports/thesis/learned_calibration/learned_calibration_disagreements.csv
reports/thesis/learned_calibration/learned_calibration_disagreements.md
reports/thesis/learned_calibration/learned_calibration_feature_importance.csv
reports/thesis/learned_calibration/learned_calibration_feature_importance.md
reports/thesis/learned_calibration/learned_calibration_ablation.csv
reports/thesis/learned_calibration/learned_calibration_ablation.md
reports/thesis/learned_calibration/learned_calibration_leakage_checks.json
reports/thesis/learned_calibration/learned_calibration_leakage_checks.md
reports/thesis/learned_calibration/learned_calibration_thesis_section.md
reports/thesis/learned_calibration/learned_calibration_limitations.md
reports/thesis/learned_calibration/legacy_high_risk_diagnostics.csv
reports/thesis/learned_calibration/legacy_high_risk_diagnostics.json
reports/thesis/learned_calibration/legacy_high_risk_diagnostics.md
reports/thesis/learned_calibration/legacy_dampening_counterfactual.csv
reports/thesis/learned_calibration/legacy_dampening_counterfactual.json
reports/thesis/learned_calibration/legacy_dampening_counterfactual.md
```

## Artifact Roles

Deterministic thesis bundle:

- `scoring_summary.md`: overview of top scored CVEs, risk levels, and scoring behavior.
- `scoring_distribution.csv`: machine-readable score distribution, normalized signals, and weighted contribution exports.
- `scoring_distribution.md`: human-readable distribution summary and model-vs-CVSS ranking examples.
- `scoring_sensitivity.csv`: robustness results under bounded scoring-weight perturbations.
- `scoring_sensitivity.md`: concise sensitivity analysis summary and qualitative guardrail status.
- `benchmark_summary.csv`: machine-readable baseline comparison metrics.
- `benchmark_summary.md`: readable benchmark table for thesis review.
- `ablation_summary.csv`: machine-readable signal-removal results.
- `ablation_summary.md`: readable ablation summary with unsupported variants documented.
- `correlation_decisions.csv`: accepted, manual_review, and rejected evidence decisions with gate metadata.
- `case_studies.json`: selected thesis case studies for scoring, Dread, false-positive resistance, and asset-aware risk.
- `evidence_policy_matrix.md`: thesis-facing matrix describing URLhaus and Dread evidence policy, scoring effects, confidence effects, and claim boundaries.
- `evidence_diagnostics_summary.md`: deterministic summary of URLhaus and Dread candidate status counts, reason-code distributions, and absent/future fixture coverage.
- `urlhaus_dread_case_studies.md`: readable case-study table for accepted URLhaus, URLhaus false-positive controls, Dread manual-review handling, and weak Dread rejection.
- `weak_source_handling_table.json`: machine-readable weak-source policy table used by the artifact quality gate.
- `risk_explanation_traces.json`: structured end-to-end traces from raw inputs to risk, confidence, and operational risk.
- `risk_explanation_traces.md`: readable appendix-style explanation traces.
- `demo_walkthrough.md`: concise defense-demo walkthrough for reading generated outputs.
- `results_summary.md`: compact generated technical results summary.
- `thesis_results_section.md`: English thesis-ready Results and Evaluation draft section.
- `limitations_and_validity.md`: generated conservative limitations and validity summary.
- `thesis_defense_pack.md`: concise defense preparation artifact with claim scope and Q&A.
- `methodology_summary.md`: concise method summary for the deterministic artifact bundle.

Optional learned calibration bundle:

- `learned_calibration_dataset.csv`: flat experimental feature export from existing analyzed CVE records.
- `learned_calibration_labels.csv`: deterministic proxy-label export; proxy labels are not ground truth.
- `learned_calibration_report.json` and `learned_calibration_summary.md`: feasibility, coverage, missing-feature, and proxy-label summaries.
- `learned_calibration_baseline_metrics.*`: heuristic `risk_score` ranking compared against proxy labels.
- `learned_calibration_model_*` and `learned_calibration_predictions.csv`: optional learned-calibration model outputs or explicit skipped status.
- `learned_vs_heuristic_comparison.*`: learned-probability ranking compared with heuristic ranking when predictions exist.
- `learned_calibration_disagreements.*`: examples for thesis discussion when learned predictions exist.
- `learned_calibration_feature_importance.*`: coefficient/importance exports when a model is trained.
- `learned_calibration_ablation.*`: deterministic learned-calibration ablation plan and results or skipped status.
- `learned_calibration_leakage_checks.*`: checks showing `risk_score` and proxy-label fields are excluded from model inputs and production behavior is unchanged.
- `learned_calibration_thesis_section.md` and `learned_calibration_limitations.md`: conservative thesis prose for the experimental learned-calibration discussion.
- `legacy_high_risk_diagnostics.*`: diagnostic grouping for modern intrinsic-floor cases, old high-CVSS retained-severity cases, and high-risk records without accepted external evidence.
- `legacy_dampening_counterfactual.*`: illustrative age-aware dampening counterfactual for future-work discussion; it does not change production scoring.

For the static version of the thesis claim boundaries, see [`docs/thesis_limitations.md`](thesis_limitations.md). For a claim-to-evidence map for thesis writing and defense preparation, see [`docs/thesis_claim_evidence_map.md`](thesis_claim_evidence_map.md). For a chapter-by-chapter English writing plan, see [`docs/thesis_chapter_blueprint.md`](thesis_chapter_blueprint.md). For the experimental learned-calibration export, see [`docs/learned_calibration.md`](learned_calibration.md).

## Interpreting Evaluation Outputs

`benchmark_summary.*` compares ranking strategies such as `cvss_only`, `epss_only`, `cvss_epss`, `kev_first`, `model_risk`, confidence-aware model variants, and the signal-based model. These results show behavior on the controlled fixture. They should not be described as statistically significant real-world performance.

`ablation_summary.*` reports what happens when supported signals are removed from the exported fixture records. Unsupported variants are explicitly marked when exact removal would require recomputation of upstream retrieval, graph, or evidence decisions. Unsupported rows are not fabricated metrics.

`scoring_sensitivity.*` probes whether ranking behavior remains qualitatively stable under bounded deterministic scoring-weight perturbations. The default production weights are not changed by this analysis. This supports behavioral robustness discussion, not statistical calibration.

`risk_explanation_traces.*` links CVSS, EPSS, KEV, normalized signals, weighted contributions, evidence decisions, confidence context, and asset-aware operational-risk examples. Use these traces to answer why a CVE received a particular generic risk score, confidence score, and operational risk score.

`learned_calibration_*` artifacts are diagnostic. They use proxy labels that are not ground truth, preserve the existing heuristic `risk_score`, preserve evidence gates, avoid live Dread access, and keep confidence separate from risk. They can support a thesis discussion of feasibility and limitations, but not a claim of real-world exploit prediction.

## Artifact Quality Gate

Run:

```bash
make thesis-artifact-quality
```

The quality gate validates structure and formatting of the generated bundle. It checks:

- manifest integrity and listed file existence
- required case-study identifiers
- required risk explanation traces and fields
- required CSV columns for correlation decisions and scoring sensitivity
- known malformed Markdown/CSV string regressions
- Markdown table row shape and pipe-count consistency

A passing run prints a JSON summary similar to:

```json
{"artifact_dir":"reports/thesis/deterministic","checked_files":20,"checked_markdown_files":12,"status":"passed"}
```

The quality gate does not validate statistical correctness, does not prove real-world generalization, and does not change model behavior.

## Known Limitations

- The deterministic fixture is intentionally controlled and small.
- The bundle is not a live operational benchmark.
- No statistical significance claim should be made from these artifacts alone.
- Real-world validation requires larger and independently curated NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets.
- Asset-aware operational risk depends on asset inventory quality, product/version matching, exposure classification, patch-state evidence, and compensating-control evidence.
- Dread evidence is experimental, optional, bounded, and not treated as ground truth.
