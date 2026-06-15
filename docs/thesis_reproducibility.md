# Thesis Reproducibility Guide

This repository implements the thesis prototype for a multi-source cyber threat intelligence and risk-prioritization platform. In the thesis context, the generated artifacts demonstrate deterministic behavior of CVE scoring, confidence estimation, evidence gating, source sensitivity, and asset-aware operational risk.

The thesis artifact bundle is generated from a controlled deterministic fixture. It is not a live threat-intelligence benchmark and does not require live network access. The fixture is used to validate ranking behavior, ablation behavior, explanation traces, and artifact structure. Real-world validation still requires larger NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets.

## Environment Assumptions

- Repository root: `~/Coding/multi-agent-threat-intelligence`
- Python virtual environment: `agent-python/.venv`
- Python imports use `PYTHONPATH=src`
- Thesis artifacts have a no live network requirement and are generated without live network calls
- Dread remains optional, bounded, and disabled for deterministic thesis artifact generation

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
- `make thesis-artifacts` regenerates `agent-python/reports/thesis/`.
- `make thesis-artifact-quality` returns a passing JSON summary.
- `git status --short` shows only intentional working-tree changes, if any.

## Generated Artifact Inventory

The deterministic bundle is written under `agent-python/reports/thesis/`:

```text
reports/thesis/manifest.json
reports/thesis/scoring_summary.md
reports/thesis/scoring_distribution.csv
reports/thesis/scoring_distribution.md
reports/thesis/scoring_sensitivity.csv
reports/thesis/scoring_sensitivity.md
reports/thesis/benchmark_summary.csv
reports/thesis/benchmark_summary.md
reports/thesis/ablation_summary.csv
reports/thesis/ablation_summary.md
reports/thesis/correlation_decisions.csv
reports/thesis/case_studies.json
reports/thesis/risk_explanation_traces.json
reports/thesis/risk_explanation_traces.md
reports/thesis/results_summary.md
reports/thesis/thesis_results_section.md
reports/thesis/limitations_and_validity.md
reports/thesis/thesis_defense_pack.md
reports/thesis/methodology_summary.md
```

`manifest.json` lists the generated files, record count, and correlation-decision count. It is the first file to inspect when checking that the bundle is complete.

## Artifact Roles

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
- `risk_explanation_traces.json`: structured end-to-end traces from raw inputs to risk, confidence, and operational risk.
- `risk_explanation_traces.md`: readable appendix-style explanation traces.
- `results_summary.md`: compact generated technical results summary.
- `thesis_results_section.md`: English thesis-ready Results and Evaluation draft section.
- `limitations_and_validity.md`: generated conservative limitations and validity summary.
- `thesis_defense_pack.md`: concise defense preparation artifact with claim scope and Q&A.
- `methodology_summary.md`: concise method summary for the deterministic artifact bundle.

For the static version of the thesis claim boundaries, see [`docs/thesis_limitations.md`](thesis_limitations.md).

## Interpreting Evaluation Outputs

`benchmark_summary.*` compares ranking strategies such as `cvss_only`, `epss_only`, `cvss_epss`, `kev_first`, `model_risk`, confidence-aware model variants, and the signal-based model. These results show behavior on the controlled fixture. They should not be described as statistically significant real-world performance.

`ablation_summary.*` reports what happens when supported signals are removed from the exported fixture records. Unsupported variants are explicitly marked when exact removal would require recomputation of upstream retrieval, graph, or evidence decisions. Unsupported rows are not fabricated metrics.

`scoring_sensitivity.*` probes whether ranking behavior remains qualitatively stable under bounded deterministic scoring-weight perturbations. The default production weights are not changed by this analysis. This supports behavioral robustness discussion, not statistical calibration.

`risk_explanation_traces.*` links CVSS, EPSS, KEV, normalized signals, weighted contributions, evidence decisions, confidence context, and asset-aware operational-risk examples. Use these traces to answer why a CVE received a particular generic risk score, confidence score, and operational risk score.

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
{"artifact_dir":"reports/thesis","checked_files":19,"checked_markdown_files":11,"status":"passed"}
```

The quality gate does not validate statistical correctness, does not prove real-world generalization, and does not change model behavior.

## Known Limitations

- The deterministic fixture is intentionally controlled and small.
- The bundle is not a live operational benchmark.
- No statistical significance claim should be made from these artifacts alone.
- Real-world validation requires larger and independently curated NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets.
- Asset-aware operational risk depends on asset inventory quality, product/version matching, exposure classification, patch-state evidence, and compensating-control evidence.
- Dread evidence is experimental, optional, bounded, and not treated as ground truth.
