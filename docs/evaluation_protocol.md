# Evaluation Protocol

Evaluation uses deterministic model exports joined with optional local EPSS and CISA KEV files. Tests and thesis artifacts do not require network access.

The built-in thesis fixture is a controlled evaluation set, not a live threat-intelligence benchmark. It is designed to validate ranking behavior, ablation behavior, correlation-decision exports, and artifact generation with reproducible inputs. Real-world validation should use larger NVD, EPSS, and CISA KEV exports.

The fixture includes bounded Dread cases for behavioral validation: Dread-only manual review, Dread corroborated by stronger URLhaus/KEV evidence, and weak Dread rejection. These cases do not require live Dread access and do not treat Dread as ground truth.

The fixture also includes false-positive stress cases: keyword-only URLhaus evidence, stale external evidence, unrelated product/vendor overlap, and IOC mentions without vulnerability context. These validate that rejected or manual-review evidence remains diagnostic and is excluded from accepted-evidence counts, correlation signal, graph/risk boosting, and high-confidence treatment.

URLhaus candidate accounting separates raw retrieval volume from evidence decisions. URLhaus retrieval first applies a conservative prefilter so generic vulnerability and protocol terms do not drive broad database queries. `ignored_low_signal_count` records any remaining candidates with no exact CVE match, no high-signal terms, no meaningful shared terms, and no usable lexical, semantic, temporal, or entity support. These ignored candidates are not rejected evidence and do not affect risk, confidence, graph support, or accepted-evidence counts. `rejected_match_count` is reserved for signal-bearing candidates that still fail the evidence gate.

Confidence reporting separates assessment confidence from data completeness. Missing EPSS, KEV, or accepted external evidence is reported as a coverage limitation instead of implying that technical severity should be zeroed. Very high confidence still requires stronger corroboration, while metadata-rich CVEs can retain moderate confidence when external coverage is incomplete.

Risk scoring can also surface intrinsic technical criticality without external corroboration. A narrow intrinsic-criticality floor allows recent CVSS 9.8/10 CVEs with strong intrinsic exploitation context to reach approximately `8.1` risk even when EPSS, KEV, URLhaus, and Dread evidence are unavailable. This floor is not evidence and does not increase confidence. It preserves the risk/confidence separation: high intrinsic risk can coexist with moderate confidence and explicit coverage limitations.

## Operational Risk Evaluation

Generic CVE risk is evaluated separately from asset-aware operational risk. The deterministic thesis scenario applies vulnerable-product metadata to a small asset inventory so the same CVE can be compared across applicable, non-applicable, patched, exposed, and compensating-control contexts.

Operational risk remains bounded in `[0, 10]` and preserves the generic CVE score as `source_risk_score`. Non-applicable CVE/asset pairs are treated as non-actionable. Patched assets and active compensating controls reduce urgency, while public-facing critical assets increase urgency. These checks validate deterministic behavior, not real-world asset inventory quality.

## Benchmark Strategies

The benchmark supports:

- `cvss_only`
- `epss_only`
- `cvss_epss`
- `kev_first`
- `model_risk`
- `model_confidence_weighted`
- `signal_based_model`

Metrics include Precision@K, Recall@K, NDCG@K, KEV hit rate@K, mean reciprocal rank, and mean KEV rank when KEV labels are available.

## Ablations

Exact ablations are reported only when exported component fields exist:

- `without_epss`
- `without_kev`
- `without_correlation`
- `without_graph`
- `without_recency`
- `without_confidence_weighting`

Variants that require recomputing retrieval, graph construction, or accepted evidence are marked unsupported with an explicit reason. Metrics are not fabricated.

## Sensitivity Analysis

The thesis artifacts include an offline scoring sensitivity analysis. It recomputes model risk from exported normalized fixture signals under deterministic bounded weight perturbations while leaving the production/default scoring weights unchanged.

The analysis reports top-5 overlap with the canonical baseline and whether qualitative guardrails remain true. It probes robustness to reasonable weight changes, but it is not statistical calibration and does not replace larger real-world validation.

## Explanation Traces

The thesis artifacts include deterministic risk explanation traces generated from the structured scenario report. These traces link CVSS, EPSS, KEV, normalized scoring signals, weighted contributions, evidence-gate decisions, confidence context, and asset-aware operational-risk examples.

The traces support auditability and appendix/debugging use. They do not change scoring behavior and should not be interpreted as statistical validation.

## Runtime Diagnostics

After a live local re-analysis, run:

```bash
make thesis-runtime-diagnostics
```

The command is read-only and writes operational diagnostics under `reports/runtime/`. It reports processed counts, risk and confidence distributions, EPSS/KEV coverage, URLhaus raw/ignored/evaluated/accepted/manual/rejected candidate counts, and high-risk moderate-confidence examples. This is an operational sanity check for the local database, not the deterministic thesis benchmark.

## Learned Calibration Experiment

Run:

```bash
make thesis-learned-calibration
```

This read-only export creates experimental learned-calibration artifacts from existing analyzed CVE records. It builds deterministic proxy labels, baseline heuristic-ranking metrics, optional scikit-learn model outputs, learned-vs-heuristic comparisons, disagreement examples, feature-importance exports, ablation plans, leakage checks, and thesis narrative summaries.

The proxy labels are not ground truth. The experiment does not change production `risk_score`, does not change URLhaus/Dread evidence gates, does not use live Dread crawling, and does not recalibrate confidence. Results are diagnostic and limited by sparse EPSS, KEV, and accepted external-evidence coverage; they should not be presented as proof of real-world exploit prediction.

The learned-calibration bundle also includes legacy high-risk diagnostics and an illustrative legacy dampening counterfactual. These outputs distinguish modern intrinsic criticality floor cases from old high-CVSS retained-severity cases and high-risk cases with no accepted external evidence. They are not production scoring changes. Preserving old CVSS 10 severity can be defensible for intrinsic technical severity, but lack of EPSS, KEV, or accepted external evidence limits operational interpretation. Future age-aware dampening should be evaluated only with stronger labels or asset context.

## Thesis Artifacts

Run:

```bash
make thesis-artifacts
```

The command runs the deterministic thesis fixture scenario and writes:

```text
reports/thesis/deterministic/
  scoring_summary.md
  scoring_distribution.csv
  scoring_distribution.md
  scoring_sensitivity.csv
  scoring_sensitivity.md
  benchmark_summary.csv
  benchmark_summary.md
  ablation_summary.csv
  ablation_summary.md
  correlation_decisions.csv
  case_studies.json
  risk_explanation_traces.json
  risk_explanation_traces.md
  results_summary.md
  thesis_results_section.md
  limitations_and_validity.md
  thesis_defense_pack.md
  methodology_summary.md
  manifest.json
```

The artifact bundle is intended for thesis tables and appendix material. It is not a claim of statistical significance, field prevalence, or production asset-inventory accuracy. Real-world operational evaluation requires high-quality asset inventory, product/version metadata, patch-state data, exposure classification, and validated compensating-control evidence.

False-positive stress cases are deterministic guardrails, not a complete adversarial evaluation of all possible noisy intelligence records.

## Artifact Quality Gate

Run the quality gate after regenerating thesis artifacts:

```bash
make thesis-artifact-quality
```

Equivalent direct command:

```bash
cd agent-python
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m evaluation.thesis_artifact_quality --artifact-dir ../reports/thesis/deterministic
```

The direct command is run from `agent-python`, so `../reports/thesis/deterministic` refers to the root-level deterministic thesis artifact directory.

The gate validates artifact structure and formatting only. It checks manifest entries, listed file existence, required case studies, required explanation traces and fields, required CSV columns, known Markdown/CSV formatting regressions, and Markdown table shape. It does not recompute statistical correctness, prove real-world validity, or change model behavior.
