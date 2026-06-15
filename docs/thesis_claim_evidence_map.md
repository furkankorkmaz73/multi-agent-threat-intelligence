# Thesis Claim-to-Evidence Map

## Purpose

This document maps thesis claims to reproducible repository evidence. It is intended to support thesis writing and defense preparation by showing where each claim is supported, what the evidence demonstrates, and what the claim does not cover.

The map should be read together with `docs/thesis_limitations.md` and `docs/thesis_reproducibility.md`.

## Claim Boundary Summary

The project is a multi-agent-inspired and agent-supported modular CTI risk-analysis prototype. It separates collection, deterministic analysis, scoring, confidence estimation, evidence-gated correlation, evaluation, and reporting responsibilities.

It is not a fully autonomous LLM-agent system. The evaluation is controlled behavioral validation over a deterministic fixture, not statistical real-world validation.

## Claim-to-Evidence Table

| Thesis claim | Supporting artifact / file | What it demonstrates | Limitation / non-claim |
| --- | --- | --- | --- |
| Multi-agent-inspired modular architecture | `README.md`, `docs/thesis_limitations.md`, `agent-python/src/analysis/`, `agent-python/src/evaluation/` | The repository separates collection, analysis, correlation, scoring, evaluation, and reporting into modular responsibilities. | Does not claim full autonomy or autonomous LLM-agent operation. |
| Heuristic signal-based risk scoring | `docs/scoring_model.md`, `agent-python/src/analysis/scoring_signals.py`, `reports/thesis/scoring_distribution.csv` | Normalized CVSS, EPSS, KEV, recency, correlation, graph, and context signals contribute through a canonical formula. | Weights are heuristic engineering choices, not learned or statistically optimized. |
| Confidence separated from risk | `docs/scoring_model.md`, `reports/thesis/scoring_distribution.csv`, `reports/thesis/risk_explanation_traces.json` | Risk expresses prioritization urgency while confidence expresses evidence reliability. | High risk is not equivalent to high certainty. |
| Evidence-gated CVE-IOC correlation | `docs/correlation_model.md`, `reports/thesis/correlation_decisions.csv` | Correlation candidates are classified as `accepted`, `manual_review`, or `rejected` with provenance and gate metadata. | Keyword overlap alone is not accepted evidence. |
| False-positive resistance | `reports/thesis/correlation_decisions.csv`, `reports/thesis/case_studies.json`, `docs/correlation_model.md` | Keyword-only, stale, unrelated-product, and manual-review cases remain diagnostic and do not boost risk as accepted evidence. | The deterministic stress cases are not a complete adversarial evaluation of all noisy CTI records. |
| Bounded Dread handling | `docs/dread_scope.md`, `reports/thesis/case_studies.json`, `reports/thesis/correlation_decisions.csv` | Dread is optional, experimental, bounded, default-off, and confidence-capped unless corroborated by stronger evidence. | Dread is not treated as ground truth and is not the core contribution. |
| Asset-aware operational risk examples | `docs/scoring_model.md`, `reports/thesis/case_studies.json`, `reports/thesis/risk_explanation_traces.json` | Generic CVE risk remains separate from operational risk adjusted by applicability, exposure, criticality, patch state, and controls. | The examples do not validate organization-wide operational risk without high-quality asset inventory. |
| Explanation traces | `reports/thesis/risk_explanation_traces.json`, `reports/thesis/risk_explanation_traces.md` | Traces connect inputs, normalized signals, weighted contributions, evidence decisions, confidence, and asset-aware examples. | Traces support auditability, not statistical validation. |
| Baseline ranking comparison | `reports/thesis/benchmark_summary.csv`, `reports/thesis/benchmark_summary.md` | The fixture compares CVSS-only, EPSS-only, KEV-first, model-risk, confidence-aware, and signal-based rankings. | Results apply to the controlled fixture and do not establish real-world superiority. |
| Ablation analysis | `reports/thesis/ablation_summary.csv`, `reports/thesis/ablation_summary.md` | Supported signal-removal variants show how ranking behavior changes when components are removed. | Unsupported variants are marked when exact removal would require recomputation. |
| Sensitivity analysis | `reports/thesis/scoring_sensitivity.csv`, `reports/thesis/scoring_sensitivity.md`, `docs/scoring_calibration.md` | Bounded perturbations probe whether qualitative behavior is stable under small weight changes. | Sensitivity analysis is a robustness probe, not calibration. |
| Reproducible artifact generation | `docs/thesis_reproducibility.md`, `Makefile`, `reports/thesis/manifest.json` | The thesis bundle can be regenerated deterministically with documented commands. | Reproducibility of the fixture does not imply live-data generalization. |
| Artifact quality gate | `agent-python/src/evaluation/thesis_artifact_quality.py`, `make thesis-artifact-quality` | The quality gate checks manifest integrity, required fields, required case studies, Markdown table shape, and unsafe generated claims. | The gate validates structure and wording, not statistical correctness. |
| Limitations and validity framing | `docs/thesis_limitations.md`, `reports/thesis/limitations_and_validity.md`, `reports/thesis/thesis_defense_pack.md` | Claim boundaries are explicit and thesis-safe. | Does not replace external validation or deployment hardening. |

## Suggested Thesis Chapter Usage

| Thesis chapter | Useful documents / artifacts | Suggested use |
| --- | --- | --- |
| Introduction / Motivation | `README.md`, `docs/thesis_limitations.md` | Describe the CTI prioritization problem and scope the prototype conservatively. |
| Related Work positioning | `docs/scoring_model.md`, `docs/dread_scope.md`, `docs/correlation_model.md` | Position CVSS, EPSS, KEV, evidence gating, and unreliable intelligence handling. |
| Methodology | `reports/thesis/methodology_summary.md`, `docs/thesis_reproducibility.md` | Explain deterministic fixture design and reproducible artifact generation. |
| System Architecture | `README.md`, `docs/thesis_limitations.md` | Present the multi-agent-inspired modular architecture without claiming full autonomy. |
| Risk Scoring Model | `docs/scoring_model.md`, `docs/scoring_calibration.md`, `reports/thesis/scoring_distribution.csv` | Explain normalized signals, heuristic weights, contribution exports, and calibration limits. |
| Evaluation | `docs/evaluation_protocol.md`, `reports/thesis/benchmark_summary.csv`, `reports/thesis/ablation_summary.csv`, `reports/thesis/scoring_sensitivity.csv` | Present controlled behavioral validation, baseline comparison, ablation, and sensitivity analysis. |
| Results | `reports/thesis/results_summary.md`, `reports/thesis/thesis_results_section.md` | Use generated English results prose and compact tables as draft material. |
| Limitations | `docs/thesis_limitations.md`, `reports/thesis/limitations_and_validity.md` | State claim boundaries, generalization limits, Dread limits, and future validation needs. |
| Defense Preparation | `reports/thesis/thesis_defense_pack.md`, `docs/thesis_claim_evidence_map.md` | Prepare concise answers that connect claims to files and artifacts. |

## Defense Risk Register

| Likely question | Supported answer location | Conservative answer boundary |
| --- | --- | --- |
| Is this really multi-agent? | `README.md`, `docs/thesis_limitations.md`, `reports/thesis/thesis_defense_pack.md` | It is multi-agent-inspired and agent-supported, with modular specialist responsibilities; it is not a fully autonomous LLM-agent system. |
| Why are weights heuristic? | `docs/scoring_model.md`, `docs/scoring_calibration.md`, `reports/thesis/scoring_sensitivity.md` | The weights encode transparent engineering semantics and are tested with bounded sensitivity analysis; they are not learned or statistically optimized. |
| Does the fixture prove real-world effectiveness? | `docs/evaluation_protocol.md`, `docs/thesis_limitations.md`, `reports/thesis/limitations_and_validity.md` | No. It supports controlled behavioral validation and reproducibility only. |
| Why include Dread? | `docs/dread_scope.md`, `docs/correlation_model.md`, `reports/thesis/case_studies.json` | Dread demonstrates bounded handling of weak optional intelligence; Dread-only evidence is not high-confidence evidence. |
| Why not use Neo4j? | `docs/thesis_limitations.md`, `reports/thesis/thesis_defense_pack.md` | Persistent graph databases are future work; current graph context is bounded fixture context. |
| What is the actual contribution? | `reports/thesis/thesis_defense_pack.md`, `docs/thesis_claim_evidence_map.md` | The contribution is an explainable modular CTI risk-analysis architecture with reproducible behavioral validation artifacts. |
| What would production use require? | `docs/thesis_limitations.md`, `README.md`, `reports/thesis/thesis_defense_pack.md` | Production use would require deployment hardening, larger curated datasets, external validation, asset inventory quality, monitoring, governance, and analyst workflows. |

## Non-Claims

This project does not claim:

- full autonomy
- production readiness
- statistical significance
- real-world validation
- optimized or learned weights
- Dread as ground truth
- persistent graph database implementation
