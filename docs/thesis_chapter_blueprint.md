# Thesis Chapter Blueprint

## Purpose

This document is a practical English writing blueprint for the thesis. It maps repository evidence, static thesis documentation, and generated thesis artifacts into a chapter-by-chapter writing plan.

The blueprint is intended to support thesis writing and defense preparation. It does not introduce new technical claims beyond the repository artifacts and the claim boundaries documented in `docs/thesis_limitations.md` and `docs/thesis_claim_evidence_map.md`.

## Global Thesis Positioning

- The project is a multi-agent-inspired and agent-supported modular CTI risk-analysis prototype.
- It is not a fully autonomous LLM-agent system.
- The evaluation is controlled behavioral validation, not statistical real-world validation.
- Scoring weights are heuristic engineering choices tested through bounded sensitivity analysis.
- Dread is optional, experimental, bounded, default-off, and not treated as ground truth.
- Persistent graph databases such as Neo4j are future work, not current thesis scope.

## Chapter-by-Chapter Blueprint

### Introduction

| Item | Guidance |
| --- | --- |
| Main message | CTI triage requires explainable prioritization that separates technical severity, evidence reliability, and operational context. |
| Supporting repository files / artifacts | `README.md`, `docs/thesis_limitations.md`, `docs/thesis_claim_evidence_map.md` |
| Suggested figures or tables | High-level thesis contribution list; short problem-scope table. |
| Claims allowed | The prototype demonstrates a modular, explainable CTI risk-analysis workflow. |
| Claims to avoid | Do not claim production readiness, full autonomy, or real-world superiority. |

### Problem Definition

| Item | Guidance |
| --- | --- |
| Main message | Raw CVE severity alone is insufficient for operational prioritization because exploit likelihood, active exploitation evidence, correlation quality, confidence, and asset context matter. |
| Supporting repository files / artifacts | `docs/scoring_model.md`, `docs/correlation_model.md`, `docs/dread_scope.md` |
| Suggested figures or tables | Problem decomposition table: severity, likelihood, evidence, confidence, and asset context. |
| Claims allowed | The thesis addresses prioritization and explainability for controlled CTI risk analysis. |
| Claims to avoid | Do not claim complete SOC automation or complete operational coverage. |

### Related Work

| Item | Guidance |
| --- | --- |
| Main message | Position CVSS as severity, EPSS as exploit likelihood, KEV as active exploitation evidence, SSVC-style context as operational reasoning, and weak-source handling as evidence-gated analysis. |
| Supporting repository files / artifacts | `docs/scoring_model.md`, `docs/scoring_calibration.md`, `docs/correlation_model.md`, `docs/dread_scope.md` |
| Suggested figures or tables | Comparison table for CVSS, EPSS, KEV, correlation evidence, and asset context. |
| Claims allowed | Existing standards and feeds motivate a combined, explainable prioritization model. |
| Claims to avoid | Do not claim that any reference source is absolute ground truth. |

### System Architecture

| Item | Guidance |
| --- | --- |
| Main message | The system is a multi-agent-inspired and agent-supported modular architecture with deterministic domain services for scoring, correlation, evaluation, and reporting. |
| Supporting repository files / artifacts | `README.md`, `docs/thesis_claim_evidence_map.md`, `reports/thesis/thesis_defense_pack.md` |
| Suggested figures or tables | Architecture diagram showing collector, analyzer, scoring, confidence, correlation, evaluation, artifacts, and analyst-facing API/UI boundaries. |
| Claims allowed | The architecture separates responsibilities and supports reproducible analysis artifacts. |
| Claims to avoid | Do not describe it as a fully autonomous LLM-agent system. |

### Risk Scoring Model

| Item | Guidance |
| --- | --- |
| Main message | Generic CVE risk is computed from normalized bounded signals with heuristic weights, while confidence remains a separate evidence-reliability score. |
| Supporting repository files / artifacts | `docs/scoring_model.md`, `docs/scoring_calibration.md`, `reports/thesis/scoring_distribution.csv`, `reports/thesis/scoring_distribution.md` |
| Suggested figures or tables | Risk scoring signal table; weighted contribution example; risk vs confidence distinction table. |
| Claims allowed | The formula is deterministic, auditable, and contribution-based. |
| Claims to avoid | Do not claim learned optimal weights or statistical calibration. |

### Evidence Correlation and Confidence

| Item | Guidance |
| --- | --- |
| Main message | Correlation candidates are evidence-gated into accepted, manual_review, or rejected decisions; only accepted evidence supports risk and confidence. |
| Supporting repository files / artifacts | `docs/correlation_model.md`, `reports/thesis/correlation_decisions.csv`, `reports/thesis/case_studies.json` |
| Suggested figures or tables | Correlation decision table; false-positive stress-case table; confidence component overview. |
| Claims allowed | The fixture demonstrates deterministic handling of accepted, rejected, and manual-review evidence. |
| Claims to avoid | Do not claim that keyword overlap or weak forum chatter is verified evidence. |

### Asset-Aware Operational Risk

| Item | Guidance |
| --- | --- |
| Main message | Asset-aware operational risk is separate from generic CVE risk and adjusts urgency based on applicability, exposure, criticality, patch state, and controls. |
| Supporting repository files / artifacts | `docs/scoring_model.md`, `reports/thesis/case_studies.json`, `reports/thesis/risk_explanation_traces.json` |
| Suggested figures or tables | Asset applicability example table; generic risk vs operational risk comparison. |
| Claims allowed | The deterministic examples show how asset context changes prioritization. |
| Claims to avoid | Do not claim organization-wide validation without real asset inventory and external validation. |

### Evaluation Methodology

| Item | Guidance |
| --- | --- |
| Main message | Evaluation uses a deterministic controlled fixture for behavioral validation of ranking, ablation, sensitivity, false-positive resistance, explanation traces, and artifact generation. |
| Supporting repository files / artifacts | `docs/evaluation_protocol.md`, `docs/thesis_reproducibility.md`, `reports/thesis/methodology_summary.md` |
| Suggested figures or tables | Evaluation protocol table; fixture coverage table; artifact inventory table. |
| Claims allowed | The fixture supports reproducible behavioral validation. |
| Claims to avoid | Do not claim statistical significance, prevalence estimates, or live CTI benchmark validity. |

### Results

| Item | Guidance |
| --- | --- |
| Main message | Results should summarize ranking behavior, ablation behavior, sensitivity robustness, correlation decisions, explanation traces, and selected case studies from generated artifacts. |
| Supporting repository files / artifacts | `reports/thesis/results_summary.md`, `reports/thesis/thesis_results_section.md`, `reports/thesis/benchmark_summary.md`, `reports/thesis/ablation_summary.md`, `reports/thesis/scoring_sensitivity.md` |
| Suggested figures or tables | Baseline comparison table; ablation table; sensitivity summary table; case-study highlight table. |
| Claims allowed | The controlled fixture suggests intended prioritization behavior under reproducible conditions. |
| Claims to avoid | Do not claim real-world validation or broad operational superiority. |

### Limitations and Threats to Validity

| Item | Guidance |
| --- | --- |
| Main message | The main limitations are controlled fixture size, heuristic weights, no statistical calibration, bounded Dread treatment, asset inventory assumptions, and no persistent graph database implementation. |
| Supporting repository files / artifacts | `docs/thesis_limitations.md`, `reports/thesis/limitations_and_validity.md`, `docs/thesis_claim_evidence_map.md` |
| Suggested figures or tables | Limitations table; threat-to-validity table; future-validation requirements table. |
| Claims allowed | Limitations are explicit and aligned with artifact evidence. |
| Claims to avoid | Do not overstate deterministic fixture results as field evidence. |

### Conclusion and Future Work

| Item | Guidance |
| --- | --- |
| Main message | The thesis contribution is an explainable modular CTI risk-analysis prototype with reproducible behavioral validation artifacts and clear future work for real-world validation. |
| Supporting repository files / artifacts | `docs/thesis_limitations.md`, `docs/thesis_claim_evidence_map.md`, `reports/thesis/thesis_defense_pack.md` |
| Suggested figures or tables | Contribution summary; future-work roadmap. |
| Claims allowed | The work provides an auditable prototype and reproducible artifact pipeline. |
| Claims to avoid | Do not imply production readiness or completed field validation. |

### Defense Preparation Appendix

| Item | Guidance |
| --- | --- |
| Main message | The appendix should connect claims to evidence and prepare concise answers to expected defense questions. |
| Supporting repository files / artifacts | `docs/thesis_claim_evidence_map.md`, `reports/thesis/demo_walkthrough.md`, `reports/thesis/thesis_defense_pack.md`, `docs/thesis_reproducibility.md` |
| Suggested figures or tables | Claim-to-evidence table; defense risk register; command reproducibility checklist. |
| Claims allowed | The defense pack supports clear explanation of scope, evidence, and limitations. |
| Claims to avoid | Do not introduce new claims not supported by repository artifacts. |

## Suggested Figures and Tables

| Figure or table | Source material | Purpose |
| --- | --- | --- |
| Architecture diagram | `README.md`, `docs/thesis_claim_evidence_map.md` | Show modular responsibilities and data flow. |
| Risk scoring signal table | `docs/scoring_model.md`, `reports/thesis/scoring_distribution.csv` | Explain normalized signals and heuristic weights. |
| Claim-to-evidence table | `docs/thesis_claim_evidence_map.md` | Tie thesis claims to files and artifacts. |
| Baseline comparison table | `reports/thesis/benchmark_summary.md` | Present controlled fixture ranking comparison. |
| Ablation table | `reports/thesis/ablation_summary.md` | Show signal-removal behavior and unsupported variants. |
| Sensitivity summary table | `reports/thesis/scoring_sensitivity.md` | Show bounded robustness probe results. |
| Explanation trace example | `reports/thesis/risk_explanation_traces.md` | Demonstrate end-to-end explainability for one CVE. |
| Limitations table | `docs/thesis_limitations.md`, `reports/thesis/limitations_and_validity.md` | State claim boundaries and threats to validity. |

## Recommended Writing Order

1. Methodology
2. Evaluation
3. Results
4. Limitations
5. Architecture
6. Introduction
7. Related Work
8. Conclusion

This order reduces rework because the methodology, evaluation protocol, generated results, and limitations define the defensible claim boundary. Architecture, introduction, related work, and conclusion can then be written around evidence that is already fixed and validated.

For a defense or portfolio walkthrough, run `make thesis-demo` and open `reports/thesis/demo_walkthrough.md` first.

## Final Defense Checklist

- No overclaiming autonomy.
- No production-readiness claim.
- No statistical significance claim.
- No real-world validation claim.
- No optimized-weight claim.
- Dread is framed as bounded weak evidence.
- The fixture is framed as controlled behavioral validation.
- Artifact commands are reproducible.
- Tests and quality gate pass.
