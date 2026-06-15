# Thesis Limitations

## Scope of Claims

This thesis presents a deterministic cyber threat intelligence risk-analysis prototype. The claims are limited to explainable scoring behavior, confidence separation, evidence gating, bounded sensitivity analysis, asset-aware operational-risk examples, and reproducible thesis artifact generation.

The repository should not be interpreted as a production deployment, a statistically validated field benchmark, or a system that demonstrates broad real-world superiority.

## Multi-Agent Interpretation

The architecture is multi-agent-inspired and agent-supported. It uses modular components with specialist responsibilities for collection, analysis, correlation, scoring, evaluation, and reporting.

It is not a fully autonomous LLM-agent system. Deterministic services perform scoring, confidence estimation, evidence gating, and artifact generation. LLM-assisted components, where present, are not treated as verified evidence.

## Controlled Evaluation Fixture

The thesis evaluation uses a deterministic controlled fixture for behavioral validation. The fixture is designed to exercise ranking behavior, ablation behavior, false-positive resistance, Dread bounds, explanation traces, and asset-aware examples.

The fixture is not a live CTI benchmark. It does not support statistical significance, real-world prevalence, incident-rate, or broad operational-performance claims.

## Scoring Weights and Sensitivity Analysis

The scoring weights are heuristic engineering choices. They encode intended semantics for CVSS severity, EPSS exploit likelihood, CISA KEV active exploitation evidence, recency, accepted correlation support, graph context, and bounded intrinsic context.

The weights are not learned parameters and are not statistically optimized. Sensitivity analysis applies bounded deterministic perturbations to probe robustness of the controlled fixture behavior. It is not calibration.

## Dread and Unreliable Intelligence Handling

Dread is optional, experimental, bounded, default-off, and not treated as ground truth. Live Dread access is not required for tests, demos, benchmark artifacts, or thesis artifact generation.

Dread-only evidence does not imply high confidence or CRITICAL risk by itself. Dread can remain diagnostically useful when routed to manual review or when modestly corroborated by stronger evidence, but it does not override CVSS, EPSS, KEV, or accepted structured evidence.

## Asset-Aware Operational Risk Limitations

Asset-aware operational risk is separate from generic CVE risk. It depends on asset applicability, exposure, criticality, patch state, and compensating controls.

The deterministic examples show how operational context changes prioritization. They do not validate organization-wide risk without high-quality asset inventory, product/version matching, exposure classification, patch-state evidence, and control evidence.

## Graph Context Limitations

Graph context is represented as bounded deterministic context within the thesis fixture. Neo4j or other persistent graph databases are future work and are not part of the current thesis implementation scope.

The current graph signal should be interpreted as local contextual support, not as a complete enterprise graph model.

## Generalization Limits

The deterministic thesis artifacts are suitable for reproducibility and behavioral validation. They do not establish real-world generalization.

Operational validation would require larger curated NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets, along with external validation criteria and repeated evaluation over time.

## Future Work

Future work includes larger longitudinal evaluation, independent external labels, stronger asset inventory integration, persistent graph storage, calibrated organization-specific thresholds, richer provenance review, analyst feedback studies, and deployment hardening.
