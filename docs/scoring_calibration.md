# Scoring Calibration Guardrails

The signal-based scoring model combines normalized severity, exploit likelihood, active exploitation evidence, recency, accepted correlation support, graph context, and intrinsic CVE context. Calibration guardrails are needed because a formula can be deterministic and still produce distorted score distributions.

## What The Fixture Validates

The controlled thesis fixture validates that:

- high CVSS with weak external evidence remains meaningful risk
- high CVSS with weak confidence is not automatically CRITICAL
- medium CVSS with high EPSS and CISA KEV can outrank high-CVSS controls
- KEV-listed records generally rank better than comparable non-KEV records
- accepted URLhaus correlation improves priority relative to weak or rejected correlation cases
- Dread-only manual-review cases do not produce high confidence
- final scores remain in `[0, 10]`
- confidence remains in `[0, 1]`
- risk and confidence remain separate concepts
- LOW, MEDIUM, HIGH, and CRITICAL buckets are represented

These checks support thesis evaluation by making the model behavior auditable and reproducible. They are regression guardrails, not a fitted calibration procedure.

## What It Does Not Validate

The deterministic fixture is not a live threat-intelligence benchmark. It does not estimate real-world prevalence, incident likelihood, statistical significance, or operational utility across all environments.

Real-world validation should use larger NVD, EPSS, and CISA KEV exports, plus organization-specific asset context where operational risk is being evaluated [CVSS-FIRST] [EPSS-FIRST] [CISA-KEV] [CISA-SSVC].

## Interpretation Notes

High risk with low confidence means the item may be urgent based on severity or exploitability signals, but the supporting evidence is incomplete or weak.

Medium CVSS with high EPSS and KEV can rank above a high-CVSS control because EPSS represents exploit likelihood and KEV represents observed active exploitation evidence. This keeps CVSS as severity rather than treating it as complete risk.

Dread is treated as optional experimental intelligence. Dread-only or manual-review evidence should not create high confidence unless corroborated by stronger evidence.
