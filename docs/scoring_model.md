# Scoring Model

The CVE score is an operational prioritization score, not a claim that the vulnerability is exploited in the local environment. CVSS is treated as technical severity because it describes intrinsic vulnerability characteristics, while operational risk also depends on exploit likelihood, active exploitation evidence, recency, correlation support, graph context, and asset context [CVSS-FIRST] [CISA-SSVC].

## Risk Versus Confidence

`risk_score` answers: how urgently should this item be prioritized?

`confidence` answers: how reliable is the supporting evidence?

Missing EPSS, KEV, URLhaus, or Dread evidence should not erase high technical severity. It should mainly reduce confidence. A high-CVSS CVE with no external evidence can remain high risk with moderate confidence.

## Normalized Signals

All signal values are bounded in `[0, 1]`.

| Signal | Meaning | Normalization |
| --- | --- | --- |
| `severity_signal` | CVSS technical severity | `clamp(CVSS, 0, 10) / 10` |
| `epss_signal` | FIRST EPSS exploit probability | EPSS probability clamped to `[0, 1]` |
| `kev_signal` | CISA KEV active exploitation listing | `1` when listed, `0` otherwise; unknown is tracked separately |
| `recency_signal` | bounded publication recency | monotonic time-decay buckets |
| `correlation_signal` | accepted CVE-IOC evidence | accepted URLhaus/Dread support normalized by cap |
| `graph_signal` | graph centrality/context | graph centrality clamped to `[0, 1]` |
| `nlp_context_signal` | intrinsic CVE context | capped NLP context score |

## Canonical Formula

The canonical CVE signal weights are defined in `agent-python/src/analysis/scoring_signals.py` as `DEFAULT_RISK_SIGNAL_WEIGHTS`. The CVE scorer, thesis fixture generation, thesis artifacts, and formula-consistency tests all use that source of truth.

| Signal | Weight | Rationale |
| --- | ---: | --- |
| `severity_signal` | `0.68` | CVSS severity remains the dominant intrinsic technical signal. |
| `epss_signal` | `0.12` | EPSS contributes exploit likelihood without replacing severity. |
| `kev_signal` | `0.12` | CISA KEV contributes active exploitation evidence when listed. |
| `recency_signal` | `0.05` | Recent publication/modification modestly increases operational urgency. |
| `correlation_signal` | `0.12` | Accepted CVE-IOC evidence adds support only after evidence gating. |
| `graph_signal` | `0.03` | Graph context provides a bounded contextual adjustment. |
| `nlp_context_signal` | `0.06` | Intrinsic CVE context contributes a bounded domain-context signal. |

Default signal scoring:

```text
weighted_signal_score =
  severity_signal * 0.68
+ epss_signal * 0.12
+ kev_signal * 0.12
+ recency_signal * 0.05
+ correlation_signal * 0.12
+ graph_signal * 0.03
+ nlp_context_signal * 0.06

risk_raw = weighted_signal_score * 10
risk_score = clamp(risk_raw, 0, 10)
```

The weights are heuristic engineering choices, not learned parameters and not statistical calibration. Their purpose is to encode the thesis model's intended risk semantics: CVSS supplies severity, EPSS supplies likelihood, KEV supplies active exploitation evidence, and accepted correlation/graph/context signals refine operational prioritization.

## Contribution Breakdown

Each scored CVE exposes `risk_signal_contributions`, where each entry is the normalized signal multiplied by its canonical weight before scaling to `[0, 10]`. The sum is exported as `weighted_signal_score`; `risk_raw` is the scaled value before the final `[0, 10]` clamp; `risk_score_from_signals` and `final_score` are the bounded final model score.

The deterministic thesis fixture uses the same helper as the scorer to derive `risk_score_from_signals`, `final_score`, and `model_risk_score`. Fixture records define normalized signal inputs rather than independently assigning final model scores, so thesis artifacts cannot silently drift away from the implemented formula.

EPSS is exploit likelihood, not impact [EPSS-FIRST]. KEV is active exploitation evidence, not a complete list of all exploited CVEs [CISA-KEV]. KEV absence therefore means "not listed in KEV", not "not exploited".

## Asset-Aware Operational Risk

Generic CVE risk and asset-aware operational risk are separate outputs. The generic CVE score describes prioritization before organization-specific context is applied. Asset-aware operational risk starts from that generic score and applies deterministic, bounded adjustments for:

- product applicability against the asset inventory
- asset criticality
- network exposure
- patch state
- active compensating controls

If a vulnerable product is not applicable to an asset, operational risk is treated as non-actionable and is set to zero. If applicability is uncertain, the score and confidence are capped. Public-facing critical assets can increase operational urgency, while patched assets and active compensating controls reduce it. The final operational score remains bounded in `[0, 10]`.

Operational-risk exports preserve both values: `source_risk_score` / `generic_cve_risk_score` for the generic CVE score and `final_operational_risk_score` / `operational_risk_score` for the asset-aware score. The component breakdown includes applicability, match reasons, criticality, exposure, patch-state, compensating-control factors, and `operational_risk_delta`.

## Confidence Components

Confidence is component-level and auditable. It includes metadata quality, CVSS availability/version, description quality, entity extraction, accepted external evidence, source reliability, evidence freshness, correlation quality, and penalties for weak descriptions, missing CVSS, stale metadata, rejected correlations, and unavailable external signals.

Dread-only evidence is capped unless corroborated by stronger evidence because dark-web posts are difficult to reproduce, verify, and attribute.
