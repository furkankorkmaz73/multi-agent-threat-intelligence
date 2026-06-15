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

Default signal scoring:

```text
risk_raw =
  severity_signal * 0.68
+ epss_signal * 0.12
+ kev_signal * 0.12
+ recency_signal * 0.05
+ correlation_signal * 0.12
+ graph_signal * 0.03
+ nlp_context_signal * 0.06

risk_score = clamp(risk_raw * 10, 0, 10)
```

EPSS is exploit likelihood, not impact [EPSS-FIRST]. KEV is active exploitation evidence, not a complete list of all exploited CVEs [CISA-KEV]. KEV absence therefore means "not listed in KEV", not "not exploited".

## Confidence Components

Confidence is component-level and auditable. It includes metadata quality, CVSS availability/version, description quality, entity extraction, accepted external evidence, source reliability, evidence freshness, correlation quality, and penalties for weak descriptions, missing CVSS, stale metadata, rejected correlations, and unavailable external signals.

Dread-only evidence is capped unless corroborated by stronger evidence because dark-web posts are difficult to reproduce, verify, and attribute.
