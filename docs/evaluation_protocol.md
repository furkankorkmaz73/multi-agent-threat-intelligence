# Evaluation Protocol

Evaluation uses deterministic model exports joined with optional local EPSS and CISA KEV files. Tests and thesis artifacts do not require network access.

The built-in thesis fixture is a controlled evaluation set, not a live threat-intelligence benchmark. It is designed to validate ranking behavior, ablation behavior, correlation-decision exports, and artifact generation with reproducible inputs. Real-world validation should use larger NVD, EPSS, and CISA KEV exports.

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

## Thesis Artifacts

Run:

```bash
make thesis-artifacts
```

The command runs the deterministic thesis fixture scenario and writes:

```text
agent-python/reports/thesis/
  scoring_summary.md
  benchmark_summary.csv
  benchmark_summary.md
  ablation_summary.csv
  ablation_summary.md
  correlation_decisions.csv
  case_studies.json
  methodology_summary.md
  manifest.json
```

The artifact bundle is intended for thesis tables and appendix material. It is not a claim of statistical significance or field prevalence.
