# Learned Calibration Feasibility Export

This export is an experimental feasibility check for a possible learned calibration layer. It does not train a model, change production `risk_score`, or change URLhaus/Dread evidence gates.

The command reads existing analyzed CVE records from MongoDB collection `cve_intel` and writes a flat feature dataset plus a small feasibility report under `reports/thesis/`.

```bash
make thesis-learned-calibration
```

The underlying CLI also supports:

```bash
cd agent-python
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m evaluation.learned_calibration \
  --output-dir ../reports/thesis \
  --limit 0 \
  --strict
```

`--limit` can be used for local smoke checks. `--strict` exits non-zero when no usable analyzed CVE rows or no CVSS-bearing rows are exported.

Generated files:

- `reports/thesis/learned_calibration_dataset.csv`
- `reports/thesis/learned_calibration_labels.csv`
- `reports/thesis/learned_calibration_report.json`
- `reports/thesis/learned_calibration_summary.md`
- `reports/thesis/learned_calibration_baseline_metrics.json`
- `reports/thesis/learned_calibration_baseline_metrics.md`
- `reports/thesis/learned_calibration_predictions.csv`
- `reports/thesis/learned_calibration_model_report.json`
- `reports/thesis/learned_calibration_model_summary.md`
- `reports/thesis/learned_vs_heuristic_comparison.json`
- `reports/thesis/learned_vs_heuristic_comparison.md`
- `reports/thesis/learned_calibration_disagreements.csv`
- `reports/thesis/learned_calibration_disagreements.md`
- `reports/thesis/learned_calibration_feature_importance.csv`
- `reports/thesis/learned_calibration_feature_importance.md`

The dataset includes exported scoring signals, confidence fields, URLhaus candidate accounting, accepted evidence counts, EPSS/KEV coverage flags, and intrinsic-criticality floor indicators when available.

The labels CSV adds deterministic proxy labels for later learned-calibration experiments:

- Strategy A combines intrinsic technical severity with known evidence.
- Strategy B prioritizes KEV, high EPSS, and accepted external evidence, and is marked limited when evidence coverage is sparse.
- Strategy C is a conservative high-vs-rest proxy for strongly defensible high cases.

These labels are experimental proxies. They are not ground truth and should not be presented as real-world exploitation outcomes.

The baseline metric artifacts compare the existing heuristic `risk_score` ranking against the proxy labels. They report precision@K, recall@K, nDCG@K, high-label coverage, average risk by proxy class, risk bucket distribution by proxy class, and confidence distribution by proxy class. No-positive and tiny-positive strategies are retained with explicit status fields so sparse-label limitations remain visible.

If scikit-learn is available, the model artifacts train an optional deterministic LogisticRegression experiment with fixed random seed `42`. The experiment uses only underlying signals and confidence/completeness fields; it does not use production `risk_score` or proxy-label fields as model inputs. If scikit-learn is unavailable or a proxy strategy has insufficient class diversity, the artifacts are written with a clear skipped status instead of adding a dependency or fabricating results.

The learned-vs-heuristic comparison artifacts compare experimental learned probability rankings with the existing heuristic `risk_score` ranking when predictions are available. They report top-K overlap, precision/recall by ranking, rank-correlation estimates, and examples where learned or heuristic ordering differs substantially. If no model predictions are available, the comparison is explicitly marked skipped.

The disagreement artifacts extract thesis-useful examples such as heuristic-high/learned-low, learned-high/heuristic-medium, CVSS-critical cases with lower learned probability, intrinsic-floor disagreements, low-confidence/high-probability cases, and high-risk records with missing accepted external evidence. If learned predictions are unavailable, the CSV is header-only and the Markdown summary explains that no disagreement cases were exported.

The feature-importance artifacts export LogisticRegression coefficients when a strategy is trained. Coefficients are ranked by absolute magnitude, include sign interpretation, include feature coverage notes, and flag cases where CVSS/severity dominates the top coefficients. If no model is trained, the artifact is explicitly skipped.

Rows are sorted deterministically by CVE identifier. The exporter accepts the current `analysis.*` shape and legacy top-level evidence, feature, and confidence structures so older analyzed records can be inspected without rewriting database contents.

The JSON report includes both legacy top-level counts and structured sections for coverage, evidence counts, dataset columns, and missing-feature accounting. Missing EPSS/KEV or accepted external evidence should be interpreted as coverage limitations, not as proof that learned calibration is valid or invalid by itself.

## Interpretation

The export is only a feasibility artifact. Proxy labels are not ground truth, Dread live crawling is not used, and confidence remains separate from risk. A future learned calibration layer would require defensible labels, stronger EPSS/KEV coverage, careful train/test separation, and validation that it does not weaken deterministic evidence gates.
