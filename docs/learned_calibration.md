# Learned Calibration Feasibility Export

This export is an experimental feasibility check for a possible learned calibration layer. It does not change production `risk_score`, confidence, or URLhaus/Dread evidence gates. When scikit-learn and sufficient proxy-label diversity are available, it may train optional deterministic diagnostic models for thesis discussion only.

Optional learned models are diagnostic only. They do not replace the heuristic scorer, they are not written back to MongoDB, and proxy labels are not ground truth. Skipped model training is an expected outcome when labels are not trainable or scikit-learn is unavailable.

Default `make test-python` does not require scikit-learn. Optional learned-calibration ML tests require `SKLEARN_OPTIONAL_TESTS=1` and scikit-learn installed, and can be run with:

```bash
make test-python-optional-ml
```

The command reads existing analyzed CVE records from MongoDB collection `cve_intel` and writes a flat feature dataset plus a small feasibility report under `reports/thesis/learned_calibration/`.

```bash
make thesis-learned-calibration
make thesis-learned-calibration-quality
```

The underlying CLI also supports:

```bash
cd agent-python
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src .venv/bin/python -m evaluation.learned_calibration \
  --output-dir ../reports/thesis/learned_calibration \
  --limit 0 \
  --strict
```

`--limit` can be used for local smoke checks. `--strict` exits non-zero when no usable analyzed CVE rows or no CVSS-bearing rows are exported.

Generated files:

- `reports/thesis/learned_calibration/learned_calibration_dataset.csv`
- `reports/thesis/learned_calibration/learned_calibration_labels.csv`
- `reports/thesis/learned_calibration/learned_calibration_report.json`
- `reports/thesis/learned_calibration/learned_calibration_summary.md`
- `reports/thesis/learned_calibration/learned_calibration_baseline_metrics.json`
- `reports/thesis/learned_calibration/learned_calibration_baseline_metrics.md`
- `reports/thesis/learned_calibration/learned_calibration_predictions.csv`
- `reports/thesis/learned_calibration/learned_calibration_model_report.json`
- `reports/thesis/learned_calibration/learned_calibration_model_summary.md`
- `reports/thesis/learned_calibration/learned_vs_heuristic_comparison.json`
- `reports/thesis/learned_calibration/learned_vs_heuristic_comparison.md`
- `reports/thesis/learned_calibration/learned_calibration_disagreements.csv`
- `reports/thesis/learned_calibration/learned_calibration_disagreements.md`
- `reports/thesis/learned_calibration/learned_calibration_feature_importance.csv`
- `reports/thesis/learned_calibration/learned_calibration_feature_importance.md`
- `reports/thesis/learned_calibration/learned_calibration_ablation.csv`
- `reports/thesis/learned_calibration/learned_calibration_ablation.md`
- `reports/thesis/learned_calibration/learned_calibration_leakage_checks.json`
- `reports/thesis/learned_calibration/learned_calibration_leakage_checks.md`
- `reports/thesis/learned_calibration/learned_calibration_thesis_section.md`
- `reports/thesis/learned_calibration/learned_calibration_limitations.md`
- `reports/thesis/learned_calibration/learned_calibration_case_studies.csv`
- `reports/thesis/learned_calibration/learned_calibration_case_studies.md`
- `reports/thesis/learned_calibration/learned_calibration_tables.json`
- `reports/thesis/learned_calibration/learned_calibration_tables.md`
- `reports/thesis/learned_calibration/learned_calibration_manifest.json`
- `reports/thesis/learned_calibration/learned_calibration_manifest.md`
- `reports/thesis/learned_calibration/learned_calibration_proxy_sensitivity.csv`
- `reports/thesis/learned_calibration/learned_calibration_proxy_sensitivity.json`
- `reports/thesis/learned_calibration/learned_calibration_proxy_sensitivity.md`
- `reports/thesis/learned_calibration/learned_calibration_bootstrap_stability.csv`
- `reports/thesis/learned_calibration/learned_calibration_bootstrap_stability.json`
- `reports/thesis/learned_calibration/learned_calibration_bootstrap_stability.md`
- `reports/thesis/learned_calibration/learned_calibration_coverage_strata.csv`
- `reports/thesis/learned_calibration/learned_calibration_coverage_strata.json`
- `reports/thesis/learned_calibration/learned_calibration_coverage_strata.md`
- `reports/thesis/learned_calibration/learned_calibration_negative_controls.json`
- `reports/thesis/learned_calibration/learned_calibration_negative_controls.md`
- `reports/thesis/learned_calibration/learned_calibration_consistency_audit.json`
- `reports/thesis/learned_calibration/learned_calibration_consistency_audit.md`
- `reports/thesis/learned_calibration/learned_calibration_appendix.md`
- `reports/thesis/learned_calibration/learned_calibration_runtime_snapshot.json`
- `reports/thesis/learned_calibration/learned_calibration_runtime_snapshot.md`
- `reports/thesis/learned_calibration/learned_calibration_reviewer_checklist.json`
- `reports/thesis/learned_calibration/learned_calibration_reviewer_checklist.md`
- `reports/thesis/learned_calibration/learned_calibration_defense_qa.md`
- `reports/thesis/learned_calibration/learned_calibration_limitations_matrix.csv`
- `reports/thesis/learned_calibration/learned_calibration_limitations_matrix.json`
- `reports/thesis/learned_calibration/learned_calibration_limitations_matrix.md`
- `reports/thesis/learned_calibration/learned_calibration_no_overclaim_audit.json`
- `reports/thesis/learned_calibration/learned_calibration_no_overclaim_audit.md`
- `reports/thesis/learned_calibration/legacy_high_risk_diagnostics.csv`
- `reports/thesis/learned_calibration/legacy_high_risk_diagnostics.json`
- `reports/thesis/learned_calibration/legacy_high_risk_diagnostics.md`
- `reports/thesis/learned_calibration/legacy_dampening_counterfactual.csv`
- `reports/thesis/learned_calibration/legacy_dampening_counterfactual.json`
- `reports/thesis/learned_calibration/legacy_dampening_counterfactual.md`
- `reports/thesis/learned_calibration/learned_calibration_quality_report.json`
- `reports/thesis/learned_calibration/learned_calibration_quality_report.md`

The dataset includes exported scoring signals, confidence fields, URLhaus candidate accounting, accepted evidence counts, EPSS/KEV coverage flags, and intrinsic-criticality floor indicators when available.

The labels CSV adds deterministic proxy labels for later learned-calibration experiments:

- Strategy A combines intrinsic technical severity with known evidence.
- Strategy B prioritizes KEV, high EPSS, and accepted external evidence, and is marked limited when evidence coverage is sparse.
- Strategy C is a conservative high-vs-rest proxy for strongly defensible high cases.

These labels are experimental proxies. They are not ground truth and should not be presented as real-world exploitation outcomes.

The baseline metric artifacts compare the existing heuristic `risk_score` ranking against the proxy labels. They report precision@K, recall@K, nDCG@K, high-label coverage, average risk by proxy class, risk bucket distribution by proxy class, and confidence distribution by proxy class. No-positive and tiny-positive strategies are retained with explicit status fields so sparse-label limitations remain visible.

If scikit-learn is available, the model artifacts train an optional deterministic LogisticRegression experiment with fixed random seed `42`. The report can also include lightweight comparison models when available: RandomForestClassifier, HistGradientBoostingClassifier, and a DummyClassifier baseline. The experiment uses only underlying signals and confidence/completeness fields; it does not use production `risk_score` or proxy-label fields as model inputs. If scikit-learn is unavailable or a proxy strategy has insufficient class diversity, the artifacts are written with a clear skipped status instead of adding a dependency or fabricating results.

The learned-vs-heuristic comparison artifacts compare experimental learned probability rankings with the existing heuristic `risk_score` ranking when predictions are available. They report top-K overlap, precision/recall by ranking, rank-correlation estimates, and examples where learned or heuristic ordering differs substantially. If no model predictions are available, the comparison is explicitly marked skipped.

The disagreement artifacts extract thesis-useful examples such as heuristic-high/learned-low, learned-high/heuristic-medium, CVSS-critical cases with lower learned probability, intrinsic-floor disagreements, low-confidence/high-probability cases, and high-risk records with missing accepted external evidence. If learned predictions are unavailable, the CSV is header-only and the Markdown summary explains that no disagreement cases were exported.

The feature-importance artifacts export LogisticRegression coefficients when a strategy is trained. Coefficients are ranked by absolute magnitude, include sign interpretation, include feature coverage notes, and flag cases where CVSS/severity dominates the top coefficients. If no model is trained, the artifact is explicitly skipped.

The ablation artifacts define deterministic feature-removal views such as no CVSS/severity, no recency, no NLP context, no confidence/data completeness, evidence-only, signals-only, and metadata/context-only. If model training is unavailable or labels are untrainable, ablation rows are written with skipped status and an explicit reason.

The leakage-check artifacts document that production `risk_score` is not used as a model feature, proxy-label fields are excluded from model inputs, learned outputs are not written back to MongoDB, Dread live crawling is not used, URLhaus/Dread gates are unchanged, and confidence is not recalibrated by the learned model.

The thesis-section and limitations artifacts provide concise academic prose that can be adapted into the thesis. They emphasize that proxy labels are not ground truth, the experiment is diagnostic thesis material, and the production heuristic risk score remains unchanged and explainable.

The case-study artifacts select thesis-useful examples for discussing high heuristic risk, learned-probability disagreements, intrinsic criticality, missing EPSS/KEV coverage, URLhaus ignored/rejected volume, and low-confidence/high-risk records. They illustrate proxy behavior and do not claim ground truth exploitation.

The publication-table artifacts collect compact thesis-ready tables for dataset coverage, proxy-label distribution, heuristic baseline metrics, optional learned-model metrics, ablation status, leakage checks, and artifact inventory. Tables are generated from artifact payloads and include unavailable/skipped rows rather than hand-written numbers.

The manifest artifacts list each learned-calibration output with file path, existence status, byte size, producer module, description, and thesis usage note.

The proxy-sensitivity artifacts evaluate deterministic threshold combinations for EPSS, CVSS, NLP context, and recency. They report label counts, high-label percentage, heuristic precision@K, stability versus default Strategy A, and whether a threshold configuration is too broad, too narrow, or usable. The analysis does not change default proxy labels or production scoring.

The bootstrap-stability artifacts run a fixed-seed deterministic bootstrap over exported CVE rows. Each iteration resamples rows with replacement, evaluates the unchanged heuristic `risk_score` ranking against Strategy A proxy labels, and records precision@10/50/100, recall@50/100, and top-50/top-100 overlap with the full-data ranking. The summary reports mean, standard deviation, min, max, and 5th/95th percentiles. This is a ranking robustness probe, not statistical calibration or evidence of real-world generalization.

The coverage-strata artifacts group exported CVE rows by EPSS availability, KEV status, KEV listing, accepted external evidence, intrinsic-floor application, confidence bucket, risk bucket, ignored URLhaus candidate bucket, and rejected URLhaus candidate bucket. Each row reports count, average risk, average confidence, proxy high counts, missing feature percentages, and an interpretation note. This helps explain where learned-calibration feasibility is limited by evidence coverage rather than by ranking mechanics.

The negative-control artifacts compare the unchanged heuristic `risk_score` ranking with fixed-seed random ranking, reverse risk ranking, CVSS-only ranking, recency-only ranking, NLP-context-only ranking, and confidence-only ranking. They report precision@10/50/100, recall@50/100, and top-K overlap with the heuristic ranking. The interpretation explicitly notes when CVSS-only is close to the heuristic because Strategy A is partly intrinsic-severity driven.

The consistency-audit artifacts check that dataset and label row counts align, CVE identifiers are unique and matched, prediction identifiers are within the dataset, JSON artifacts parse, CSV headers are not duplicated, Markdown summaries retain limitation language, model skip status is consistent with the local scikit-learn environment, and no learned-calibration artifact claims ground-truth exploitation prediction.

The appendix artifact is a long-form English draft assembled from generated artifact values. It covers purpose, dataset construction, feature schema, proxy-label design, coverage limits, baseline metrics, model status, sensitivity, bootstrap stability, coverage strata, negative controls, case studies, leakage checks, heuristic-score rationale, threats to validity, and future work.

The runtime-snapshot artifacts summarize local learned-calibration artifact health from files and git metadata. They record the current branch and HEAD, core artifact presence, key CSV row counts, JSON status values, model-training status, scikit-learn availability, known validation commands, and warnings for missing or empty optional artifacts.

The reviewer-checklist artifacts provide structured thesis review items across reproducibility, artifacts, proxy-label validity, leakage, model training, ranking metrics, limitations, no-overclaim checks, defense readiness, and manual author review. Each item records a status, evidence artifact, and reviewer note.

The defense Q&A artifact provides concise academic answers for common thesis-defense questions about proxy labels, heuristic scoring, skipped model training, URLhaus/Dread limitations, confidence-vs-risk separation, sensitivity, bootstrap stability, negative controls, and safe thesis claims.

The limitations-matrix artifacts consolidate thesis-safe limitations into structured CSV, JSON, and Markdown forms. They map each limitation to interpretive impact, implemented mitigation, future work, and wording that can be reused in thesis text.

The no-overclaim audit artifacts scan learned-calibration docs and generated reports for unsafe claims such as ground-truth prediction, production readiness, autonomous-agent claims, optimal weights, or learned-model replacement of heuristic scoring. Explicitly negated or limitation-framed wording is allowed.

The legacy high-risk diagnostic artifacts separate modern intrinsic criticality floor cases from old high-CVSS retained-severity cases and high-risk records with no accepted external evidence. These diagnostics are not a production scoring change. Preserving old CVSS 10 severity can be defensible for intrinsic technical severity, but lack of EPSS, KEV, or accepted external evidence limits operational interpretation.

The legacy dampening counterfactual artifacts evaluate an illustrative age-aware dampening rule for future work. They do not change production `risk_score`, confidence, or evidence gates. Any future age-aware dampening should be evaluated only with stronger labels, asset context, and explicit review of operational impact.

The quality report artifacts are produced by `make thesis-learned-calibration-quality`. The gate checks required learned-calibration files, JSON parseability, CSV headers, limitation language, experimental framing, unchanged production risk score wording, unchanged evidence-gate wording, and absence of real-world exploitation-proof claims.

Rows are sorted deterministically by CVE identifier. The exporter accepts the current `analysis.*` shape and legacy top-level evidence, feature, and confidence structures so older analyzed records can be inspected without rewriting database contents.

The JSON report includes both legacy top-level counts and structured sections for coverage, evidence counts, dataset columns, and missing-feature accounting. Missing EPSS/KEV or accepted external evidence should be interpreted as coverage limitations, not as proof that learned calibration is valid or invalid by itself.

## Maintainability Future Work

The learned-calibration evaluation module is intentionally kept as a single artifact-generation module for thesis freeze stability. A future engineering refactor could split dataset extraction, proxy labels, feature construction, model diagnostics, leakage checks, reporting, and CLI orchestration into separate modules.

## Interpretation

The export is only a feasibility artifact. Proxy labels are not ground truth, Dread live crawling is not used, and confidence remains separate from risk. A future learned calibration layer would require defensible labels, stronger EPSS/KEV coverage, careful train/test separation, and validation that it does not weaken deterministic evidence gates.
