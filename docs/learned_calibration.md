# Learned Calibration Feasibility Export

This export is an experimental feasibility check for a possible learned calibration layer. It does not train a model, change production `risk_score`, or change URLhaus/Dread evidence gates.

The command reads existing analyzed CVE records from MongoDB collection `cve_intel` and writes a flat feature dataset plus a small feasibility report under `reports/thesis/`.

```bash
make thesis-learned-calibration
```

Generated files:

- `reports/thesis/learned_calibration_dataset.csv`
- `reports/thesis/learned_calibration_report.json`
- `reports/thesis/learned_calibration_summary.md`

The dataset includes exported scoring signals, confidence fields, URLhaus candidate accounting, accepted evidence counts, EPSS/KEV coverage flags, and intrinsic-criticality floor indicators when available.

## Interpretation

The export is only a feasibility artifact. Proxy labels are not ground truth, Dread live crawling is not used, and confidence remains separate from risk. A future learned calibration layer would require defensible labels, stronger EPSS/KEV coverage, careful train/test separation, and validation that it does not weaken deterministic evidence gates.
