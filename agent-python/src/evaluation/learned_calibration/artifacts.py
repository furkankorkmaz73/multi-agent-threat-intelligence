from __future__ import annotations

import argparse
import csv
import json
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil, floor, log2
from pathlib import Path
from random import Random
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping, Sequence

import pymongo
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from config import DB_NAME, MONGO_URI, get_settings

SETTINGS = get_settings()

def _learned_calibration_artifact_specs() -> list[dict[str, str]]:
    return [
        {"group": "dataset", "filename": "learned_calibration_dataset.csv", "description": "Flat feature export", "usage": "Feature matrix for learned-calibration feasibility discussion."},
        {"group": "labels", "filename": "learned_calibration_labels.csv", "description": "Proxy-label export", "usage": "Documents deterministic proxy labels and limitations."},
        {"group": "baseline metrics", "filename": "learned_calibration_baseline_metrics.json", "description": "Heuristic baseline metrics", "usage": "Compares risk_score ranking with proxy labels."},
        {"group": "baseline metrics", "filename": "learned_calibration_baseline_metrics.md", "description": "Readable heuristic baseline metrics", "usage": "Thesis table source for baseline behavior."},
        {"group": "model report", "filename": "learned_calibration_model_report.json", "description": "Optional model report", "usage": "Records trained/skipped model status and metrics."},
        {"group": "model report", "filename": "learned_calibration_model_summary.md", "description": "Readable model summary", "usage": "Concise thesis summary of model availability."},
        {"group": "predictions", "filename": "learned_calibration_predictions.csv", "description": "Optional learned predictions", "usage": "Input to ranking comparisons when a model is trained."},
        {"group": "comparison report", "filename": "learned_vs_heuristic_comparison.json", "description": "Learned vs heuristic comparison", "usage": "Compares learned and heuristic ranking when predictions exist."},
        {"group": "comparison report", "filename": "learned_vs_heuristic_comparison.md", "description": "Readable learned-vs-heuristic comparison", "usage": "Thesis narrative support for ranking agreement/disagreement."},
        {"group": "disagreements", "filename": "learned_calibration_disagreements.csv", "description": "Disagreement cases", "usage": "Case examples when learned predictions exist."},
        {"group": "disagreements", "filename": "learned_calibration_disagreements.md", "description": "Readable disagreement summary", "usage": "Thesis discussion of disagreement categories."},
        {"group": "feature importance", "filename": "learned_calibration_feature_importance.csv", "description": "Coefficient/importance export", "usage": "Interpretability support when coefficients exist."},
        {"group": "feature importance", "filename": "learned_calibration_feature_importance.md", "description": "Readable feature importance", "usage": "Thesis discussion of feature dominance."},
        {"group": "ablation", "filename": "learned_calibration_ablation.csv", "description": "Ablation rows", "usage": "Feature-removal experiment plan/results."},
        {"group": "ablation", "filename": "learned_calibration_ablation.md", "description": "Readable ablation summary", "usage": "Thesis-ready ablation table."},
        {"group": "leakage checks", "filename": "learned_calibration_leakage_checks.json", "description": "Leakage and robustness checks", "usage": "Evidence that learned artifacts do not change production behavior."},
        {"group": "leakage checks", "filename": "learned_calibration_leakage_checks.md", "description": "Readable leakage checks", "usage": "Appendix-quality leakage/robustness summary."},
        {"group": "thesis narrative", "filename": "learned_calibration_thesis_section.md", "description": "Thesis section draft", "usage": "Academic prose for learned-calibration discussion."},
        {"group": "thesis narrative", "filename": "learned_calibration_limitations.md", "description": "Limitations summary", "usage": "Conservative claims and limitations wording."},
        {"group": "tables", "filename": "learned_calibration_tables.json", "description": "Publication table payloads", "usage": "Machine-readable table source."},
        {"group": "tables", "filename": "learned_calibration_tables.md", "description": "Publication table markdown", "usage": "Thesis-ready compact tables."},
        {"group": "case studies", "filename": "learned_calibration_case_studies.csv", "description": "Case-study rows", "usage": "Selected examples for thesis discussion."},
        {"group": "case studies", "filename": "learned_calibration_case_studies.md", "description": "Case-study summary", "usage": "Readable summary of selected case groups."},
        {"group": "proxy sensitivity", "filename": "learned_calibration_proxy_sensitivity.csv", "description": "Proxy threshold grid rows", "usage": "Sensitivity of proxy labels to threshold choices."},
        {"group": "proxy sensitivity", "filename": "learned_calibration_proxy_sensitivity.json", "description": "Proxy threshold grid payload", "usage": "Machine-readable proxy threshold sensitivity analysis."},
        {"group": "proxy sensitivity", "filename": "learned_calibration_proxy_sensitivity.md", "description": "Readable proxy sensitivity summary", "usage": "Thesis discussion of proxy threshold robustness."},
        {"group": "bootstrap stability", "filename": "learned_calibration_bootstrap_stability.csv", "description": "Bootstrap ranking stability iterations", "usage": "Deterministic resampling check for heuristic ranking stability."},
        {"group": "bootstrap stability", "filename": "learned_calibration_bootstrap_stability.json", "description": "Bootstrap ranking stability payload", "usage": "Machine-readable bootstrap summary and iteration rows."},
        {"group": "bootstrap stability", "filename": "learned_calibration_bootstrap_stability.md", "description": "Readable bootstrap stability summary", "usage": "Thesis discussion of ranking robustness under resampling."},
        {"group": "coverage strata", "filename": "learned_calibration_coverage_strata.csv", "description": "Coverage-limitation strata rows", "usage": "Stratifies proxy-label feasibility by evidence and score-context coverage."},
        {"group": "coverage strata", "filename": "learned_calibration_coverage_strata.json", "description": "Coverage-limitation strata payload", "usage": "Machine-readable coverage strata analysis."},
        {"group": "coverage strata", "filename": "learned_calibration_coverage_strata.md", "description": "Readable coverage-limitation strata summary", "usage": "Thesis discussion of data coverage effects."},
        {"group": "negative controls", "filename": "learned_calibration_negative_controls.json", "description": "Negative-control ranking comparisons", "usage": "Compares heuristic ranking with random, reverse, and single-feature controls."},
        {"group": "negative controls", "filename": "learned_calibration_negative_controls.md", "description": "Readable negative-control summary", "usage": "Thesis sanity check for proxy-label ranking metrics."},
        {"group": "consistency audit", "filename": "learned_calibration_consistency_audit.json", "description": "Cross-artifact consistency checks", "usage": "Machine-readable artifact integrity audit."},
        {"group": "consistency audit", "filename": "learned_calibration_consistency_audit.md", "description": "Readable cross-artifact consistency checks", "usage": "Appendix-quality artifact integrity summary."},
        {"group": "appendix", "filename": "learned_calibration_appendix.md", "description": "Long-form learned-calibration appendix draft", "usage": "Thesis appendix draft assembled from generated artifact values."},
        {"group": "runtime snapshot", "filename": "learned_calibration_runtime_snapshot.json", "description": "Local learned-calibration artifact health snapshot", "usage": "Records git metadata, artifact presence, row counts, statuses, and warnings."},
        {"group": "runtime snapshot", "filename": "learned_calibration_runtime_snapshot.md", "description": "Readable runtime artifact health snapshot", "usage": "Quick review of generated artifact health before thesis use."},
        {"group": "reviewer checklist", "filename": "learned_calibration_reviewer_checklist.json", "description": "Reviewer checklist payload", "usage": "Structured thesis/reviewer checklist for learned calibration."},
        {"group": "reviewer checklist", "filename": "learned_calibration_reviewer_checklist.md", "description": "Readable reviewer checklist", "usage": "Checklist for thesis review and defense preparation."},
        {"group": "defense preparation", "filename": "learned_calibration_defense_qa.md", "description": "Learned-calibration defense Q&A draft", "usage": "Defense-preparation answers for learned calibration and limitations."},
        {"group": "limitations matrix", "filename": "learned_calibration_limitations_matrix.csv", "description": "Structured limitations matrix rows", "usage": "Machine-readable thesis limitations matrix."},
        {"group": "limitations matrix", "filename": "learned_calibration_limitations_matrix.json", "description": "Structured limitations matrix payload", "usage": "JSON thesis limitations matrix."},
        {"group": "limitations matrix", "filename": "learned_calibration_limitations_matrix.md", "description": "Readable limitations matrix", "usage": "Thesis-safe limitations table."},
        {"group": "no-overclaim audit", "filename": "learned_calibration_no_overclaim_audit.json", "description": "No-overclaim audit payload", "usage": "Checks learned-calibration docs and reports for unsafe claims."},
        {"group": "no-overclaim audit", "filename": "learned_calibration_no_overclaim_audit.md", "description": "Readable no-overclaim audit", "usage": "Final thesis claim-safety audit."},
        {"group": "legacy high-risk diagnostics", "filename": "legacy_high_risk_diagnostics.csv", "description": "Legacy high-risk diagnostic rows", "usage": "Diagnostic review of old or intrinsic-severity-driven high-risk CVEs."},
        {"group": "legacy high-risk diagnostics", "filename": "legacy_high_risk_diagnostics.json", "description": "Legacy high-risk diagnostic payload", "usage": "Machine-readable summary of legacy high-risk diagnostic groups."},
        {"group": "legacy high-risk diagnostics", "filename": "legacy_high_risk_diagnostics.md", "description": "Readable legacy high-risk diagnostics", "usage": "Thesis discussion of retained severity versus operational evidence coverage."},
        {"group": "legacy dampening counterfactual", "filename": "legacy_dampening_counterfactual.csv", "description": "Legacy dampening counterfactual rows", "usage": "Diagnostic sensitivity rows for possible future age-aware dampening."},
        {"group": "legacy dampening counterfactual", "filename": "legacy_dampening_counterfactual.json", "description": "Legacy dampening counterfactual payload", "usage": "Machine-readable score and bucket-change summary."},
        {"group": "legacy dampening counterfactual", "filename": "legacy_dampening_counterfactual.md", "description": "Readable legacy dampening counterfactual", "usage": "Thesis discussion of age-aware dampening as future work."},
    ]

__all__ = [name for name in globals() if not name.startswith("__")]
