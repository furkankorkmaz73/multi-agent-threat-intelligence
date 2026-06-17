from __future__ import annotations

from .constants import *
from .data import (
    build_feasibility_report,
    build_proxy_label_row,
    build_proxy_label_rows,
    extract_calibration_row,
    read_analyzed_cves_from_mongo,
    strict_validation_errors,
    summarize_proxy_labels,
)
from .metrics import (
    ablation_plan,
    bootstrap_sample_indices,
    build_leakage_checks,
    build_negative_control_rankings,
    compute_ablation_experiments,
    compute_baseline_metrics,
    compute_bootstrap_stability,
    compute_coverage_strata,
    compute_disagreement_cases,
    compute_learned_vs_heuristic_comparison,
    compute_negative_controls,
    compute_proxy_threshold_sensitivity,
    extract_feature_importance,
    proxy_threshold_grid,
    render_coverage_strata_markdown,
    render_negative_controls_markdown,
    summarize_bootstrap_metrics,
)
from .reports import (
    build_learned_calibration_manifest,
    build_legacy_dampening_counterfactual,
    build_legacy_high_risk_diagnostics,
    build_publication_tables,
    export_from_documents,
    extract_cve_year,
    render_legacy_dampening_counterfactual_markdown,
    render_legacy_high_risk_diagnostics_markdown,
    select_case_studies,
    write_outputs,
)
from .snapshots import (
    _current_git_metadata,
    build_consistency_audit,
    build_limitations_matrix,
    build_no_overclaim_audit,
    build_reviewer_checklist,
    build_runtime_snapshot,
    render_consistency_audit_markdown,
    render_limitations_matrix_markdown,
    render_no_overclaim_audit_markdown,
    render_reviewer_checklist_markdown,
    render_runtime_snapshot_markdown,
)
from .training import model_registry, train_learned_calibration_models
from .optional_dependencies import _load_sklearn
from .cli import main
from .data import pymongo

# Re-export markdown helpers used by downstream scripts/tests.
from .metrics import (
    render_ablation_markdown,
    render_baseline_metrics_markdown,
    render_bootstrap_stability_markdown,
    render_disagreements_markdown,
    render_feature_importance_markdown,
    render_leakage_checks_markdown,
    render_learned_vs_heuristic_markdown,
    render_proxy_sensitivity_markdown,
)
from .reports import (
    render_case_studies_markdown,
    render_learned_calibration_appendix,
    render_learned_calibration_defense_qa,
    render_learned_calibration_limitations,
    render_learned_calibration_manifest_markdown,
    render_learned_calibration_thesis_section,
    render_publication_tables_markdown,
    render_summary_markdown,
)
from .training import render_model_summary_markdown

__all__ = [name for name in globals() if not name.startswith("__") and name not in {"annotations"}]
