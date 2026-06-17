from __future__ import annotations

_MISSING = object()

DATASET_COLUMNS = [
    "cve_id",
    "cvss_score",
    "risk_score",
    "risk_level",
    "confidence",
    "severity_signal",
    "epss_signal",
    "kev_signal",
    "recency_signal",
    "correlation_signal",
    "graph_signal",
    "nlp_context_signal",
    "score_before_intrinsic_floor",
    "intrinsic_criticality_floor_applied",
    "accepted_urlhaus_count",
    "accepted_dread_count",
    "candidate_urlhaus_count",
    "candidate_dread_count",
    "urlhaus_raw_candidate_count",
    "urlhaus_ignored_low_signal_count",
    "urlhaus_rejected_match_count",
    "assessment_confidence",
    "data_completeness",
    "coverage_limitations",
    "epss_available",
    "kev_status_known",
    "kev_listed",
    "age_days",
]

LABEL_COLUMNS = [
    "cve_id",
    "proxy_label_strategy_a",
    "proxy_binary_high_strategy_a",
    "proxy_label_strategy_b",
    "proxy_binary_high_strategy_b",
    "proxy_label_strategy_c",
    "proxy_binary_high_strategy_c",
    "proxy_label_reason",
    "proxy_label_limitations",
]

MODEL_FEATURE_COLUMNS = [
    "cvss_score",
    "severity_signal",
    "epss_signal",
    "kev_signal",
    "recency_signal",
    "correlation_signal",
    "graph_signal",
    "nlp_context_signal",
    "accepted_urlhaus_count",
    "accepted_dread_count",
    "data_completeness",
    "assessment_confidence",
    "age_days",
    "intrinsic_criticality_floor_applied",
]

PREDICTION_COLUMNS = [
    "cve_id",
    "strategy",
    "proxy_binary_high",
    "learned_probability",
    "learned_prediction",
]

DISAGREEMENT_COLUMNS = [
    "strategy",
    "cve_id",
    "cvss_score",
    "risk_score",
    "risk_level",
    "confidence",
    "learned_probability",
    "proxy_label",
    "key_signals",
    "coverage_limitations",
    "disagreement_type",
    "reason",
]

FEATURE_IMPORTANCE_COLUMNS = [
    "strategy",
    "feature",
    "coefficient",
    "absolute_coefficient_rank",
    "sign_interpretation",
    "feature_coverage_note",
    "warning",
]

ABLATION_COLUMNS = [
    "strategy",
    "ablation",
    "status",
    "features",
    "accuracy",
    "balanced_accuracy",
    "precision",
    "recall",
    "f1",
    "roc_auc",
    "pr_auc",
    "interpretation",
    "skip_reason",
]

LEAKAGE_CHECK_COLUMNS = [
    "check",
    "status",
    "details",
]

CASE_STUDY_COLUMNS = [
    "cve_id",
    "cvss_score",
    "risk_score",
    "confidence",
    "proxy_label",
    "learned_probability",
    "coverage_limitations",
    "key_reason",
    "case_group",
]

PROXY_SENSITIVITY_COLUMNS = [
    "epss_high_threshold",
    "cvss_critical_threshold",
    "nlp_context_threshold",
    "recency_threshold",
    "high_count",
    "medium_count",
    "low_count",
    "high_percentage",
    "precision_at_10",
    "precision_at_50",
    "precision_at_100",
    "label_stability_vs_strategy_a",
    "classification",
]

BOOTSTRAP_STABILITY_COLUMNS = [
    "iteration",
    "precision_at_10",
    "precision_at_50",
    "precision_at_100",
    "recall_at_50",
    "recall_at_100",
    "top50_overlap_with_full",
    "top100_overlap_with_full",
    "sample_size",
    "positive_count",
    "status",
    "skip_reason",
]

COVERAGE_STRATA_COLUMNS = [
    "stratum",
    "group",
    "count",
    "average_risk_score",
    "average_confidence",
    "strategy_a_high_count",
    "strategy_b_high_count",
    "strategy_c_high_count",
    "missing_feature_percentages",
    "interpretation_note",
]

LIMITATIONS_MATRIX_COLUMNS = [
    "limitation",
    "impact_on_interpretation",
    "mitigation_already_implemented",
    "future_work",
    "thesis_safe_wording",
]

LEGACY_HIGH_RISK_DIAGNOSTIC_COLUMNS = [
    "cve_id",
    "cve_year",
    "risk_score",
    "risk_level",
    "confidence",
    "cvss_score",
    "severity_signal",
    "recency_signal",
    "nlp_context_signal",
    "correlation_signal",
    "intrinsic_criticality_floor_applied",
    "accepted_urlhaus_count",
    "accepted_dread_count",
    "coverage_limitations",
    "diagnostic_group",
    "interpretation",
]

LEGACY_DAMPENING_COUNTERFACTUAL_COLUMNS = [
    "cve_id",
    "cve_year",
    "risk_score",
    "counterfactual_score",
    "risk_bucket",
    "counterfactual_risk_bucket",
    "high_medium_low_level",
    "counterfactual_high_medium_low_level",
    "risk_bucket_changed",
    "high_medium_low_level_changed",
    "cvss_score",
    "recency_signal",
    "epss_signal",
    "kev_listed",
    "accepted_urlhaus_count",
    "accepted_dread_count",
    "dampening_applied",
    "dampening_amount",
    "counterfactual_floor",
    "interpretation",
]

__all__ = [name for name in globals() if not name.startswith("__")]
