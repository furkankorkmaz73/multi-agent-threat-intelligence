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

from .constants import *
from .common import *
from .artifacts import _learned_calibration_artifact_specs
from .data import build_feasibility_report, build_proxy_label_rows, extract_calibration_row, read_analyzed_cves_from_mongo, strict_validation_errors
from .metrics import (
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
    render_ablation_markdown,
    render_baseline_metrics_markdown,
    render_bootstrap_stability_markdown,
    render_coverage_strata_markdown,
    render_disagreements_markdown,
    render_feature_importance_markdown,
    render_leakage_checks_markdown,
    render_learned_vs_heuristic_markdown,
    render_negative_controls_markdown,
    render_proxy_sensitivity_markdown,
)
from .snapshots import (
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
from .training import render_model_summary_markdown, train_learned_calibration_models

def render_summary_markdown(report: Mapping[str, Any]) -> str:
    label = report.get("proxy_supervised_learning_feasibility", "not_recommended")
    warnings = report.get("warnings") or []
    lines = [
        "# Learned Calibration Feasibility Summary",
        "",
        "This export is an experimental calibration layer for analysis, not a production scoring change.",
        "Proxy labels are not ground truth, and production `risk_score` behavior is unchanged.",
        "Confidence remains separate from risk. Dread live crawling is not used.",
        "",
        "## Dataset Snapshot",
        "",
        f"- Total CVE records read: `{report.get('total_cve_records_read', 0)}`",
        f"- Analyzed records exported: `{report.get('analyzed_records_exported', 0)}`",
        f"- Records with CVSS: `{report.get('records_with_cvss', 0)}`",
        f"- EPSS available: `{report.get('epss_availability_count', 0)}`",
        f"- KEV status known: `{report.get('kev_known_count', 0)}`",
        f"- Accepted external evidence count: `{report.get('accepted_external_evidence_count', 0)}`",
        f"- Proxy label rows: `{report.get('analyzed_records_exported', 0)}`",
        "",
        "## Feasibility",
        "",
        f"- Proxy-supervised learning feasibility: `{label}`",
        "",
        "The current data is suitable for proxy-supervised learning only if feature coverage and externally defensible proxy labels are adequate. Weak EPSS, KEV, or external-evidence coverage limits what can be learned responsibly.",
        "Proxy labels are deterministic thesis-analysis aids, not verified exploitation outcomes.",
        "",
        "## Warnings",
        "",
    ]
    if warnings:
        lines.extend(f"- {warning}" for warning in warnings)
    else:
        lines.append("- No major feasibility warnings were generated.")
    lines.append("")
    return "\n".join(lines)

def write_outputs(rows: Sequence[Mapping[str, Any]], report: Mapping[str, Any], output_dir: str | Path) -> dict[str, str]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    dataset_path = output / "learned_calibration_dataset.csv"
    labels_path = output / "learned_calibration_labels.csv"
    report_path = output / "learned_calibration_report.json"
    summary_path = output / "learned_calibration_summary.md"
    baseline_json_path = output / "learned_calibration_baseline_metrics.json"
    baseline_md_path = output / "learned_calibration_baseline_metrics.md"
    predictions_path = output / "learned_calibration_predictions.csv"
    model_report_path = output / "learned_calibration_model_report.json"
    model_summary_path = output / "learned_calibration_model_summary.md"
    comparison_path = output / "learned_vs_heuristic_comparison.json"
    comparison_summary_path = output / "learned_vs_heuristic_comparison.md"
    disagreements_path = output / "learned_calibration_disagreements.csv"
    disagreements_summary_path = output / "learned_calibration_disagreements.md"
    feature_importance_path = output / "learned_calibration_feature_importance.csv"
    feature_importance_summary_path = output / "learned_calibration_feature_importance.md"
    ablation_path = output / "learned_calibration_ablation.csv"
    ablation_summary_path = output / "learned_calibration_ablation.md"
    leakage_path = output / "learned_calibration_leakage_checks.json"
    leakage_summary_path = output / "learned_calibration_leakage_checks.md"
    thesis_section_path = output / "learned_calibration_thesis_section.md"
    limitations_path = output / "learned_calibration_limitations.md"
    case_studies_path = output / "learned_calibration_case_studies.csv"
    case_studies_summary_path = output / "learned_calibration_case_studies.md"
    tables_path = output / "learned_calibration_tables.json"
    tables_summary_path = output / "learned_calibration_tables.md"
    manifest_path = output / "learned_calibration_manifest.json"
    manifest_summary_path = output / "learned_calibration_manifest.md"
    proxy_sensitivity_path = output / "learned_calibration_proxy_sensitivity.csv"
    proxy_sensitivity_json_path = output / "learned_calibration_proxy_sensitivity.json"
    proxy_sensitivity_summary_path = output / "learned_calibration_proxy_sensitivity.md"
    bootstrap_path = output / "learned_calibration_bootstrap_stability.csv"
    bootstrap_json_path = output / "learned_calibration_bootstrap_stability.json"
    bootstrap_summary_path = output / "learned_calibration_bootstrap_stability.md"
    coverage_strata_path = output / "learned_calibration_coverage_strata.csv"
    coverage_strata_json_path = output / "learned_calibration_coverage_strata.json"
    coverage_strata_summary_path = output / "learned_calibration_coverage_strata.md"
    negative_controls_path = output / "learned_calibration_negative_controls.json"
    negative_controls_summary_path = output / "learned_calibration_negative_controls.md"
    consistency_audit_path = output / "learned_calibration_consistency_audit.json"
    consistency_audit_summary_path = output / "learned_calibration_consistency_audit.md"
    appendix_path = output / "learned_calibration_appendix.md"
    runtime_snapshot_path = output / "learned_calibration_runtime_snapshot.json"
    runtime_snapshot_summary_path = output / "learned_calibration_runtime_snapshot.md"
    reviewer_checklist_path = output / "learned_calibration_reviewer_checklist.json"
    reviewer_checklist_summary_path = output / "learned_calibration_reviewer_checklist.md"
    defense_qa_path = output / "learned_calibration_defense_qa.md"
    limitations_matrix_path = output / "learned_calibration_limitations_matrix.csv"
    limitations_matrix_json_path = output / "learned_calibration_limitations_matrix.json"
    limitations_matrix_summary_path = output / "learned_calibration_limitations_matrix.md"
    no_overclaim_audit_path = output / "learned_calibration_no_overclaim_audit.json"
    no_overclaim_audit_summary_path = output / "learned_calibration_no_overclaim_audit.md"
    legacy_high_risk_path = output / "legacy_high_risk_diagnostics.csv"
    legacy_high_risk_json_path = output / "legacy_high_risk_diagnostics.json"
    legacy_high_risk_summary_path = output / "legacy_high_risk_diagnostics.md"
    legacy_dampening_path = output / "legacy_dampening_counterfactual.csv"
    legacy_dampening_json_path = output / "legacy_dampening_counterfactual.json"
    legacy_dampening_summary_path = output / "legacy_dampening_counterfactual.md"
    label_rows = build_proxy_label_rows(rows)
    baseline_metrics = compute_baseline_metrics(rows, label_rows)
    model_result = train_learned_calibration_models(rows, label_rows)
    comparison = compute_learned_vs_heuristic_comparison(rows, label_rows, model_result["predictions"])
    disagreements = compute_disagreement_cases(rows, label_rows, model_result["predictions"])
    feature_importance = extract_feature_importance(model_result["report"], rows)
    ablations = compute_ablation_experiments(model_result["report"])
    leakage_checks = build_leakage_checks(model_result["report"], report, summary_text=render_summary_markdown(report))
    case_studies = select_case_studies(rows, label_rows, model_result["predictions"])
    publication_tables = build_publication_tables(
        feasibility_report=report,
        baseline_metrics=baseline_metrics,
        model_report=model_result["report"],
        ablations=ablations,
        leakage_checks=leakage_checks,
    )
    proxy_sensitivity = compute_proxy_threshold_sensitivity(rows, label_rows)
    bootstrap_stability = compute_bootstrap_stability(rows, label_rows)
    coverage_strata = compute_coverage_strata(rows, label_rows)
    negative_controls = compute_negative_controls(rows, label_rows)
    with dataset_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DATASET_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in DATASET_COLUMNS})
    with labels_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LABEL_COLUMNS)
        writer.writeheader()
        for row in label_rows:
            writer.writerow({column: row.get(column, "") for column in LABEL_COLUMNS})
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True, default=str), encoding="utf-8")
    summary_path.write_text(render_summary_markdown(report), encoding="utf-8")
    baseline_json_path.write_text(json.dumps(baseline_metrics, indent=2, sort_keys=True, default=str), encoding="utf-8")
    baseline_md_path.write_text(render_baseline_metrics_markdown(baseline_metrics), encoding="utf-8")
    with predictions_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PREDICTION_COLUMNS)
        writer.writeheader()
        for row in model_result["predictions"]:
            writer.writerow({column: row.get(column, "") for column in PREDICTION_COLUMNS})
    model_report_path.write_text(json.dumps(model_result["report"], indent=2, sort_keys=True, default=str), encoding="utf-8")
    model_summary_path.write_text(render_model_summary_markdown(model_result["report"]), encoding="utf-8")
    comparison_path.write_text(json.dumps(comparison, indent=2, sort_keys=True, default=str), encoding="utf-8")
    comparison_summary_path.write_text(render_learned_vs_heuristic_markdown(comparison), encoding="utf-8")
    with disagreements_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=DISAGREEMENT_COLUMNS)
        writer.writeheader()
        for row in disagreements:
            writer.writerow({column: row.get(column, "") for column in DISAGREEMENT_COLUMNS})
    disagreements_summary_path.write_text(render_disagreements_markdown(disagreements), encoding="utf-8")
    with feature_importance_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FEATURE_IMPORTANCE_COLUMNS)
        writer.writeheader()
        for row in feature_importance:
            writer.writerow({column: row.get(column, "") for column in FEATURE_IMPORTANCE_COLUMNS})
    feature_importance_summary_path.write_text(render_feature_importance_markdown(feature_importance, model_result["report"]), encoding="utf-8")
    with ablation_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=ABLATION_COLUMNS)
        writer.writeheader()
        for row in ablations:
            writer.writerow({column: row.get(column, "") for column in ABLATION_COLUMNS})
    ablation_summary_path.write_text(render_ablation_markdown(ablations), encoding="utf-8")
    leakage_path.write_text(json.dumps(leakage_checks, indent=2, sort_keys=True, default=str), encoding="utf-8")
    leakage_summary_path.write_text(render_leakage_checks_markdown(leakage_checks), encoding="utf-8")
    thesis_section_path.write_text(
        render_learned_calibration_thesis_section(report, baseline_metrics, model_result["report"], comparison, disagreements, ablations),
        encoding="utf-8",
    )
    limitations_path.write_text(render_learned_calibration_limitations(report, model_result["report"], leakage_checks), encoding="utf-8")
    with case_studies_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CASE_STUDY_COLUMNS)
        writer.writeheader()
        for row in case_studies:
            writer.writerow({column: row.get(column, "") for column in CASE_STUDY_COLUMNS})
    case_studies_summary_path.write_text(render_case_studies_markdown(case_studies), encoding="utf-8")
    tables_path.write_text(json.dumps(publication_tables, indent=2, sort_keys=True, default=str), encoding="utf-8")
    tables_summary_path.write_text(render_publication_tables_markdown(publication_tables), encoding="utf-8")
    with proxy_sensitivity_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=PROXY_SENSITIVITY_COLUMNS)
        writer.writeheader()
        for row in proxy_sensitivity["rows"]:
            writer.writerow({column: row.get(column, "") for column in PROXY_SENSITIVITY_COLUMNS})
    proxy_sensitivity_json_path.write_text(json.dumps(proxy_sensitivity, indent=2, sort_keys=True, default=str), encoding="utf-8")
    proxy_sensitivity_summary_path.write_text(render_proxy_sensitivity_markdown(proxy_sensitivity), encoding="utf-8")
    with bootstrap_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=BOOTSTRAP_STABILITY_COLUMNS)
        writer.writeheader()
        for row in bootstrap_stability["iterations"]:
            writer.writerow({column: row.get(column, "") for column in BOOTSTRAP_STABILITY_COLUMNS})
    bootstrap_json_path.write_text(json.dumps(bootstrap_stability, indent=2, sort_keys=True, default=str), encoding="utf-8")
    bootstrap_summary_path.write_text(render_bootstrap_stability_markdown(bootstrap_stability), encoding="utf-8")
    with coverage_strata_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COVERAGE_STRATA_COLUMNS)
        writer.writeheader()
        for row in coverage_strata["rows"]:
            writer.writerow({column: row.get(column, "") for column in COVERAGE_STRATA_COLUMNS})
    coverage_strata_json_path.write_text(json.dumps(coverage_strata, indent=2, sort_keys=True, default=str), encoding="utf-8")
    coverage_strata_summary_path.write_text(render_coverage_strata_markdown(coverage_strata), encoding="utf-8")
    negative_controls_path.write_text(json.dumps(negative_controls, indent=2, sort_keys=True, default=str), encoding="utf-8")
    negative_controls_summary_path.write_text(render_negative_controls_markdown(negative_controls), encoding="utf-8")
    runtime_snapshot = build_runtime_snapshot(output)
    runtime_snapshot_path.write_text(json.dumps(runtime_snapshot, indent=2, sort_keys=True, default=str), encoding="utf-8")
    runtime_snapshot_summary_path.write_text(render_runtime_snapshot_markdown(runtime_snapshot), encoding="utf-8")
    reviewer_checklist = build_reviewer_checklist(output)
    reviewer_checklist_path.write_text(json.dumps(reviewer_checklist, indent=2, sort_keys=True, default=str), encoding="utf-8")
    reviewer_checklist_summary_path.write_text(render_reviewer_checklist_markdown(reviewer_checklist), encoding="utf-8")
    defense_qa_path.write_text(render_learned_calibration_defense_qa(model_result["report"], report), encoding="utf-8")
    limitations_matrix = build_limitations_matrix()
    with limitations_matrix_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LIMITATIONS_MATRIX_COLUMNS)
        writer.writeheader()
        for row in limitations_matrix["rows"]:
            writer.writerow({column: row.get(column, "") for column in LIMITATIONS_MATRIX_COLUMNS})
    limitations_matrix_json_path.write_text(json.dumps(limitations_matrix, indent=2, sort_keys=True, default=str), encoding="utf-8")
    limitations_matrix_summary_path.write_text(render_limitations_matrix_markdown(limitations_matrix), encoding="utf-8")
    legacy_high_risk = build_legacy_high_risk_diagnostics(rows)
    with legacy_high_risk_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEGACY_HIGH_RISK_DIAGNOSTIC_COLUMNS)
        writer.writeheader()
        for row in legacy_high_risk["rows"]:
            writer.writerow({column: row.get(column, "") for column in LEGACY_HIGH_RISK_DIAGNOSTIC_COLUMNS})
    legacy_high_risk_json_path.write_text(json.dumps(legacy_high_risk, indent=2, sort_keys=True, default=str), encoding="utf-8")
    legacy_high_risk_summary_path.write_text(render_legacy_high_risk_diagnostics_markdown(legacy_high_risk), encoding="utf-8")
    legacy_dampening = build_legacy_dampening_counterfactual(rows)
    with legacy_dampening_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEGACY_DAMPENING_COUNTERFACTUAL_COLUMNS)
        writer.writeheader()
        for row in legacy_dampening["rows"]:
            writer.writerow({column: row.get(column, "") for column in LEGACY_DAMPENING_COUNTERFACTUAL_COLUMNS})
    legacy_dampening_json_path.write_text(json.dumps(legacy_dampening, indent=2, sort_keys=True, default=str), encoding="utf-8")
    legacy_dampening_summary_path.write_text(render_legacy_dampening_counterfactual_markdown(legacy_dampening), encoding="utf-8")
    no_overclaim_audit = build_no_overclaim_audit(output)
    no_overclaim_audit_path.write_text(json.dumps(no_overclaim_audit, indent=2, sort_keys=True, default=str), encoding="utf-8")
    no_overclaim_audit_summary_path.write_text(render_no_overclaim_audit_markdown(no_overclaim_audit), encoding="utf-8")
    appendix_path.write_text(
        render_learned_calibration_appendix(
            feasibility_report=report,
            baseline_metrics=baseline_metrics,
            model_report=model_result["report"],
            proxy_sensitivity=proxy_sensitivity,
            bootstrap_stability=bootstrap_stability,
            coverage_strata=coverage_strata,
            negative_controls=negative_controls,
            case_studies=case_studies,
            leakage_checks=leakage_checks,
            consistency_audit={"status": "pending"},
        ),
        encoding="utf-8",
    )
    consistency_audit = build_consistency_audit(output)
    consistency_audit_path.write_text(json.dumps(consistency_audit, indent=2, sort_keys=True, default=str), encoding="utf-8")
    consistency_audit_summary_path.write_text(render_consistency_audit_markdown(consistency_audit), encoding="utf-8")
    appendix_path.write_text(
        render_learned_calibration_appendix(
            feasibility_report=report,
            baseline_metrics=baseline_metrics,
            model_report=model_result["report"],
            proxy_sensitivity=proxy_sensitivity,
            bootstrap_stability=bootstrap_stability,
            coverage_strata=coverage_strata,
            negative_controls=negative_controls,
            case_studies=case_studies,
            leakage_checks=leakage_checks,
            consistency_audit=consistency_audit,
        ),
        encoding="utf-8",
    )
    artifact_manifest = build_learned_calibration_manifest(output)
    manifest_path.write_text(json.dumps(artifact_manifest, indent=2, sort_keys=True, default=str), encoding="utf-8")
    manifest_summary_path.write_text(render_learned_calibration_manifest_markdown(artifact_manifest), encoding="utf-8")
    runtime_snapshot = build_runtime_snapshot(output)
    runtime_snapshot_path.write_text(json.dumps(runtime_snapshot, indent=2, sort_keys=True, default=str), encoding="utf-8")
    runtime_snapshot_summary_path.write_text(render_runtime_snapshot_markdown(runtime_snapshot), encoding="utf-8")
    reviewer_checklist = build_reviewer_checklist(output)
    reviewer_checklist_path.write_text(json.dumps(reviewer_checklist, indent=2, sort_keys=True, default=str), encoding="utf-8")
    reviewer_checklist_summary_path.write_text(render_reviewer_checklist_markdown(reviewer_checklist), encoding="utf-8")
    return {
        "dataset": str(dataset_path),
        "labels": str(labels_path),
        "report": str(report_path),
        "summary": str(summary_path),
        "baseline_metrics": str(baseline_json_path),
        "baseline_summary": str(baseline_md_path),
        "predictions": str(predictions_path),
        "model_report": str(model_report_path),
        "model_summary": str(model_summary_path),
        "learned_vs_heuristic_comparison": str(comparison_path),
        "learned_vs_heuristic_summary": str(comparison_summary_path),
        "disagreements": str(disagreements_path),
        "disagreements_summary": str(disagreements_summary_path),
        "feature_importance": str(feature_importance_path),
        "feature_importance_summary": str(feature_importance_summary_path),
        "ablation": str(ablation_path),
        "ablation_summary": str(ablation_summary_path),
        "leakage_checks": str(leakage_path),
        "leakage_checks_summary": str(leakage_summary_path),
        "thesis_section": str(thesis_section_path),
        "limitations": str(limitations_path),
        "case_studies": str(case_studies_path),
        "case_studies_summary": str(case_studies_summary_path),
        "tables": str(tables_path),
        "tables_summary": str(tables_summary_path),
        "proxy_sensitivity": str(proxy_sensitivity_path),
        "proxy_sensitivity_json": str(proxy_sensitivity_json_path),
        "proxy_sensitivity_summary": str(proxy_sensitivity_summary_path),
        "bootstrap_stability": str(bootstrap_path),
        "bootstrap_stability_json": str(bootstrap_json_path),
        "bootstrap_stability_summary": str(bootstrap_summary_path),
        "coverage_strata": str(coverage_strata_path),
        "coverage_strata_json": str(coverage_strata_json_path),
        "coverage_strata_summary": str(coverage_strata_summary_path),
        "negative_controls": str(negative_controls_path),
        "negative_controls_summary": str(negative_controls_summary_path),
        "consistency_audit": str(consistency_audit_path),
        "consistency_audit_summary": str(consistency_audit_summary_path),
        "appendix": str(appendix_path),
        "runtime_snapshot": str(runtime_snapshot_path),
        "runtime_snapshot_summary": str(runtime_snapshot_summary_path),
        "reviewer_checklist": str(reviewer_checklist_path),
        "reviewer_checklist_summary": str(reviewer_checklist_summary_path),
        "defense_qa": str(defense_qa_path),
        "limitations_matrix": str(limitations_matrix_path),
        "limitations_matrix_json": str(limitations_matrix_json_path),
        "limitations_matrix_summary": str(limitations_matrix_summary_path),
        "no_overclaim_audit": str(no_overclaim_audit_path),
        "no_overclaim_audit_summary": str(no_overclaim_audit_summary_path),
        "legacy_high_risk_diagnostics": str(legacy_high_risk_path),
        "legacy_high_risk_diagnostics_json": str(legacy_high_risk_json_path),
        "legacy_high_risk_diagnostics_summary": str(legacy_high_risk_summary_path),
        "legacy_dampening_counterfactual": str(legacy_dampening_path),
        "legacy_dampening_counterfactual_json": str(legacy_dampening_json_path),
        "legacy_dampening_counterfactual_summary": str(legacy_dampening_summary_path),
        "manifest": str(manifest_path),
        "manifest_summary": str(manifest_summary_path),
    }

def export_from_documents(docs: Sequence[Mapping[str, Any]], output_dir: str | Path, *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [row for doc in docs if (row := extract_calibration_row(doc)) is not None]
    rows = sorted(rows, key=lambda row: str(row.get("cve_id", "")))
    report = build_feasibility_report(rows, total_records_read=len(docs), generated_at=generated_at)
    paths = write_outputs(rows, report, output_dir)
    return {"paths": paths, "report": report}

def render_learned_calibration_thesis_section(
    feasibility_report: Mapping[str, Any],
    baseline_metrics: Mapping[str, Any],
    model_report: Mapping[str, Any],
    comparison: Mapping[str, Any],
    disagreements: Sequence[Mapping[str, Any]],
    ablations: Sequence[Mapping[str, Any]],
) -> str:
    lines = [
        "# Learned Calibration Experiment",
        "",
        "This section summarizes an experimental learned-calibration layer built around the existing deterministic risk engine.",
        "The purpose is diagnostic: to examine whether proxy-supervised models could reproduce or challenge the heuristic ranking without replacing production `risk_score`.",
        "",
        "## Proxy Labels",
        "",
        "Proxy labels are constructed from intrinsic severity/context, EPSS/KEV signals when available, and accepted external evidence counts.",
        "They are not ground truth exploitation outcomes and do not support real-world supervised exploitation-prediction claims.",
        f"The exported dataset contains `{feasibility_report.get('analyzed_records_exported', 0)}` analyzed CVE rows.",
        "",
        "## Feature Set",
        "",
        "The experimental feature set includes CVSS, normalized scoring signals, accepted evidence counts, confidence/data-completeness fields, age, and the intrinsic-criticality floor flag.",
        "Production `risk_score` and proxy-label fields are excluded from model inputs.",
        "",
        "## Baseline Comparison",
        "",
        "The baseline artifacts compare the existing heuristic `risk_score` ranking against each proxy strategy.",
        f"Baseline strategy statuses: `{_strategy_status_summary(baseline_metrics)}`.",
        "",
        "## Model Metrics",
        "",
        f"Model artifact status: `{model_report.get('status', '')}`.",
        "When scikit-learn or usable class diversity is unavailable, model metrics are explicitly skipped rather than fabricated.",
        "",
        "## Ablation Interpretation",
        "",
        f"Ablation rows exported: `{len(ablations)}`.",
        "Ablations are designed to test CVSS/severity dominance, recency, NLP context, confidence/data completeness, sparse evidence, normalized signals, and metadata/context views.",
        "",
        "## Disagreement Analysis",
        "",
        f"Disagreement rows exported: `{len(disagreements)}`.",
        "These rows are intended as thesis examples when learned predictions are available; otherwise the artifact remains empty with an explicit explanation.",
        "",
        "## Production Risk Score",
        "",
        "The production risk score remains heuristic, deterministic, and explainable.",
        "The learned-calibration artifacts do not write predictions back into MongoDB, do not recalibrate confidence, and do not change URLhaus/Dread evidence gates.",
        "",
        "## Interpretation",
        "",
        "The current experiment supports discussion of feasibility, proxy-label limitations, feature leakage controls, and evidence sparsity.",
        "It does not establish statistical significance, production readiness, or real-world exploitation-prediction performance.",
        "",
    ]
    return "\n".join(lines)

def render_learned_calibration_limitations(
    feasibility_report: Mapping[str, Any],
    model_report: Mapping[str, Any],
    leakage_checks: Mapping[str, Any],
) -> str:
    lines = [
        "# Learned Calibration Limitations",
        "",
        "## Scope",
        "",
        "Learned calibration is an experimental thesis artifact. It does not replace the deterministic scoring engine.",
        "",
        "## Proxy Labels Are Not Ground Truth",
        "",
        "The labels are deterministic proxies derived from available signals. They are not verified exploitation labels and should not be used to claim real-world predictive validity.",
        "",
        "## Evidence Coverage",
        "",
        f"EPSS available count: `{feasibility_report.get('epss_availability_count', 0)}`.",
        f"KEV known count: `{feasibility_report.get('kev_known_count', 0)}`.",
        f"Accepted external evidence count: `{feasibility_report.get('accepted_external_evidence_count', 0)}`.",
        "Sparse EPSS/KEV or accepted external evidence limits what a learned model can responsibly learn.",
        "",
        "## Model Availability",
        "",
        f"Model status: `{model_report.get('status', '')}`.",
        "If scikit-learn is unavailable or labels lack class diversity, training is skipped with explicit status fields.",
        "",
        "## Leakage Controls",
        "",
        f"Leakage check status: `{leakage_checks.get('status', '')}`.",
        "The experiment excludes production `risk_score` and proxy-label fields from model inputs and writes only local artifacts.",
        "",
        "## Production Use",
        "",
        "The learned-calibration outputs are diagnostic and thesis-facing. Production scoring remains heuristic, auditable, and evidence-gated.",
        "",
    ]
    return "\n".join(lines)

def _strategy_status_summary(metrics: Mapping[str, Any]) -> str:
    return ", ".join(
        f"{strategy}={payload.get('status', '')}"
        for strategy, payload in (metrics.get("strategies") or {}).items()
    )

def select_case_studies(
    rows: Sequence[Mapping[str, Any]],
    label_rows: Sequence[Mapping[str, Any]],
    prediction_rows: Sequence[Mapping[str, Any]],
    *,
    max_per_group: int = 5,
) -> list[dict[str, Any]]:
    label_by_cve = {str(row.get("cve_id", "")): row for row in label_rows}
    probability_by_cve = _best_probability_by_cve(prediction_rows)
    groups: dict[str, list[dict[str, Any]]] = {
        "high_heuristic_risk_and_high_learned_probability": [],
        "high_heuristic_risk_but_low_learned_probability": [],
        "low_medium_heuristic_risk_but_high_learned_probability": [],
        "intrinsic_floor_applied": [],
        "missing_epss_kev_high_intrinsic_severity": [],
        "no_accepted_external_evidence_high_proxy_label": [],
        "rejected_ignored_urlhaus_heavy": [],
        "low_confidence_but_high_risk": [],
    }
    for row in sorted(rows, key=lambda item: (-_safe_float(item.get("risk_score")), str(item.get("cve_id", "")))):
        cve_id = str(row.get("cve_id", ""))
        label = str((label_by_cve.get(cve_id) or {}).get("proxy_label_strategy_a", ""))
        probability = probability_by_cve.get(cve_id)
        if _safe_float(row.get("risk_score")) >= 7.0 and probability is not None and probability >= 0.7:
            groups["high_heuristic_risk_and_high_learned_probability"].append(_case_study_row(row, label, probability, "high_heuristic_risk_and_high_learned_probability", "high heuristic risk and high learned probability"))
        if _safe_float(row.get("risk_score")) >= 7.0 and probability is not None and probability < 0.4:
            groups["high_heuristic_risk_but_low_learned_probability"].append(_case_study_row(row, label, probability, "high_heuristic_risk_but_low_learned_probability", "high heuristic risk but low learned probability"))
        if _safe_float(row.get("risk_score")) < 7.0 and probability is not None and probability >= 0.7:
            groups["low_medium_heuristic_risk_but_high_learned_probability"].append(_case_study_row(row, label, probability, "low_medium_heuristic_risk_but_high_learned_probability", "low or medium heuristic risk but high learned probability"))
        if _truthy(row.get("intrinsic_criticality_floor_applied")):
            groups["intrinsic_floor_applied"].append(_case_study_row(row, label, probability, "intrinsic_floor_applied", "intrinsic criticality floor was applied"))
        if _safe_float(row.get("cvss_score")) >= 9.8 and not _truthy(row.get("epss_available")) and not _truthy(row.get("kev_status_known")):
            groups["missing_epss_kev_high_intrinsic_severity"].append(_case_study_row(row, label, probability, "missing_epss_kev_high_intrinsic_severity", "high intrinsic severity with missing EPSS/KEV coverage"))
        if _accepted_external_count(row) == 0 and label == "high":
            groups["no_accepted_external_evidence_high_proxy_label"].append(_case_study_row(row, label, probability, "no_accepted_external_evidence_high_proxy_label", "high proxy label without accepted external evidence"))
        if _safe_int(row.get("urlhaus_ignored_low_signal_count")) + _safe_int(row.get("urlhaus_rejected_match_count")) >= 5:
            groups["rejected_ignored_urlhaus_heavy"].append(_case_study_row(row, label, probability, "rejected_ignored_urlhaus_heavy", "many URLhaus candidates were ignored or rejected"))
        if _safe_float(row.get("confidence")) < 0.4 and _safe_float(row.get("risk_score")) >= 7.0:
            groups["low_confidence_but_high_risk"].append(_case_study_row(row, label, probability, "low_confidence_but_high_risk", "high risk with low confidence"))
    output: list[dict[str, Any]] = []
    for group in groups.values():
        output.extend(group[:max_per_group])
    return output

def render_case_studies_markdown(rows: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# Learned Calibration Case Studies",
        "",
        "These case studies are selected for thesis discussion from deterministic learned-calibration artifacts.",
        "They do not claim ground truth exploitation; they illustrate proxy-label and ranking behavior.",
        "",
    ]
    if not rows:
        lines.extend(["No case studies matched the configured groups.", ""])
        return "\n".join(lines)
    counts: dict[str, int] = {}
    for row in rows:
        group = str(row.get("case_group", ""))
        counts[group] = counts.get(group, 0) + 1
    lines.append("## Case Groups")
    lines.append("")
    for group, count in sorted(counts.items()):
        lines.append(f"- `{group}`: {count}")
    lines.append("")
    return "\n".join(lines)

def build_publication_tables(
    *,
    feasibility_report: Mapping[str, Any],
    baseline_metrics: Mapping[str, Any],
    model_report: Mapping[str, Any],
    ablations: Sequence[Mapping[str, Any]],
    leakage_checks: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "dataset_coverage_summary": [
            {"metric": "analyzed_records", "value": feasibility_report.get("analyzed_records_exported", 0)},
            {"metric": "records_with_cvss", "value": feasibility_report.get("records_with_cvss", 0)},
            {"metric": "epss_available", "value": feasibility_report.get("epss_availability_count", 0)},
            {"metric": "kev_known", "value": feasibility_report.get("kev_known_count", 0)},
            {"metric": "accepted_external_evidence", "value": feasibility_report.get("accepted_external_evidence_count", 0)},
        ],
        "proxy_label_class_distribution": _table_proxy_label_distribution(feasibility_report),
        "heuristic_baseline_metrics": _table_baseline_metrics(baseline_metrics),
        "learned_model_metrics": _table_model_metrics(model_report),
        "ablation_summary": _table_ablation_summary(ablations),
        "leakage_robustness_checks": list(leakage_checks.get("checks") or []),
        "artifact_inventory": [
            {"artifact": "learned_calibration_dataset.csv", "usage": "feature export"},
            {"artifact": "learned_calibration_labels.csv", "usage": "proxy labels"},
            {"artifact": "learned_calibration_baseline_metrics.json", "usage": "heuristic baseline"},
            {"artifact": "learned_calibration_model_report.json", "usage": "optional model metrics"},
            {"artifact": "learned_calibration_leakage_checks.json", "usage": "leakage controls"},
            {"artifact": "learned_calibration_case_studies.csv", "usage": "case studies"},
        ],
    }

def render_publication_tables_markdown(tables: Mapping[str, Any]) -> str:
    lines = ["# Learned Calibration Publication Tables", ""]
    lines.extend(_markdown_table("Dataset Coverage Summary", ["metric", "value"], tables.get("dataset_coverage_summary") or []))
    lines.extend(_markdown_table("Proxy Label Class Distribution", ["strategy", "label", "count"], tables.get("proxy_label_class_distribution") or []))
    lines.extend(_markdown_table("Heuristic Baseline Metrics", ["strategy", "status", "precision_at_10", "recall_at_50", "ndcg_at_50"], tables.get("heuristic_baseline_metrics") or []))
    lines.extend(_markdown_table("Learned Model Metrics", ["strategy", "status", "balanced_accuracy", "f1"], tables.get("learned_model_metrics") or []))
    lines.extend(_markdown_table("Ablation Summary", ["ablation", "status", "interpretation"], tables.get("ablation_summary") or []))
    lines.extend(_markdown_table("Leakage and Robustness Checks", ["check", "status", "details"], tables.get("leakage_robustness_checks") or []))
    lines.extend(_markdown_table("Artifact Inventory", ["artifact", "usage"], tables.get("artifact_inventory") or []))
    return "\n".join(lines)

def build_learned_calibration_manifest(output_dir: str | Path) -> dict[str, Any]:
    output = Path(output_dir)
    artifacts = []
    for spec in _learned_calibration_artifact_specs():
        path = output / spec["filename"]
        artifacts.append(
            {
                "group": spec["group"],
                "path": str(path),
                "exists": path.exists(),
                "size_bytes": path.stat().st_size if path.exists() else 0,
                "description": spec["description"],
                "producer": "evaluation.learned_calibration",
                "thesis_usage_note": spec["usage"],
            }
        )
    return {
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "status": "complete" if all(item["exists"] for item in artifacts) else "incomplete",
    }

def render_learned_calibration_manifest_markdown(manifest: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Artifact Manifest",
        "",
        f"- Status: `{manifest.get('status', '')}`",
        f"- Artifact count: `{manifest.get('artifact_count', 0)}`",
        "",
        "| Group | Path | Exists | Size Bytes | Thesis Usage |",
        "| --- | --- | --- | ---: | --- |",
    ]
    for item in manifest.get("artifacts") or []:
        lines.append(
            "| {group} | {path} | {exists} | {size} | {usage} |".format(
                group=item.get("group", ""),
                path=item.get("path", ""),
                exists=item.get("exists", ""),
                size=item.get("size_bytes", 0),
                usage=item.get("thesis_usage_note", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)

def render_learned_calibration_appendix(
    *,
    feasibility_report: Mapping[str, Any],
    baseline_metrics: Mapping[str, Any],
    model_report: Mapping[str, Any],
    proxy_sensitivity: Mapping[str, Any],
    bootstrap_stability: Mapping[str, Any],
    coverage_strata: Mapping[str, Any],
    negative_controls: Mapping[str, Any],
    case_studies: Sequence[Mapping[str, Any]],
    leakage_checks: Mapping[str, Any],
    consistency_audit: Mapping[str, Any],
) -> str:
    strategy_a = (baseline_metrics.get("strategies") or {}).get("strategy_a") or {}
    model_status = str(model_report.get("status", "unavailable"))
    bootstrap_summary = bootstrap_stability.get("summary") or {}
    bootstrap_p10 = (bootstrap_summary.get("precision_at_10") or {}).get("mean")
    negative_interpretation = (negative_controls.get("interpretation") or {}).get("summary", "Unavailable.")
    lines = [
        "# Learned Calibration Appendix Draft",
        "",
        "This appendix draft summarizes the learned-calibration feasibility artifacts in conservative academic language. Proxy labels are not ground truth exploitation outcomes, and this appendix does not change production scoring.",
        "",
        "## 1. Purpose of the Learned Calibration Experiment",
        "",
        "The learned-calibration experiment evaluates whether the existing deterministic signal export could support a future supervised calibration layer. It is diagnostic thesis material only: it does not replace the heuristic risk engine, does not write learned outputs back to MongoDB, and does not weaken URLhaus or Dread evidence gates.",
        "",
        "## 2. Dataset Construction",
        "",
        f"The export contains `{feasibility_report.get('analyzed_records_exported', 0)}` analyzed CVE rows from the existing analysis collection. `{feasibility_report.get('records_with_cvss', 0)}` rows include CVSS values, `{feasibility_report.get('epss_availability_count', 0)}` rows report EPSS availability, and `{feasibility_report.get('kev_known_count', 0)}` rows have known KEV status. Accepted external-evidence count is `{feasibility_report.get('accepted_external_evidence_count', 0)}`.",
        "",
        "## 3. Feature Schema",
        "",
        "The feature schema exports CVSS/severity, EPSS, KEV, recency, correlation, graph, NLP context, accepted evidence counts, confidence/data-completeness fields, age, and intrinsic criticality indicators. Production `risk_score` is excluded from learned-model feature columns to avoid leakage.",
        "",
        "## 4. Proxy-Label Design",
        "",
        "Strategy A combines intrinsic severity patterns with known evidence, Strategy B emphasizes KEV/EPSS/accepted external evidence, and Strategy C is a conservative high-vs-rest proxy. These labels are deterministic proxies for feasibility analysis, not real-world exploitation labels.",
        "",
        "## 5. Coverage Limitations",
        "",
        f"Coverage remains limited: EPSS availability is `{feasibility_report.get('epss_availability_count', 0)}` and KEV-known count is `{feasibility_report.get('kev_known_count', 0)}` in the exported dataset. Missing EPSS, KEV, or accepted external evidence should be interpreted as coverage limitations rather than proof that a CVE is unimportant.",
        "Legacy high-risk diagnostics distinguish modern intrinsic criticality floor cases, old high-CVSS retained-severity cases, and high-risk cases with no accepted external evidence. These diagnostics are not a production scoring change. Preserving old CVSS 10 severity can be defensible for intrinsic technical severity, but lack of EPSS, KEV, or accepted external evidence limits operational interpretation.",
        "",
        "## 6. Baseline Ranking Metrics",
        "",
        f"For Strategy A, heuristic precision@10 is `{_format_metric((strategy_a.get('precision_at_k') or {}).get('10'))}`, recall@50 is `{_format_metric((strategy_a.get('recall_at_k') or {}).get('50'))}`, and nDCG@50 is `{_format_metric((strategy_a.get('ndcg_at_k') or {}).get('50'))}`. These metrics compare the unchanged heuristic ranking with proxy labels only.",
        "",
        "## 7. Model Training Status and Dependency Limitations",
        "",
        f"Model training status is `{model_status}`. If scikit-learn is unavailable or proxy labels lack class diversity, model artifacts are explicitly skipped instead of fabricating learned results.",
        "",
        "## 8. Sensitivity Analysis",
        "",
        f"The proxy-threshold sensitivity grid contains `{proxy_sensitivity.get('grid_size', 0)}` deterministic configurations. This probes threshold robustness for proxy-label definitions and does not alter default labels or production scoring.",
        "",
        "## 9. Bootstrap Stability",
        "",
        f"Bootstrap stability status is `{bootstrap_stability.get('status', 'unavailable')}` with `{bootstrap_stability.get('iteration_count', 0)}` fixed-seed iterations. Mean precision@10 is `{_format_metric(bootstrap_p10)}` when available. This is a deterministic robustness check, not statistical calibration.",
        "",
        "## 10. Coverage-Stratified Analysis",
        "",
        f"The coverage-strata artifact reports `{coverage_strata.get('strata_count', 0)}` strata rows across EPSS, KEV, evidence, intrinsic-floor, confidence, risk, and URLhaus candidate-accounting groups. It helps separate ranking behavior from evidence-coverage limitations.",
        "",
        "## 11. Negative Controls",
        "",
        str(negative_interpretation),
        "",
        "## 12. Disagreement/Case-Study Interpretation",
        "",
        f"The case-study export contains `{len(case_studies)}` selected rows when examples are available. These cases are intended for qualitative discussion of proxy behavior, sparse evidence, intrinsic criticality, ignored URLhaus volume, and low-confidence high-risk records.",
        "",
        "## 13. Leakage and Robustness Checks",
        "",
        f"Leakage-check status is `{leakage_checks.get('status', 'unavailable')}`. The checks document that production `risk_score` is excluded from learned features, proxy-label fields are not model inputs, evidence gates are unchanged, and Dread live crawling is not used.",
        "",
        "## 14. Why Production Risk Scoring Remains Heuristic",
        "",
        "The current thesis implementation keeps production risk scoring heuristic and explainable because proxy labels are not ground truth, external evidence coverage is sparse, and learned models may be unavailable or untrainable in the local environment. Learned calibration remains a future extension candidate.",
        "",
        "## 15. Threats to Validity",
        "",
        "The main threats are proxy-label circularity, sparse EPSS/KEV and accepted external evidence, limited positive labels, dependency availability, and lack of external ground-truth outcomes. The artifacts support feasibility and robustness discussion, not claims of real-world predictive performance.",
        "",
        "## 16. Recommended Future Work",
        "",
        f"Future work should add defensible external labels, improve EPSS/KEV and asset-context coverage, evaluate train/test separation on curated datasets, and repeat consistency checks. Future age-aware dampening should be evaluated only with stronger labels or asset context. Current consistency-audit status is `{consistency_audit.get('status', 'unavailable')}`.",
        "",
    ]
    return "\n".join(lines)

def render_learned_calibration_defense_qa(
    model_report: Mapping[str, Any],
    feasibility_report: Mapping[str, Any],
) -> str:
    model_status = str(model_report.get("status", "unavailable"))
    skip_reason = str(model_report.get("skip_reason", "not applicable"))
    exported = feasibility_report.get("analyzed_records_exported", 0)
    qa_entries = [
        ("Why were proxy labels used?", "Proxy labels were used because defensible external exploitation outcomes are not available in this repository. They enable a bounded feasibility discussion over exported signals without claiming real-world prediction."),
        ("Why are proxy labels not ground truth?", "They are deterministic labels derived from existing signals and engineering rules. They do not independently verify exploitation, prevalence, exploitability, or operational impact."),
        ("Why does the production risk score remain heuristic?", "The production risk score remains heuristic because it is explainable, deterministic, and tied to existing evidence gates. The learned-calibration artifacts are experimental and do not replace production scoring."),
        ("Why is learned calibration described as experimental?", "The experiment evaluates feasibility under sparse labels and coverage limitations. It is not a deployed scoring layer and does not write learned outputs back to MongoDB."),
        ("What does scikit-learn absence mean if the model was skipped?", f"The local model status is `{model_status}`. If skipped, the reason is `{skip_reason}`. Skipping records dependency limitations transparently instead of fabricating model results."),
        ("What would change with real ground truth labels?", "Curated external labels would allow train/test evaluation, calibration checks, and stronger claims about predictive behavior. They would still require leakage controls and independent validation."),
        ("Why may accepted URLhaus correlation be zero?", "URLhaus evidence gates are conservative. Candidate retrieval or weak keyword overlap is not accepted evidence; exact or strong corroborated evidence is required."),
        ("Why is live Dread crawling disabled?", "Live Dread crawling was not used. Dread is optional, experimental, bounded, default-off, and unsuitable as ground truth without corroboration and ethical/legal controls."),
        ("How does confidence differ from risk?", "Risk estimates prioritization urgency from technical and contextual signals. Confidence estimates reliability and completeness of supporting evidence. High risk can coexist with moderate confidence."),
        ("How do evidence gates prevent false positives?", "Evidence gates separate accepted, manual-review, rejected, and ignored low-signal candidates. Only accepted evidence can support correlation risk; diagnostic or rejected evidence is preserved without boosting risk."),
        ("Why is CVSS dominance a limitation?", "CVSS captures technical severity, not full operational risk. If proxy labels include intrinsic severity, CVSS-only rankings may appear close to the heuristic and should be interpreted cautiously."),
        ("How should sensitivity analysis be interpreted?", "Sensitivity analysis probes robustness to bounded threshold or weight changes. It is not statistical calibration and does not prove generalization."),
        ("How should negative controls be interpreted?", "Negative controls show whether heuristic ranking behaves differently from random, reverse, or single-feature rankings under proxy labels. They are sanity checks, not proof of real-world performance."),
        ("How should bootstrap stability be interpreted?", "Bootstrap stability checks whether ranking metrics are stable under fixed-seed resampling of exported rows. It does not create new evidence or external validation."),
        ("What future work is needed?", "Future work requires curated external labels, better EPSS/KEV coverage, stronger asset-context data, independent validation splits, and careful review of model calibration and leakage."),
        ("What claims are safe in the thesis?", "Safe claims are limited to deterministic export, proxy-label feasibility, artifact reproducibility, conservative gates, and observed behavior on the exported dataset."),
        ("What claims should be avoided?", "Avoid claims of production readiness, real-world exploitation prediction, optimized weights, autonomous-agent validation, or learned replacement of heuristic scoring."),
        ("How many analyzed rows were exported?", f"The learned-calibration export contains `{exported}` analyzed CVE rows in the current artifact bundle."),
        ("Why is accepted external evidence sparse?", "Accepted evidence is sparse because evidence gates require strong support. Sparse accepted evidence is a coverage limitation, not a reason to relax gates."),
        ("Does proxy-supervised learning prove real-world exploitation prediction?", "No. Proxy-supervised learning does not prove real-world exploitation prediction; it only supports a constrained feasibility discussion over local deterministic artifacts."),
    ]
    lines = [
        "# Learned Calibration Defense Q&A",
        "",
        "This defense-preparation draft focuses on learned calibration and thesis limitations. It uses academic, conservative wording; proxy labels are not ground truth, live Dread crawling was not used, and production scoring remains heuristic.",
        "",
    ]
    for index, (question, answer) in enumerate(qa_entries, start=1):
        lines.extend([f"## Q{index}. {question}", "", answer, ""])
    return "\n".join(lines)

def build_legacy_high_risk_diagnostics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    diagnostic_rows: list[dict[str, Any]] = []
    group_values: dict[str, dict[str, list[float]]] = {}
    for row in rows:
        cve_year = extract_cve_year(row.get("cve_id"))
        for group in _legacy_high_risk_groups(row, cve_year):
            diagnostic = _legacy_high_risk_diagnostic_row(row, cve_year, group)
            diagnostic_rows.append(diagnostic)
            values = group_values.setdefault(group, {"risk": [], "confidence": []})
            values["risk"].append(_safe_float(row.get("risk_score")))
            values["confidence"].append(_safe_float(row.get("confidence")))
    diagnostic_rows = sorted(
        diagnostic_rows,
        key=lambda item: (item["diagnostic_group"], -_safe_float(item["risk_score"]), item["cve_id"]),
    )
    groups = sorted(group_values)
    return {
        "status": "available",
        "total_analyzed_cves": len(rows),
        "warning": "This diagnostic is not a production scoring change and does not change risk_score, confidence, or evidence gates.",
        "count_per_diagnostic_group": {
            group: sum(1 for item in diagnostic_rows if item["diagnostic_group"] == group)
            for group in groups
        },
        "average_risk_per_group": {
            group: round(mean(group_values[group]["risk"]), 4) if group_values[group]["risk"] else 0.0
            for group in groups
        },
        "average_confidence_per_group": {
            group: round(mean(group_values[group]["confidence"]), 4) if group_values[group]["confidence"] else 0.0
            for group in groups
        },
        "highest_risk_examples_per_group": {
            group: [
                {
                    "cve_id": item["cve_id"],
                    "risk_score": item["risk_score"],
                    "confidence": item["confidence"],
                    "interpretation": item["interpretation"],
                }
                for item in sorted(
                    (candidate for candidate in diagnostic_rows if candidate["diagnostic_group"] == group),
                    key=lambda candidate: (-_safe_float(candidate["risk_score"]), candidate["cve_id"]),
                )[:5]
            ]
            for group in groups
        },
        "rows": diagnostic_rows,
    }

def render_legacy_high_risk_diagnostics_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Legacy High-Risk Diagnostics",
        "",
        "This artifact identifies old or intrinsic-severity-driven CVEs for diagnostic review only.",
        "It does not change production `risk_score`, confidence, or URLhaus/Dread evidence gates.",
        "",
        f"- Total analyzed CVEs: `{payload.get('total_analyzed_cves', 0)}`",
        f"- Diagnostic rows: `{len(payload.get('rows') or [])}`",
        f"- Warning: {payload.get('warning', '')}",
        "",
        "## Diagnostic Groups",
        "",
        "| Group | Count | Average Risk | Average Confidence |",
        "| --- | ---: | ---: | ---: |",
    ]
    counts = payload.get("count_per_diagnostic_group") or {}
    average_risk = payload.get("average_risk_per_group") or {}
    average_confidence = payload.get("average_confidence_per_group") or {}
    if counts:
        for group in sorted(counts):
            lines.append(
                "| {group} | {count} | {risk} | {confidence} |".format(
                    group=group,
                    count=counts.get(group, 0),
                    risk=_format_metric(average_risk.get(group)),
                    confidence=_format_metric(average_confidence.get(group)),
                )
            )
    else:
        lines.append("| none | 0 | 0.0 | 0.0 |")
    lines.extend(["", "## Highest-Risk Examples", ""])
    examples = payload.get("highest_risk_examples_per_group") or {}
    if examples:
        for group in sorted(examples):
            lines.extend([f"### {group}", ""])
            for item in examples.get(group) or []:
                lines.append(
                    "- `{cve}` risk `{risk}` confidence `{confidence}`: {interpretation}".format(
                        cve=item.get("cve_id", ""),
                        risk=item.get("risk_score", ""),
                        confidence=item.get("confidence", ""),
                        interpretation=item.get("interpretation", ""),
                    )
                )
            lines.append("")
    else:
        lines.append("No CVEs matched the diagnostic groups.")
        lines.append("")
    return "\n".join(lines)

def extract_cve_year(cve_id: Any) -> int | None:
    parts = str(cve_id or "").upper().split("-")
    if len(parts) >= 3 and parts[0] == "CVE":
        try:
            year = int(parts[1])
        except ValueError:
            return None
        if 1999 <= year <= 2100:
            return year
    return None

def _legacy_high_risk_groups(row: Mapping[str, Any], cve_year: int | None = None) -> list[str]:
    year = cve_year if cve_year is not None else extract_cve_year(row.get("cve_id"))
    cvss = _safe_float(row.get("cvss_score"))
    risk = _safe_float(row.get("risk_score"))
    recency = _safe_float(row.get("recency_signal"))
    nlp = _safe_float(row.get("nlp_context_signal"))
    accepted_urlhaus = _safe_int(row.get("accepted_urlhaus_count"))
    accepted_dread = _safe_int(row.get("accepted_dread_count"))
    groups: list[str] = []
    if year is not None and year <= 2010 and cvss >= 9.0 and risk >= 7.0:
        groups.append("legacy_high_cvss_high_risk")
    if year is not None and year <= 2010 and cvss == 10.0 and nlp >= 0.8:
        groups.append("legacy_cvss10_high_context")
    if recency <= 0.1 and risk >= 7.0:
        groups.append("low_recency_high_risk")
    if _truthy(row.get("intrinsic_criticality_floor_applied")):
        groups.append("modern_intrinsic_floor")
    if year is not None and year >= 2024 and risk >= 7.0 and accepted_urlhaus == 0 and accepted_dread == 0:
        groups.append("modern_high_risk_no_external_evidence")
    return groups

def _legacy_high_risk_diagnostic_row(row: Mapping[str, Any], cve_year: int | None, group: str) -> dict[str, Any]:
    return {
        "cve_id": row.get("cve_id", ""),
        "cve_year": cve_year if cve_year is not None else "",
        "risk_score": row.get("risk_score", ""),
        "risk_level": row.get("risk_level", ""),
        "confidence": row.get("confidence", ""),
        "cvss_score": row.get("cvss_score", ""),
        "severity_signal": row.get("severity_signal", ""),
        "recency_signal": row.get("recency_signal", ""),
        "nlp_context_signal": row.get("nlp_context_signal", ""),
        "correlation_signal": row.get("correlation_signal", ""),
        "intrinsic_criticality_floor_applied": row.get("intrinsic_criticality_floor_applied", ""),
        "accepted_urlhaus_count": row.get("accepted_urlhaus_count", 0),
        "accepted_dread_count": row.get("accepted_dread_count", 0),
        "coverage_limitations": row.get("coverage_limitations", ""),
        "diagnostic_group": group,
        "interpretation": _legacy_high_risk_interpretation(group),
    }

def _legacy_high_risk_interpretation(group: str) -> str:
    if group == "legacy_high_cvss_high_risk":
        return "Legacy CVE remains high because intrinsic CVSS severity is high; operational interpretation is limited without fresh EPSS, KEV, or accepted external evidence."
    if group == "legacy_cvss10_high_context":
        return "Legacy CVSS 10 CVE also has strong intrinsic NLP context; this is retained technical severity, not evidence of current exploitation."
    if group == "low_recency_high_risk":
        return "Low recency with high risk highlights retained severity and context; review with asset applicability before operational escalation."
    if group == "modern_intrinsic_floor":
        return "Modern CVE received the intrinsic criticality floor; confidence remains separate and external-evidence coverage still limits interpretation."
    if group == "modern_high_risk_no_external_evidence":
        return "Modern high-risk CVE has no accepted URLhaus or Dread evidence in this export; risk is intrinsic and should be read with coverage limitations."
    return "Diagnostic grouping only; this row does not change production scoring."

def build_legacy_dampening_counterfactual(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    counterfactual_rows = [_legacy_dampening_counterfactual_row(row) for row in rows]
    affected_rows = [row for row in counterfactual_rows if _truthy(row.get("dampening_applied"))]
    original_scores = [_safe_float(row.get("risk_score")) for row in affected_rows]
    counterfactual_scores = [_safe_float(row.get("counterfactual_score")) for row in affected_rows]
    top_affected = sorted(
        affected_rows,
        key=lambda item: (
            -_safe_float(item.get("dampening_amount")),
            -_safe_float(item.get("risk_score")),
            str(item.get("cve_id", "")),
        ),
    )[:10]
    return {
        "status": "available",
        "warning": "This is a counterfactual sensitivity artifact only; it does not change production risk_score, confidence, or evidence gates.",
        "affected_record_count": len(affected_rows),
        "average_original_score": round(mean(original_scores), 4) if original_scores else 0.0,
        "average_counterfactual_score": round(mean(counterfactual_scores), 4) if counterfactual_scores else 0.0,
        "risk_bucket_change_count": sum(1 for row in counterfactual_rows if _truthy(row.get("risk_bucket_changed"))),
        "high_medium_low_level_change_count": sum(1 for row in counterfactual_rows if _truthy(row.get("high_medium_low_level_changed"))),
        "top_affected_cves": [
            {
                "cve_id": row.get("cve_id", ""),
                "risk_score": row.get("risk_score", ""),
                "counterfactual_score": row.get("counterfactual_score", ""),
                "dampening_amount": row.get("dampening_amount", ""),
                "interpretation": row.get("interpretation", ""),
            }
            for row in top_affected
        ],
        "material_thesis_conclusion_effect": _legacy_dampening_material_effect(counterfactual_rows),
        "rows": counterfactual_rows,
    }

def render_legacy_dampening_counterfactual_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Legacy Dampening Counterfactual",
        "",
        "This artifact evaluates an illustrative age-aware dampening rule for legacy CVEs.",
        "It is diagnostic only and does not change production `risk_score`, confidence, or URLhaus/Dread evidence gates.",
        "",
        f"- Affected records: `{payload.get('affected_record_count', 0)}`",
        f"- Average original score: `{payload.get('average_original_score', 0.0)}`",
        f"- Average counterfactual score: `{payload.get('average_counterfactual_score', 0.0)}`",
        f"- Risk bucket changes: `{payload.get('risk_bucket_change_count', 0)}`",
        f"- HIGH/MEDIUM/LOW level changes: `{payload.get('high_medium_low_level_change_count', 0)}`",
        f"- Thesis conclusion effect: {payload.get('material_thesis_conclusion_effect', '')}",
        "",
        "## Top Affected CVEs",
        "",
        "| CVE | Original Risk | Counterfactual Risk | Dampening | Interpretation |",
        "| --- | ---: | ---: | ---: | --- |",
    ]
    examples = payload.get("top_affected_cves") or []
    if examples:
        for row in examples:
            lines.append(
                "| {cve} | {risk} | {counterfactual} | {amount} | {interpretation} |".format(
                    cve=row.get("cve_id", ""),
                    risk=row.get("risk_score", ""),
                    counterfactual=row.get("counterfactual_score", ""),
                    amount=row.get("dampening_amount", ""),
                    interpretation=row.get("interpretation", ""),
                )
            )
    else:
        lines.append("| none | 0.0 | 0.0 | 0.0 | No rows met the counterfactual dampening rule. |")
    lines.append("")
    return "\n".join(lines)

def _legacy_dampening_counterfactual_row(row: Mapping[str, Any]) -> dict[str, Any]:
    cve_year = extract_cve_year(row.get("cve_id"))
    original = round(_safe_float(row.get("risk_score")), 4)
    counterfactual = _legacy_dampened_score(row, cve_year)
    original_bucket = _risk_bucket(original)
    counterfactual_bucket = _risk_bucket(counterfactual)
    original_level = _high_medium_low_level(original)
    counterfactual_level = _high_medium_low_level(counterfactual)
    dampening_amount = round(max(original - counterfactual, 0.0), 4)
    applied = dampening_amount > 0
    return {
        "cve_id": row.get("cve_id", ""),
        "cve_year": cve_year if cve_year is not None else "",
        "risk_score": original,
        "counterfactual_score": counterfactual,
        "risk_bucket": original_bucket,
        "counterfactual_risk_bucket": counterfactual_bucket,
        "high_medium_low_level": original_level,
        "counterfactual_high_medium_low_level": counterfactual_level,
        "risk_bucket_changed": original_bucket != counterfactual_bucket,
        "high_medium_low_level_changed": original_level != counterfactual_level,
        "cvss_score": row.get("cvss_score", ""),
        "recency_signal": row.get("recency_signal", ""),
        "epss_signal": row.get("epss_signal", ""),
        "kev_listed": row.get("kev_listed", ""),
        "accepted_urlhaus_count": row.get("accepted_urlhaus_count", 0),
        "accepted_dread_count": row.get("accepted_dread_count", 0),
        "dampening_applied": applied,
        "dampening_amount": dampening_amount,
        "counterfactual_floor": _legacy_dampening_floor(_safe_float(row.get("cvss_score"))) if applied else "",
        "interpretation": _legacy_dampening_interpretation(applied),
    }

def _legacy_dampened_score(row: Mapping[str, Any], cve_year: int | None = None) -> float:
    original = _safe_float(row.get("risk_score"))
    if not _legacy_dampening_applies(row, cve_year):
        return round(original, 4)
    floor_value = _legacy_dampening_floor(_safe_float(row.get("cvss_score")))
    return round(max(original - 0.6, floor_value, 0.0), 4)

def _legacy_dampening_applies(row: Mapping[str, Any], cve_year: int | None = None) -> bool:
    year = cve_year if cve_year is not None else extract_cve_year(row.get("cve_id"))
    if year is None or year > 2010:
        return False
    return (
        _safe_float(row.get("recency_signal")) <= 0.1
        and _safe_int(row.get("accepted_urlhaus_count")) == 0
        and _safe_int(row.get("accepted_dread_count")) == 0
        and not _truthy(row.get("kev_listed"))
        and _safe_float(row.get("epss_signal")) == 0.0
    )

def _legacy_dampening_floor(cvss_score: float) -> float:
    if cvss_score >= 10.0:
        return 6.8
    if cvss_score >= 9.0:
        return 6.5
    return 0.0

def _high_medium_low_level(score: float) -> str:
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"

def _legacy_dampening_interpretation(applied: bool) -> str:
    if applied:
        return "Illustrative age-aware dampening applied because the legacy CVE has low recency and no EPSS, KEV, URLhaus, or Dread support in this export."
    return "Production score retained in the counterfactual because the CVE is modern or has recency/external evidence conditions outside the diagnostic rule."

def _legacy_dampening_material_effect(rows: Sequence[Mapping[str, Any]]) -> str:
    if not rows:
        return "No rows were available, so thesis conclusions cannot be assessed from this artifact."
    changed = sum(1 for row in rows if _truthy(row.get("high_medium_low_level_changed")))
    affected = sum(1 for row in rows if _truthy(row.get("dampening_applied")))
    if affected == 0:
        return "No rows meet the illustrative rule; thesis conclusions are unchanged by this counterfactual."
    if changed == 0:
        return "The rule changes some scores but does not change HIGH/MEDIUM/LOW levels; thesis conclusions are not materially altered."
    return "The rule changes some HIGH/MEDIUM/LOW levels; this supports treating age-aware dampening as future work requiring stronger labels or asset context."

def _table_proxy_label_distribution(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy, counts in (report.get("proxy_label_class_counts") or {}).items():
        for label, count in counts.items():
            rows.append({"strategy": strategy, "label": label, "count": count})
    return rows or [{"strategy": "unavailable", "label": "unavailable", "count": 0}]

def _table_baseline_metrics(metrics: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy, payload in (metrics.get("strategies") or {}).items():
        rows.append(
            {
                "strategy": strategy,
                "status": payload.get("status", ""),
                "precision_at_10": (payload.get("precision_at_k") or {}).get("10"),
                "recall_at_50": (payload.get("recall_at_k") or {}).get("50"),
                "ndcg_at_50": (payload.get("ndcg_at_k") or {}).get("50"),
            }
        )
    return rows or [{"strategy": "unavailable", "status": "unavailable", "precision_at_10": "", "recall_at_50": "", "ndcg_at_50": ""}]

def _table_model_metrics(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for strategy, payload in (report.get("strategies") or {}).items():
        metrics = payload.get("metrics") or {}
        rows.append(
            {
                "strategy": strategy,
                "status": payload.get("status", ""),
                "balanced_accuracy": metrics.get("balanced_accuracy", ""),
                "f1": metrics.get("f1", ""),
            }
        )
    return rows or [{"strategy": "unavailable", "status": report.get("status", "unavailable"), "balanced_accuracy": "", "f1": ""}]

def _table_ablation_summary(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        name = str(row.get("ablation", ""))
        if name in seen:
            continue
        seen.add(name)
        output.append({"ablation": name, "status": row.get("status", ""), "interpretation": row.get("interpretation", "")})
    return output or [{"ablation": "unavailable", "status": "unavailable", "interpretation": ""}]

def _best_probability_by_cve(prediction_rows: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    probabilities: dict[str, float] = {}
    for row in prediction_rows:
        cve_id = str(row.get("cve_id", ""))
        value = _safe_float(row.get("learned_probability"))
        if cve_id and (cve_id not in probabilities or value > probabilities[cve_id]):
            probabilities[cve_id] = value
    return probabilities

def _case_study_row(
    row: Mapping[str, Any],
    proxy_label: str,
    probability: float | None,
    group: str,
    reason: str,
) -> dict[str, Any]:
    return {
        "cve_id": row.get("cve_id", ""),
        "cvss_score": row.get("cvss_score", ""),
        "risk_score": row.get("risk_score", ""),
        "confidence": row.get("confidence", ""),
        "proxy_label": proxy_label,
        "learned_probability": "" if probability is None else round(probability, 6),
        "coverage_limitations": row.get("coverage_limitations", ""),
        "key_reason": reason,
        "case_group": group,
    }
