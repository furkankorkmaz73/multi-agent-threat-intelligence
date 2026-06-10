from __future__ import annotations

import argparse
import csv
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from evaluation.datasets import safe_float
from evaluation.runner import write_report_json


REPORTING_VERSION = "thesis-reporting-v1"
DEFAULT_OBJECTIVE_DIR = Path("~/thesis-artifacts/objective-evaluation").expanduser()
DEFAULT_BALANCED_DIR = Path("~/thesis-artifacts/balanced-benchmark/balanced").expanduser()
DEFAULT_CORRELATION_DIR = Path("~/thesis-artifacts/correlation-benchmark/out").expanduser()
DEFAULT_OUTPUT_DIR = Path("~/thesis-artifacts/thesis-reporting").expanduser()

REQUIRED_CHARTS = (
    "chart_model_vs_cvss_scatter",
    "chart_model_vs_epss_scatter",
    "chart_precision_at_k_comparison",
    "chart_ndcg_at_k_comparison",
    "chart_correlation_confusion_matrix",
    "chart_risk_delta_urlhaus",
    "chart_confidence_delta_urlhaus",
    "chart_operational_risk_by_applicability",
    "chart_operational_risk_by_exposure",
    "chart_operational_risk_by_patch_state",
    "chart_operational_risk_by_criticality",
)

CASE_KEYS = {
    "high_severity_low_exploitation_priority": "High severity / low exploitation priority",
    "correlation_driven_uplift_case": "Correlation-driven uplift",
    "old_but_still_actively_exploited_case": "Old but still actively exploited",
    "high_exploitation_priority_low_operational_risk": "High source risk / low operational risk",
    "moderate_severity_high_operational_risk_due_to_asset_context": "Moderate severity / high operational risk",
    "strongest_severity_disagreement": "Strongest model-vs-CVSS disagreement",
    "strongest_model_vs_epss_disagreement": "Strongest model-vs-EPSS disagreement",
}


@dataclass(frozen=True)
class ReportingInputs:
    objective_dir: Path
    balanced_dir: Path
    correlation_dir: Path


def run_thesis_reporting(
    *,
    objective_dir: str | Path = DEFAULT_OBJECTIVE_DIR,
    balanced_dir: str | Path = DEFAULT_BALANCED_DIR,
    correlation_dir: str | Path = DEFAULT_CORRELATION_DIR,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    generated_at: str | None = None,
    include_svg: bool = False,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    inputs = ReportingInputs(Path(objective_dir).expanduser(), Path(balanced_dir).expanduser(), Path(correlation_dir).expanduser())
    artifacts = load_reporting_inputs(inputs)
    output = Path(output_dir).expanduser()
    output.mkdir(parents=True, exist_ok=True)
    (output / "charts").mkdir(exist_ok=True)
    (output / "cases").mkdir(exist_ok=True)

    tables = write_tables(artifacts, output)
    charts = write_charts(artifacts, output / "charts", include_svg=include_svg)
    cases = write_case_studies(artifacts, output)
    findings = build_thesis_findings(artifacts)
    write_report_json(findings, output / "thesis_findings.json")
    manifest = build_reporting_manifest(
        inputs=inputs,
        output_dir=output,
        artifacts=artifacts,
        generated_at=generated,
        tables=tables,
        charts=charts,
        cases=cases,
    )
    write_report_json(manifest, output / "reporting_manifest.json")
    return _stable(
        {
            "generated_at": generated,
            "output_dir": str(output),
            "tables": tables,
            "charts": charts,
            "case_studies": cases,
            "manifest": manifest,
            "thesis_findings": findings,
        }
    )


def load_reporting_inputs(inputs: ReportingInputs) -> dict[str, Any]:
    files = {
        "objective_comparison": inputs.objective_dir / "objective_comparison.csv",
        "objective_metrics": inputs.objective_dir / "objective_metrics.csv",
        "evaluation_objectives": inputs.objective_dir / "evaluation_objectives.json",
        "severity": inputs.objective_dir / "severity_evaluation.json",
        "exploitation": inputs.objective_dir / "exploitation_priority_evaluation.json",
        "operational": inputs.objective_dir / "operational_risk_evaluation.json",
        "objective_cases": inputs.objective_dir / "objective_case_candidates.json",
        "thesis_summary": inputs.objective_dir / "thesis_results_summary.json",
        "balanced_records": inputs.balanced_dir / "benchmark_records.csv",
        "balanced_summary": inputs.balanced_dir / "benchmark_summary.json",
        "balanced_cases": inputs.balanced_dir / "case_candidates.json",
        "balanced_diagnostics": inputs.balanced_dir / "benchmark_diagnostics.json",
        "correlation_evaluation": inputs.correlation_dir / "correlation_evaluation.json",
        "correlation_records": inputs.correlation_dir / "correlation_records.csv",
        "correlation_cases": inputs.correlation_dir / "correlation_case_candidates.json",
        "paired_results": inputs.correlation_dir / "paired_model_results.json",
    }
    missing = [str(path) for path in files.values() if not path.exists()]
    if missing:
        raise FileNotFoundError("Required thesis-reporting input artifact(s) are missing: " + ", ".join(sorted(missing)))
    loaded = {
        "files": files,
        "hashes": {name: _sha256(path) for name, path in files.items()},
        "objective_comparison": _read_csv(files["objective_comparison"]),
        "objective_metrics": _read_csv(files["objective_metrics"]),
        "evaluation_objectives": _read_json(files["evaluation_objectives"]),
        "severity": _read_json(files["severity"]),
        "exploitation": _read_json(files["exploitation"]),
        "operational": _read_json(files["operational"]),
        "objective_cases": _read_json(files["objective_cases"]),
        "thesis_summary": _read_json(files["thesis_summary"]),
        "balanced_records": _read_csv(files["balanced_records"]),
        "balanced_summary": _read_json(files["balanced_summary"]),
        "balanced_cases": _read_json(files["balanced_cases"]),
        "balanced_diagnostics": _read_json(files["balanced_diagnostics"]),
        "correlation_evaluation": _read_json(files["correlation_evaluation"]),
        "correlation_records": _read_csv(files["correlation_records"]),
        "correlation_cases": _read_json(files["correlation_cases"]),
        "paired_results": _read_json(files["paired_results"]),
    }
    return loaded


def write_tables(artifacts: Mapping[str, Any], output: Path) -> dict[str, str]:
    tables: dict[str, str] = {}
    objective_rows = list(artifacts["objective_comparison"])
    tables["objective_comparison_csv"] = _write_table_csv(objective_rows, output / "table_objective_comparison.csv")
    tables["objective_comparison_md"] = _write_markdown_table(objective_rows, output / "table_objective_comparison.md")

    severity_rows = _severity_table_rows(artifacts["severity"])
    tables["severity_results_csv"] = _write_table_csv(severity_rows, output / "table_severity_results.csv")

    exploitation_rows = _exploitation_table_rows(artifacts["exploitation"])
    tables["exploitation_results_csv"] = _write_table_csv(exploitation_rows, output / "table_exploitation_results.csv")

    correlation_rows = _correlation_table_rows(artifacts["correlation_evaluation"])
    tables["correlation_results_csv"] = _write_table_csv(correlation_rows, output / "table_correlation_results.csv")

    operational_rows = _operational_table_rows(artifacts["operational"])
    tables["operational_risk_results_csv"] = _write_table_csv(operational_rows, output / "table_operational_risk_results.csv")

    case_rows = _case_summary_rows(artifacts)
    tables["case_studies_csv"] = _write_table_csv(case_rows, output / "table_case_studies.csv")
    tables["validity_limitations_md"] = _write_limitations_markdown(artifacts, output / "table_validity_limitations.md")
    return tables


def write_charts(artifacts: Mapping[str, Any], output: Path, *, include_svg: bool = False) -> dict[str, Any]:
    chart_paths: dict[str, Any] = {}
    records = artifacts["balanced_records"]
    paired = list((artifacts["paired_results"].get("records") or []))
    exploitation = artifacts["exploitation"]
    operational = artifacts["operational"]
    correlation = artifacts["correlation_evaluation"]

    chart_paths["model_vs_cvss_scatter"] = _scatter_chart(
        records,
        x_key="cvss_score",
        y_key="model_risk_score",
        title=f"Model Risk vs CVSS (n={len(records)})",
        xlabel="CVSS score",
        ylabel="Model risk score",
        path=output / "chart_model_vs_cvss_scatter.png",
        include_svg=include_svg,
    )
    chart_paths["model_vs_epss_scatter"] = _scatter_chart(
        [row for row in records if _has_number(row.get("epss_score"))],
        x_key="epss_score",
        y_key="model_risk_score",
        title="Model Risk vs EPSS",
        xlabel="EPSS probability",
        ylabel="Model risk score",
        path=output / "chart_model_vs_epss_scatter.png",
        include_svg=include_svg,
    )
    chart_paths["precision_at_k_comparison"] = _metric_line_chart(
        exploitation,
        metric_prefix="precision_at_",
        title="Precision@K by Ranking Strategy",
        ylabel="Precision",
        path=output / "chart_precision_at_k_comparison.png",
        include_svg=include_svg,
    )
    chart_paths["ndcg_at_k_comparison"] = _metric_line_chart(
        exploitation,
        metric_prefix="ndcg_at_",
        title="NDCG@K by Ranking Strategy",
        ylabel="NDCG",
        path=output / "chart_ndcg_at_k_comparison.png",
        include_svg=include_svg,
    )
    chart_paths["correlation_confusion_matrix"] = _confusion_matrix_chart(
        correlation,
        path=output / "chart_correlation_confusion_matrix.png",
        include_svg=include_svg,
    )
    chart_paths["risk_delta_urlhaus"] = _delta_bar_chart(
        paired,
        value_key="risk_score_delta",
        title="CVE-only vs URLhaus-enabled Risk Delta",
        ylabel="Risk score delta",
        path=output / "chart_risk_delta_urlhaus.png",
        include_svg=include_svg,
    )
    chart_paths["confidence_delta_urlhaus"] = _delta_bar_chart(
        paired,
        value_key="confidence_delta",
        title="CVE-only vs URLhaus-enabled Confidence Delta",
        ylabel="Confidence delta",
        path=output / "chart_confidence_delta_urlhaus.png",
        include_svg=include_svg,
    )
    for dimension, filename, title in (
        ("applicability", "chart_operational_risk_by_applicability.png", "Operational Risk by Applicability"),
        ("exposure", "chart_operational_risk_by_exposure.png", "Operational Risk by Exposure"),
        ("patch_state", "chart_operational_risk_by_patch_state.png", "Operational Risk by Patch State"),
        ("criticality", "chart_operational_risk_by_criticality.png", "Operational Risk by Asset Criticality"),
    ):
        chart_paths[f"operational_risk_by_{dimension}"] = _operational_group_chart(
            operational,
            dimension,
            title=title,
            path=output / filename,
            include_svg=include_svg,
        )
    return chart_paths


def write_case_studies(artifacts: Mapping[str, Any], output: Path) -> dict[str, Any]:
    cases_dir = output / "cases"
    cases_dir.mkdir(exist_ok=True)
    case_studies = build_case_studies(artifacts)
    available = [case for case in case_studies if case["available"]]
    unavailable = [case for case in case_studies if not case["available"]]
    for case in available:
        write_report_json(case, cases_dir / f"{case['case_key']}.json")
    write_report_json({"cases": case_studies}, output / "case_studies.json")
    (output / "case_study_summary.md").write_text(_case_summary_markdown(case_studies), encoding="utf-8")
    return {
        "case_studies_json": str(output / "case_studies.json"),
        "case_study_summary_md": str(output / "case_study_summary.md"),
        "cases_dir": str(cases_dir),
        "available": [case["case_key"] for case in available],
        "unavailable": [case["case_key"] for case in unavailable],
    }


def build_case_studies(artifacts: Mapping[str, Any]) -> list[dict[str, Any]]:
    objective_cases = dict(artifacts["objective_cases"])
    objective_cases["strongest_model_vs_epss_disagreement"] = artifacts["balanced_cases"].get("strongest_model_vs_epss_disagreement")
    balanced_by_cve = {row["cve_id"]: row for row in artifacts["balanced_records"]}
    correlation_by_cve = {row["cve_id"]: row for row in artifacts["correlation_records"]}
    paired_by_cve = {row["cve_id"]: row for row in artifacts["paired_results"].get("records", [])}
    rankings = _ranking_positions(artifacts["balanced_summary"])
    studies = []
    for key, title in CASE_KEYS.items():
        raw = objective_cases.get(key)
        if not isinstance(raw, Mapping) or raw.get("available") is False:
            studies.append(_unavailable_case(key, title, raw))
            continue
        cve_id = raw.get("cve_id") or raw.get("source_identifier")
        if not cve_id:
            studies.append(_unavailable_case(key, title, {"reason": "Selected artifact did not include a CVE identifier."}))
            continue
        balanced = dict(balanced_by_cve.get(cve_id) or {})
        correlation = dict(correlation_by_cve.get(cve_id) or {})
        paired = dict(paired_by_cve.get(cve_id) or {})
        study = {
            "available": True,
            "case_key": key,
            "title": title,
            "cve_id": cve_id,
            "asset_id": raw.get("asset_id"),
            "scores": {
                "cvss_score": _first_number(raw, balanced, "cvss_score"),
                "epss_score": _first_number(raw, balanced, "epss_score"),
                "model_risk_score": _first_number(raw, balanced, "model_risk_score"),
                "source_risk_score": raw.get("source_risk_score"),
                "final_operational_risk_score": raw.get("final_operational_risk_score"),
                "risk_score_delta": raw.get("risk_score_delta", paired.get("risk_score_delta")),
                "confidence_delta": paired.get("confidence_delta"),
            },
            "benchmark_labels": {
                "bucket": balanced.get("bucket"),
                "is_kev": balanced.get("is_kev"),
                "correlation_label": correlation.get("label"),
                "predicted_correlation_status": correlation.get("predicted_status"),
            },
            "ranking_positions": rankings.get(cve_id, {}),
            "evidence_summary": {
                "related_urlhaus_count": paired.get("evidence_related_urlhaus_count", paired.get("baseline_related_urlhaus_count")),
                "related_dread_count": paired.get("evidence_related_dread_count", paired.get("baseline_related_dread_count")),
                "accepted_count": correlation.get("accepted_count"),
                "manual_review_count": correlation.get("manual_review_count"),
                "rejected_count": correlation.get("rejected_count"),
            },
            "correlation_result": correlation or None,
            "asset_context": _asset_context(raw),
            "why_selected": title,
            "limitations": _case_limitations(key, artifacts),
            "source_artifact_references": _source_references(artifacts, cve_id),
            "raw_selected_case": dict(raw),
        }
        studies.append(study)
    return studies


def build_reporting_manifest(
    *,
    inputs: ReportingInputs,
    output_dir: Path,
    artifacts: Mapping[str, Any],
    generated_at: str,
    tables: Mapping[str, str],
    charts: Mapping[str, Any],
    cases: Mapping[str, Any],
) -> dict[str, Any]:
    output_paths = [str(path) for path in tables.values()]
    for chart in charts.values():
        output_paths.append(chart["png"])
        if chart.get("svg"):
            output_paths.append(chart["svg"])
    output_paths.extend([cases["case_studies_json"], cases["case_study_summary_md"]])
    output_paths.extend(str(path) for path in sorted((output_dir / "cases").glob("*.json")))
    output_paths.extend([str(output_dir / "reporting_manifest.json"), str(output_dir / "thesis_findings.json")])
    return {
        "reporting_version": REPORTING_VERSION,
        "generated_at": generated_at,
        "input_artifact_paths": {
            "objective_dir": str(inputs.objective_dir),
            "balanced_dir": str(inputs.balanced_dir),
            "correlation_dir": str(inputs.correlation_dir),
        },
        "input_hashes": artifacts["hashes"],
        "generated_output_paths": sorted(output_paths),
        "table_count": len(tables),
        "chart_count": len(charts),
        "case_study_count": len(cases.get("available", [])),
        "unavailable_cases": list(cases.get("unavailable", [])),
        "data_source_limitations": list(artifacts["thesis_summary"].get("limitations") or []),
    }


def build_thesis_findings(artifacts: Mapping[str, Any]) -> dict[str, Any]:
    severity = artifacts["severity"]
    exploitation = artifacts["exploitation"]
    operational = artifacts["operational"]
    correlation = artifacts["correlation_evaluation"]
    model_metrics = exploitation.get("balanced_benchmark", {}).get("model_risk", {}).get("metrics", {})
    epss_metrics = exploitation.get("balanced_benchmark", {}).get("epss_only", {}).get("metrics", {})
    cvss_metrics = exploitation.get("balanced_benchmark", {}).get("cvss_only", {}).get("metrics", {})
    return {
        "reporting_version": REPORTING_VERSION,
        "supported_findings_only": True,
        "statistical_significance_claimed": False,
        "severity_reference": {
            "spearman_model_vs_cvss": severity.get("metrics", {}).get("spearman_model_vs_cvss"),
            "mean_absolute_score_delta": severity.get("metrics", {}).get("mean_absolute_score_delta"),
            "interpretation": "CVSS is used as a technical-severity reference, not ground truth.",
        },
        "exploitation_priority": {
            "model_precision_at_10": model_metrics.get("precision_at_10"),
            "epss_precision_at_10": epss_metrics.get("precision_at_10"),
            "cvss_precision_at_10": cvss_metrics.get("precision_at_10"),
            "model_ndcg_at_10": model_metrics.get("ndcg_at_10"),
            "epss_ndcg_at_10": epss_metrics.get("ndcg_at_10"),
            "negative_results_visible": True,
        },
        "urlhaus_exact_correlation": {
            "precision": correlation.get("precision"),
            "recall": correlation.get("recall"),
            "f1": correlation.get("f1"),
            "included_ground_truth_count": correlation.get("included_ground_truth_count"),
            "unknown_excluded_count": correlation.get("unknown_excluded_count"),
        },
        "operational_risk_fixture": {
            "fixture_derived": bool(operational.get("fixture_derived")),
            "applicable_mean": _nested(operational, "comparisons", "applicability", "applicable", "mean_final_operational_risk_score"),
            "not_applicable_mean": _nested(operational, "comparisons", "applicability", "not_applicable", "mean_final_operational_risk_score"),
        },
        "limitations": list(artifacts["thesis_summary"].get("limitations") or []),
    }


def _severity_table_rows(severity: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = [
        {"section": "metric", "name": name, "value": value, "cve_id": "", "notes": severity.get("reference", "")}
        for name, value in sorted((severity.get("metrics") or {}).items())
    ]
    for case in severity.get("disagreement_cases", [])[:5]:
        rows.append(
            {
                "section": "disagreement_case",
                "name": case.get("direction"),
                "value": case.get("absolute_delta"),
                "cve_id": case.get("cve_id"),
                "notes": f"CVSS {case.get('cvss_score')} vs model {case.get('model_risk_score')}",
            }
        )
    return rows


def _exploitation_table_rows(exploitation: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for strategy in ("model_risk", "cvss_only", "epss_only", "cvss_epss", "model_confidence_weighted"):
        payload = exploitation.get("balanced_benchmark", {}).get(strategy) or {}
        metrics = payload.get("metrics") or {}
        rows.append(
            {
                "strategy": strategy,
                "precision_at_5": metrics.get("precision_at_5"),
                "precision_at_10": metrics.get("precision_at_10"),
                "precision_at_20": metrics.get("precision_at_20"),
                "recall_at_10": metrics.get("recall_at_10"),
                "ndcg_at_10": metrics.get("ndcg_at_10"),
                "mrr": metrics.get("mrr"),
                "spearman_vs_model_risk": payload.get("spearman_vs_model_risk"),
            }
        )
    rows.append(
        {
            "strategy": "correlation_focused_exact_urlhaus",
            "precision_at_5": "",
            "precision_at_10": (exploitation.get("correlation_focused_subset", {}).get("metrics") or {}).get("precision"),
            "precision_at_20": "",
            "recall_at_10": (exploitation.get("correlation_focused_subset", {}).get("metrics") or {}).get("recall"),
            "ndcg_at_10": "",
            "mrr": "",
            "spearman_vs_model_risk": "",
        }
    )
    return rows


def _correlation_table_rows(correlation: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [
        {"metric": "true_positives", "value": correlation.get("true_positives", 0), "notes": "accepted confirmed positives"},
        {"metric": "false_positives", "value": correlation.get("false_positives", 0), "notes": "accepted confirmed negatives"},
        {"metric": "true_negatives", "value": correlation.get("true_negatives", 0), "notes": "rejected confirmed negatives"},
        {"metric": "false_negatives", "value": correlation.get("false_negatives", 0), "notes": "rejected confirmed positives"},
        {"metric": "manual_review_count", "value": correlation.get("manual_review_count", 0), "notes": "kept separate from accepted"},
        {"metric": "unknown_excluded_count", "value": correlation.get("unknown_excluded_count", 0), "notes": "excluded from precision/recall"},
        {"metric": "precision", "value": correlation.get("precision", 0), "notes": "labeled cases only"},
        {"metric": "recall", "value": correlation.get("recall", 0), "notes": "labeled cases only"},
        {"metric": "f1", "value": correlation.get("f1", 0), "notes": "labeled cases only"},
    ]


def _operational_table_rows(operational: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for dimension, groups in sorted((operational.get("comparisons") or {}).items()):
        for group, values in sorted(groups.items()):
            rows.append({"dimension": dimension, "group": group, **dict(values), "fixture_derived": operational.get("fixture_derived")})
    return rows


def _case_summary_rows(artifacts: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for case in build_case_studies(artifacts):
        rows.append(
            {
                "case_key": case["case_key"],
                "title": case["title"],
                "available": case["available"],
                "cve_id": case.get("cve_id", ""),
                "asset_id": case.get("asset_id", ""),
                "reason": case.get("unavailable_reason", case.get("why_selected", "")),
            }
        )
    return rows


def _write_table_csv(rows: Sequence[Mapping[str, Any]], path: Path) -> str:
    _write_csv(rows, path)
    return str(path)


def _write_markdown_table(rows: Sequence[Mapping[str, Any]], path: Path) -> str:
    path.write_text(_markdown_table(rows), encoding="utf-8")
    return str(path)


def _write_limitations_markdown(artifacts: Mapping[str, Any], path: Path) -> str:
    limitations = list(artifacts["thesis_summary"].get("limitations") or [])
    diagnostics = artifacts["balanced_diagnostics"]
    lines = ["# Validity Limitations", ""]
    for item in limitations:
        lines.append(f"- {item}")
    for warning in diagnostics.get("warnings", []):
        lines.append(f"- Balanced benchmark warning: {warning}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _scatter_chart(
    rows: Sequence[Mapping[str, Any]],
    *,
    x_key: str,
    y_key: str,
    title: str,
    xlabel: str,
    ylabel: str,
    path: Path,
    include_svg: bool,
) -> dict[str, Any]:
    points = [(safe_float(row.get(x_key)), safe_float(row.get(y_key))) for row in rows if _has_number(row.get(x_key)) and _has_number(row.get(y_key))]
    fig, ax = plt.subplots(figsize=(6.5, 4.5), dpi=200)
    if points:
        x, y = zip(*points)
        ax.scatter(x, y, s=32, alpha=0.75, edgecolors="black", linewidths=0.4)
        _pad_axis(ax, x, axis="x")
        _pad_axis(ax, y, axis="y")
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.grid(True, alpha=0.25)
    return _save_chart(fig, path, include_svg=include_svg, source_rows=len(points))


def _metric_line_chart(
    exploitation: Mapping[str, Any],
    *,
    metric_prefix: str,
    title: str,
    ylabel: str,
    path: Path,
    include_svg: bool,
) -> dict[str, Any]:
    strategies = ("model_risk", "cvss_only", "epss_only", "cvss_epss", "model_confidence_weighted")
    fig, ax = plt.subplots(figsize=(7, 4.5), dpi=200)
    plotted = 0
    for strategy in strategies:
        metrics = ((exploitation.get("balanced_benchmark") or {}).get(strategy) or {}).get("metrics") or {}
        points = sorted(
            (int(name.removeprefix(metric_prefix)), safe_float(value))
            for name, value in metrics.items()
            if name.startswith(metric_prefix) and str(name.removeprefix(metric_prefix)).isdigit()
        )
        if not points:
            continue
        plotted += 1
        x, y = zip(*points)
        ax.plot(x, y, marker="o", linewidth=1.8, label=strategy)
    ax.set_title(title)
    ax.set_xlabel("K")
    ax.set_ylabel(ylabel)
    ax.grid(True, alpha=0.25)
    if plotted:
        ax.legend(fontsize=8)
    return _save_chart(fig, path, include_svg=include_svg, source_rows=plotted)


def _confusion_matrix_chart(correlation: Mapping[str, Any], *, path: Path, include_svg: bool) -> dict[str, Any]:
    matrix = [
        [safe_float(correlation.get("true_positives")), safe_float(correlation.get("false_negatives"))],
        [safe_float(correlation.get("false_positives")), safe_float(correlation.get("true_negatives"))],
    ]
    fig, ax = plt.subplots(figsize=(5.2, 4.6), dpi=200)
    image = ax.imshow(matrix, cmap="Blues")
    ax.set_title("Correlation Confusion Matrix")
    ax.set_xticks([0, 1], labels=["Predicted accepted", "Predicted rejected"], rotation=20, ha="right")
    ax.set_yticks([0, 1], labels=["Positive label", "Negative label"])
    for y, row in enumerate(matrix):
        for x, value in enumerate(row):
            ax.text(x, y, str(int(value)), ha="center", va="center", color="black")
    fig.colorbar(image, ax=ax, fraction=0.046, pad=0.04)
    return _save_chart(fig, path, include_svg=include_svg, source_rows=4)


def _delta_bar_chart(
    rows: Sequence[Mapping[str, Any]],
    *,
    value_key: str,
    title: str,
    ylabel: str,
    path: Path,
    include_svg: bool,
) -> dict[str, Any]:
    ranked = sorted(rows, key=lambda row: (-abs(safe_float(row.get(value_key))), str(row.get("cve_id"))))
    labels = [str(row.get("cve_id")) for row in ranked]
    values = [safe_float(row.get(value_key)) for row in ranked]
    fig, ax = plt.subplots(figsize=(8, 4.8), dpi=200)
    ax.bar(range(len(values)), values, color="#4c78a8")
    ax.set_title(f"{title} (n={len(values)})")
    ax.set_xlabel("CVE")
    ax.set_ylabel(ylabel)
    ax.set_xticks(range(len(labels)), labels=labels, rotation=80, ha="right", fontsize=7)
    ax.axhline(0, color="black", linewidth=0.8)
    ax.grid(True, axis="y", alpha=0.25)
    return _save_chart(fig, path, include_svg=include_svg, source_rows=len(values))


def _operational_group_chart(
    operational: Mapping[str, Any],
    dimension: str,
    *,
    title: str,
    path: Path,
    include_svg: bool,
) -> dict[str, Any]:
    groups = dict((operational.get("comparisons") or {}).get(dimension) or {})
    labels = list(groups)
    values = [safe_float(groups[label].get("mean_final_operational_risk_score")) for label in labels]
    counts = [groups[label].get("count") for label in labels]
    fig, ax = plt.subplots(figsize=(6, 4.2), dpi=200)
    ax.bar(range(len(values)), values, color="#59a14f")
    ax.set_title(title)
    ax.set_xlabel(dimension.replace("_", " ").title())
    ax.set_ylabel("Mean final operational risk")
    ax.set_xticks(range(len(labels)), labels=[f"{label}\n(n={count})" for label, count in zip(labels, counts)])
    ax.grid(True, axis="y", alpha=0.25)
    return _save_chart(fig, path, include_svg=include_svg, source_rows=len(values))


def _save_chart(fig: Any, path: Path, *, include_svg: bool, source_rows: int) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    svg_path = None
    if include_svg:
        svg_path = path.with_suffix(".svg")
        fig.savefig(svg_path)
    width, height = fig.get_size_inches()
    plt.close(fig)
    return {
        "png": str(path),
        "svg": str(svg_path) if svg_path else None,
        "width_px": int(width * 200),
        "height_px": int(height * 200),
        "source_rows": source_rows,
    }


def _pad_axis(ax: Any, values: Sequence[float], *, axis: str) -> None:
    low = min(values)
    high = max(values)
    padding = (high - low) * 0.08 if high != low else max(abs(high) * 0.08, 0.1)
    if axis == "x":
        ax.set_xlim(low - padding, high + padding)
    else:
        ax.set_ylim(low - padding, high + padding)


def _ranking_positions(summary: Mapping[str, Any]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for strategy, payload in (summary.get("baselines") or {}).items():
        for index, cve_id in enumerate(payload.get("ranking") or [], start=1):
            result.setdefault(cve_id, {})[strategy] = index
    return result


def _asset_context(raw: Mapping[str, Any]) -> dict[str, Any] | None:
    if not raw.get("asset_id"):
        return None
    return {
        "asset_id": raw.get("asset_id"),
        "applicability_status": _nested(raw, "applicability", "status"),
        "criticality": _nested(raw, "component_breakdown", "criticality"),
        "exposure": _nested(raw, "component_breakdown", "exposure"),
        "patch_state": _nested(raw, "component_breakdown", "patch_state"),
        "final_operational_risk_score": raw.get("final_operational_risk_score"),
    }


def _case_limitations(key: str, artifacts: Mapping[str, Any]) -> list[str]:
    limitations = []
    if key in {"high_exploitation_priority_low_operational_risk", "moderate_severity_high_operational_risk_due_to_asset_context"}:
        limitations.append("Operational-risk case is fixture-derived unless a real operational report was supplied.")
    if key == "correlation_driven_uplift_case":
        limitations.append("URLhaus exact-correlation benchmark is a small focused subset.")
    limitations.extend(artifacts["thesis_summary"].get("limitations") or [])
    return list(dict.fromkeys(limitations))


def _source_references(artifacts: Mapping[str, Any], cve_id: Any) -> dict[str, str]:
    references = {
        name: str(path)
        for name, path in artifacts["files"].items()
        if name
        in {
            "severity",
            "exploitation",
            "operational",
            "objective_cases",
            "balanced_records",
            "balanced_summary",
            "correlation_records",
            "paired_results",
        }
    }
    references["cve_id"] = str(cve_id)
    return references


def _unavailable_case(key: str, title: str, raw: Any) -> dict[str, Any]:
    reason = "No matching supplied case was available; no case was fabricated."
    if isinstance(raw, Mapping):
        reason = str(raw.get("reason") or reason)
    return {
        "available": False,
        "case_key": key,
        "title": title,
        "unavailable_reason": reason,
    }


def _first_number(primary: Mapping[str, Any], secondary: Mapping[str, Any], key: str) -> float | None:
    if _has_number(primary.get(key)):
        return safe_float(primary.get(key))
    if _has_number(secondary.get(key)):
        return safe_float(secondary.get(key))
    return None


def _case_summary_markdown(cases: Sequence[Mapping[str, Any]]) -> str:
    lines = ["# Case Study Summary", ""]
    for case in cases:
        if not case.get("available"):
            lines.append(f"- {case['title']}: unavailable. {case.get('unavailable_reason')}")
            continue
        scores = case.get("scores") or {}
        lines.append(
            f"- {case['title']}: {case.get('cve_id')} "
            f"(model={scores.get('model_risk_score')}, cvss={scores.get('cvss_score')}, epss={scores.get('epss_score')})."
        )
    return "\n".join(lines) + "\n"


def _markdown_table(rows: Sequence[Mapping[str, Any]]) -> str:
    if not rows:
        return "\n"
    fields = list(rows[0])
    lines = ["| " + " | ".join(fields) + " |", "| " + " | ".join("---" for _ in fields) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(_markdown_escape(row.get(field, "")) for field in fields) + " |")
    return "\n".join(lines) + "\n"


def _markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _write_csv(rows: Sequence[Mapping[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = sorted({field for row in rows for field in row})
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: _csv_value(row.get(field)) for field in fields})


def _csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True)
    return value


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def _read_csv(path: Path) -> list[dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return [_coerce_row(row) for row in csv.DictReader(handle)]


def _coerce_row(row: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        if value == "":
            out[key] = None
        elif value in {"True", "False"}:
            out[key] = value == "True"
        elif _has_number(value):
            out[key] = safe_float(value)
        else:
            out[key] = value
    return out


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _has_number(value: Any) -> bool:
    if value is None or value == "":
        return False
    try:
        float(value)
    except (TypeError, ValueError):
        return False
    return True


def _nested(row: Mapping[str, Any], *keys: str) -> Any:
    value: Any = row
    for key in keys:
        if not isinstance(value, Mapping):
            return None
        value = value.get(key)
    return value


def _stable(payload: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(payload, sort_keys=True, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate thesis-ready tables, charts, and case-study artifacts")
    parser.add_argument("--objective-dir", default=str(DEFAULT_OBJECTIVE_DIR), help="Objective evaluation artifact directory")
    parser.add_argument("--balanced-dir", default=str(DEFAULT_BALANCED_DIR), help="Balanced benchmark artifact directory")
    parser.add_argument("--correlation-dir", default=str(DEFAULT_CORRELATION_DIR), help="Correlation benchmark artifact directory")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory for thesis reporting artifacts")
    parser.add_argument("--generated-at", default=None, help="Optional deterministic timestamp")
    parser.add_argument("--svg", action="store_true", help="Also generate SVG chart files")
    args = parser.parse_args()
    report = run_thesis_reporting(
        objective_dir=args.objective_dir,
        balanced_dir=args.balanced_dir,
        correlation_dir=args.correlation_dir,
        output_dir=args.output_dir,
        generated_at=args.generated_at,
        include_svg=args.svg,
    )
    print(
        json.dumps(
            {
                "output_dir": report["output_dir"],
                "table_count": len(report["tables"]),
                "chart_count": len(report["charts"]),
                "case_study_count": len(report["case_studies"]["available"]),
                "unavailable_cases": report["case_studies"]["unavailable"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
