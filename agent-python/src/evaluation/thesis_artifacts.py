from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Mapping, Sequence

from evaluation.balanced_benchmark import build_ablation_report
from evaluation.datasets import EvaluationRecord, safe_float
from evaluation.runner import write_report_json
from evaluation.scoring_sensitivity import build_scoring_sensitivity_report


DEFAULT_SCENARIO_REPORT = Path("reports/thesis/deterministic/thesis_scenario_report.json")
DEFAULT_OUTPUT_DIR = Path("reports/thesis/deterministic")
THESIS_ARTIFACT_VERSION = "thesis-artifacts-v1"
SCORING_DISTRIBUTION_FIELDS = [
    "cve_id",
    "cvss_score",
    "epss_score",
    "is_kev",
    "risk_score",
    "confidence",
    "risk_level",
    "severity_signal",
    "epss_signal",
    "kev_signal",
    "recency_signal",
    "correlation_signal",
    "graph_signal",
    "nlp_context_signal",
    "severity_weighted_contribution",
    "epss_weighted_contribution",
    "kev_weighted_contribution",
    "recency_weighted_contribution",
    "correlation_weighted_contribution",
    "graph_weighted_contribution",
    "nlp_context_weighted_contribution",
    "weighted_signal_score",
    "score_before_intrinsic_floor",
    "intrinsic_criticality_floor_applied",
    "intrinsic_criticality_floor_value",
    "intrinsic_criticality_reason",
    "urlhaus_raw_candidate_count",
    "urlhaus_ignored_low_signal_count",
    "urlhaus_evaluated_candidate_count",
    "urlhaus_signal_candidate_count",
    "urlhaus_accepted_match_count",
    "urlhaus_manual_review_match_count",
    "urlhaus_rejected_match_count",
    "assessment_confidence",
    "data_completeness",
    "uncertainty_penalty",
    "coverage_limitations",
    "fixture_rationale",
]


def _display_path(path: str | Path) -> str:
    candidate = Path(path)
    parts = candidate.parts
    if "reports" in parts:
        report_index = parts.index("reports")
        return Path(*parts[report_index:]).as_posix()
    return str(candidate)


def generate_thesis_artifacts(
    *,
    scenario_report_path: str | Path = DEFAULT_SCENARIO_REPORT,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    scenario_path = Path(scenario_report_path)
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    stale_turkish_results = output / "thesis_results_section_tr.md"
    if stale_turkish_results.exists():
        stale_turkish_results.unlink()

    evaluation = dict(scenario.get("evaluation") or {})
    records = _evaluation_records(evaluation.get("records") or [])

    k_values = evaluation.get("metric_config", {}).get("k_values") or [1, 3, 5, 10]
    if records:
        ablation_report = build_ablation_report(records, k_values=k_values)
    else:
        ablation_report = {
            "supported": {},
            "unsupported": {
                "no_records": {
                    "status": "unsupported",
                    "reason": "No evaluation records available.",
                }
            },
        }

    files = {
        "scoring_summary": output / "scoring_summary.md",
        "scoring_distribution": output / "scoring_distribution.csv",
        "scoring_distribution_md": output / "scoring_distribution.md",
        "scoring_sensitivity": output / "scoring_sensitivity.csv",
        "scoring_sensitivity_md": output / "scoring_sensitivity.md",
        "benchmark_summary": output / "benchmark_summary.csv",
        "benchmark_summary_md": output / "benchmark_summary.md",
        "ablation_summary": output / "ablation_summary.csv",
        "ablation_summary_md": output / "ablation_summary.md",
        "correlation_decisions": output / "correlation_decisions.csv",
        "case_studies": output / "case_studies.json",
        "risk_explanation_traces": output / "risk_explanation_traces.json",
        "risk_explanation_traces_md": output / "risk_explanation_traces.md",
        "demo_walkthrough": output / "demo_walkthrough.md",
        "results_summary": output / "results_summary.md",
        "thesis_results_section": output / "thesis_results_section.md",
        "limitations_and_validity": output / "limitations_and_validity.md",
        "thesis_defense_pack": output / "thesis_defense_pack.md",
        "methodology_summary": output / "methodology_summary.md",
        "manifest": output / "manifest.json",
    }

    files["scoring_summary"].write_text(
        _scoring_summary_markdown(scenario, records),
        encoding="utf-8",
    )
    scoring_distribution_rows = _scoring_distribution_rows(records)
    _write_csv(scoring_distribution_rows, files["scoring_distribution"], SCORING_DISTRIBUTION_FIELDS)
    files["scoring_distribution_md"].write_text(
        _scoring_distribution_markdown(records, scoring_distribution_rows),
        encoding="utf-8",
    )
    sensitivity_report = build_scoring_sensitivity_report(records, k_values=k_values) if records else {"variants": []}
    _write_scoring_sensitivity(sensitivity_report, files["scoring_sensitivity"])
    files["scoring_sensitivity_md"].write_text(
        _scoring_sensitivity_markdown(sensitivity_report),
        encoding="utf-8",
    )
    _write_benchmark_summary(evaluation.get("baselines") or {}, files["benchmark_summary"])
    files["benchmark_summary_md"].write_text(
        _benchmark_summary_markdown(evaluation.get("baselines") or {}, records),
        encoding="utf-8",
    )
    _write_ablation_summary(ablation_report, files["ablation_summary"])
    files["ablation_summary_md"].write_text(
        _ablation_summary_markdown(ablation_report),
        encoding="utf-8",
    )
    _write_correlation_decisions(
        scenario.get("correlation_decisions") or [],
        files["correlation_decisions"],
    )
    write_report_json({"cases": scenario.get("notable_cases") or []}, files["case_studies"])
    explanation_traces = _risk_explanation_traces(scenario, records)
    write_report_json({"traces": explanation_traces}, files["risk_explanation_traces"])
    files["risk_explanation_traces_md"].write_text(
        _risk_explanation_traces_markdown(explanation_traces),
        encoding="utf-8",
    )
    files["demo_walkthrough"].write_text(
        _demo_walkthrough_markdown(
            scenario=scenario,
            records=records,
            baselines=evaluation.get("baselines") or {},
            ablation_report=ablation_report,
        ),
        encoding="utf-8",
    )
    files["results_summary"].write_text(
        _results_summary_markdown(
            scenario=scenario,
            records=records,
            baselines=evaluation.get("baselines") or {},
            ablation_report=ablation_report,
        ),
        encoding="utf-8",
    )
    files["thesis_results_section"].write_text(
        _thesis_results_section_markdown(
            scenario=scenario,
            records=records,
            baselines=evaluation.get("baselines") or {},
            ablation_report=ablation_report,
        ),
        encoding="utf-8",
    )
    files["limitations_and_validity"].write_text(_limitations_and_validity_markdown(), encoding="utf-8")
    files["thesis_defense_pack"].write_text(_thesis_defense_pack_markdown(), encoding="utf-8")
    files["methodology_summary"].write_text(_methodology_summary_markdown(), encoding="utf-8")

    manifest = {
        "version": THESIS_ARTIFACT_VERSION,
        "scenario_report_path": _display_path(scenario_report_path),
        "output_dir": _display_path(output),
        "generated_files": {
            name: _display_path(path)
            for name, path in files.items()
            if name != "manifest"
        },
        "record_count": len(records),
        "correlation_decision_count": len(scenario.get("correlation_decisions") or []),
    }
    write_report_json(manifest, files["manifest"])
    return manifest


def _evaluation_records(rows: Iterable[Mapping[str, Any]]) -> list[EvaluationRecord]:
    records: list[EvaluationRecord] = []
    for row in rows:
        records.append(
            EvaluationRecord(
                cve_id=row["cve_id"],
                model_risk_score=safe_float(row.get("model_risk_score")),
                model_confidence=safe_float(row.get("model_confidence")),
                cvss_score=safe_float(row.get("cvss_score")),
                epss_score=row.get("epss_score"),
                epss_percentile=row.get("epss_percentile"),
                is_kev=bool(row.get("is_kev")),
                exploitation_evidence=row.get("exploitation_evidence") or {},
                feature_breakdown=row.get("feature_breakdown") or {},
            )
        )
    return records


def _scoring_summary_markdown(
    scenario: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
) -> str:
    rows = sorted(records, key=lambda record: (-record.model_risk_score, record.cve_id))

    cvss_rank = {
        record.cve_id: index + 1
        for index, record in enumerate(
            sorted(records, key=lambda record: (-record.cvss_score, record.cve_id))
        )
    }
    model_rank = {
        record.cve_id: index + 1
        for index, record in enumerate(rows)
    }

    disagreements = sorted(
        records,
        key=lambda record: (
            abs(model_rank[record.cve_id] - cvss_rank[record.cve_id]),
            record.cve_id,
        ),
        reverse=True,
    )[:5]

    level_counts: dict[str, int] = {}
    for record in records:
        level = _risk_level(record.model_risk_score)
        level_counts[level] = level_counts.get(level, 0) + 1

    lines = [
        "# Scoring Summary",
        "",
        "This artifact summarizes deterministic CVE risk outputs from the controlled thesis evaluation fixture.",
        "",
        f"- Total CVE count: {len(records)}",
        f"- KEV records: {sum(1 for record in records if record.is_kev)}",
        f"- Records with EPSS: {sum(1 for record in records if record.epss_score is not None)}",
        "- Risk level distribution: "
        + ", ".join(f"{level}={count}" for level, count in sorted(level_counts.items()))
        + ".",
        "",
        "## Top 10 Model-Risk CVEs",
        "",
        _markdown_table(
            [
                "Rank",
                "CVE",
                "Risk",
                "Level",
                "Confidence",
                "CVSS",
                "EPSS",
                "KEV",
                "URLhaus",
                "Dread",
            ],
            [
                [
                    index,
                    record.cve_id,
                    record.model_risk_score,
                    _risk_level(record.model_risk_score),
                    record.model_confidence,
                    record.cvss_score,
                    record.epss_score,
                    record.is_kev,
                    _feature_value(record, "related_urlhaus_count", 0),
                    _feature_value(record, "related_dread_count", 0),
                ]
                for index, record in enumerate(rows[:10], start=1)
            ],
            align=[
                "right",
                "left",
                "right",
                "left",
                "right",
                "right",
                "right",
                "left",
                "right",
                "right",
            ],
        ),
        "",
        "## Model Ranking Differs From CVSS-Only",
        "",
        _markdown_table(
            ["CVE", "Model Rank", "CVSS Rank", "Risk", "CVSS", "EPSS", "KEV", "Rationale"],
            [
                [
                    record.cve_id,
                    model_rank[record.cve_id],
                    cvss_rank[record.cve_id],
                    record.model_risk_score,
                    record.cvss_score,
                    record.epss_score,
                    record.is_kev,
                    _feature_value(record, "fixture_rationale", ""),
                ]
                for record in disagreements
            ],
            align=["left", "right", "right", "right", "right", "right", "left", "left"],
        ),
    ]
    return "\n".join(lines) + "\n"


def _scoring_distribution_rows(records: Sequence[EvaluationRecord]) -> list[dict[str, Any]]:
    rows = []
    for record in sorted(records, key=lambda item: item.cve_id):
        contributions = _feature_value(record, "risk_signal_contributions", {})
        if not isinstance(contributions, Mapping):
            contributions = {}
        evidence = (record.feature_breakdown or {}).get("evidence") or {}
        confidence_breakdown = (record.feature_breakdown or {}).get("confidence_breakdown") or {}
        urlhaus_stats = evidence.get("urlhaus_match_stats") or {}
        rows.append(
            {
                "cve_id": record.cve_id,
                "cvss_score": record.cvss_score,
                "epss_score": record.epss_score,
                "is_kev": record.is_kev,
                "risk_score": record.model_risk_score,
                "confidence": record.model_confidence,
                "risk_level": _risk_level(record.model_risk_score),
                "severity_signal": _feature_value(record, "severity_signal", ""),
                "epss_signal": _feature_value(record, "epss_signal", ""),
                "kev_signal": _feature_value(record, "kev_signal", ""),
                "recency_signal": _feature_value(record, "recency_signal", ""),
                "correlation_signal": _feature_value(record, "correlation_signal", ""),
                "graph_signal": _feature_value(record, "graph_signal", ""),
                "nlp_context_signal": _feature_value(record, "nlp_context_signal", ""),
                "severity_weighted_contribution": contributions.get("severity_signal", ""),
                "epss_weighted_contribution": contributions.get("epss_signal", ""),
                "kev_weighted_contribution": contributions.get("kev_signal", ""),
                "recency_weighted_contribution": contributions.get("recency_signal", ""),
                "correlation_weighted_contribution": contributions.get("correlation_signal", ""),
                "graph_weighted_contribution": contributions.get("graph_signal", ""),
                "nlp_context_weighted_contribution": contributions.get("nlp_context_signal", ""),
                "weighted_signal_score": _feature_value(record, "weighted_signal_score", ""),
                "score_before_intrinsic_floor": _feature_value(record, "score_before_intrinsic_floor", ""),
                "intrinsic_criticality_floor_applied": _feature_value(record, "intrinsic_criticality_floor_applied", ""),
                "intrinsic_criticality_floor_value": _feature_value(record, "intrinsic_criticality_floor_value", ""),
                "intrinsic_criticality_reason": _feature_value(record, "intrinsic_criticality_reason", ""),
                "urlhaus_raw_candidate_count": urlhaus_stats.get("raw_candidate_count", ""),
                "urlhaus_ignored_low_signal_count": urlhaus_stats.get("ignored_low_signal_count", ""),
                "urlhaus_evaluated_candidate_count": urlhaus_stats.get("evaluated_candidate_count", ""),
                "urlhaus_signal_candidate_count": urlhaus_stats.get("signal_candidate_count", ""),
                "urlhaus_accepted_match_count": urlhaus_stats.get("accepted_match_count", ""),
                "urlhaus_manual_review_match_count": urlhaus_stats.get("manual_review_match_count", ""),
                "urlhaus_rejected_match_count": urlhaus_stats.get("rejected_match_count", ""),
                "assessment_confidence": confidence_breakdown.get("assessment_confidence", ""),
                "data_completeness": confidence_breakdown.get("data_completeness", ""),
                "uncertainty_penalty": confidence_breakdown.get("uncertainty_penalty", ""),
                "coverage_limitations": ";".join(confidence_breakdown.get("coverage_limitations") or []),
                "fixture_rationale": _feature_value(record, "fixture_rationale", ""),
            }
        )
    return rows


def _scoring_distribution_markdown(records: Sequence[EvaluationRecord], rows: Sequence[Mapping[str, Any]]) -> str:
    risk_scores = [record.model_risk_score for record in records]
    level_counts: dict[str, int] = {}
    for record in records:
        level = _risk_level(record.model_risk_score)
        level_counts[level] = level_counts.get(level, 0) + 1

    model_ranked = sorted(records, key=lambda record: (-record.model_risk_score, record.cve_id))
    cvss_ranked = sorted(records, key=lambda record: (-record.cvss_score, record.cve_id))
    model_rank = {record.cve_id: index + 1 for index, record in enumerate(model_ranked)}
    cvss_rank = {record.cve_id: index + 1 for index, record in enumerate(cvss_ranked)}
    disagreements = sorted(
        records,
        key=lambda record: (abs(model_rank[record.cve_id] - cvss_rank[record.cve_id]), record.cve_id),
        reverse=True,
    )[:8]

    lines = [
        "# Scoring Distribution Review",
        "",
        f"- Total records: {len(records)}",
        "- Risk level distribution: "
        + ", ".join(f"{level}={count}" for level, count in sorted(level_counts.items()))
        + ".",
        f"- Minimum risk score: {min(risk_scores) if risk_scores else 0.0}",
        f"- Maximum risk score: {max(risk_scores) if risk_scores else 0.0}",
        f"- Mean risk score: {round(mean(risk_scores), 4) if risk_scores else 0.0}",
        "",
        "## Top 10 By Model Risk",
        "",
        _score_rank_table(model_ranked[:10], model_rank=model_rank, cvss_rank=cvss_rank),
        "",
        "## Top 10 By CVSS",
        "",
        _score_rank_table(cvss_ranked[:10], model_rank=model_rank, cvss_rank=cvss_rank),
        "",
        "## Model-Vs-CVSS Ranking Disagreements",
        "",
        _score_rank_table(disagreements, model_rank=model_rank, cvss_rank=cvss_rank),
        "",
        "## Sanity Check Notes",
        "",
        "- High CVSS remains meaningful risk even when EPSS, KEV, and accepted external evidence are weak.",
        "- Weak-confidence high-CVSS controls are not automatically treated as CRITICAL.",
        "- Medium-CVSS records with high EPSS and KEV can outrank high-CVSS records with weak exploitation evidence.",
        "- Accepted correlation, graph context, and recency are visible as bounded signal columns.",
        "- Risk score and confidence are reviewed separately; they should not be interpreted as the same value.",
        f"- CSV rows emitted: {len(rows)}.",
    ]
    return "\n".join(lines) + "\n"


def _risk_explanation_traces(
    scenario: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
) -> list[dict[str, Any]]:
    decisions_by_cve: dict[str, list[Mapping[str, Any]]] = {}
    for decision in scenario.get("correlation_decisions") or []:
        decisions_by_cve.setdefault(str(decision.get("source_identifier")), []).append(decision)

    assets_by_cve: dict[str, list[Mapping[str, Any]]] = {}
    for row in scenario.get("asset_operational_risk") or []:
        assets_by_cve.setdefault(str(row.get("cve_id") or row.get("source_identifier")), []).append(row)

    traces = []
    seen_cves: set[str] = set()
    for record in sorted(records, key=lambda item: item.cve_id):
        seen_cves.add(record.cve_id)
        decisions = sorted(
            decisions_by_cve.get(record.cve_id, []),
            key=lambda item: (_decision_sort_key(str(item.get("status") or item.get("decision"))), str(item.get("target_identifier"))),
        )
        asset_rows = assets_by_cve.get(record.cve_id, [])
        contributors = _risk_contributors(record)
        accepted_count = sum(int(item.get("accepted_evidence_count", 0) or 0) for item in decisions)
        manual_count = sum(int(item.get("manual_review_evidence_count", 0) or 0) for item in decisions)
        rejected_count = sum(int(item.get("rejected_evidence_count", 0) or 0) for item in decisions)
        dread_present = bool(
            _feature_value(record, "related_dread_count", 0)
            or any(item.get("dread_evidence_present") for item in decisions)
        )
        confidence_cap_reason = next(
            (str(item.get("confidence_cap_reason")) for item in decisions if item.get("confidence_cap_reason")),
            "",
        )
        traces.append(
            {
                "cve_id": record.cve_id,
                "cvss_score": record.cvss_score,
                "epss_score": record.epss_score,
                "is_kev": record.is_kev,
                "normalized_signals": {
                    name: _feature_value(record, name, 0.0)
                    for name in (
                        "severity_signal",
                        "epss_signal",
                        "kev_signal",
                        "recency_signal",
                        "correlation_signal",
                        "graph_signal",
                        "nlp_context_signal",
                    )
                },
                "risk_signal_weights": _feature_value(record, "risk_signal_weights", {}),
                "weighted_signal_contributions": _feature_value(record, "risk_signal_contributions", {}),
                "generic_cve_risk_score": record.model_risk_score,
                "confidence": record.model_confidence,
                "risk_level": _risk_level(record.model_risk_score),
                "top_positive_risk_contributors": contributors,
                "top_evidence_decisions": [_decision_trace(item) for item in decisions[:8]],
                "accepted_evidence_count": accepted_count,
                "manual_review_evidence_count": manual_count,
                "rejected_evidence_count": rejected_count,
                "dread_evidence_present": dread_present,
                "confidence_cap_reason": confidence_cap_reason,
                "asset_operational_risk_examples": _asset_examples(asset_rows),
                "explanation": _trace_explanation(record, contributors, accepted_count, manual_count, rejected_count, confidence_cap_reason, asset_rows),
            }
        )
    for row in sorted(scenario.get("source_results") or [], key=lambda item: str(item.get("entity_id"))):
        cve_id = str(row.get("entity_id") or "")
        if not cve_id.startswith("CVE-") or cve_id in seen_cves:
            continue
        decisions = sorted(
            decisions_by_cve.get(cve_id, []),
            key=lambda item: (_decision_sort_key(str(item.get("status") or item.get("decision"))), str(item.get("target_identifier"))),
        )
        asset_rows = assets_by_cve.get(cve_id, [])
        accepted_count = sum(int(item.get("accepted_evidence_count", 0) or 0) for item in decisions)
        manual_count = sum(int(item.get("manual_review_evidence_count", 0) or 0) for item in decisions)
        rejected_count = sum(int(item.get("rejected_evidence_count", 0) or 0) for item in decisions)
        confidence_cap_reason = next(
            (str(item.get("confidence_cap_reason")) for item in decisions if item.get("confidence_cap_reason")),
            "",
        )
        traces.append(
            {
                "cve_id": cve_id,
                "cvss_score": None,
                "epss_score": None,
                "is_kev": False,
                "normalized_signals": {},
                "risk_signal_weights": {},
                "weighted_signal_contributions": {},
                "generic_cve_risk_score": row.get("risk_score", 0.0),
                "confidence": row.get("confidence", 0.0),
                "risk_level": row.get("risk_level") or _risk_level(safe_float(row.get("risk_score"))),
                "top_positive_risk_contributors": [],
                "top_evidence_decisions": [_decision_trace(item) for item in decisions[:8]],
                "accepted_evidence_count": accepted_count,
                "manual_review_evidence_count": manual_count,
                "rejected_evidence_count": rejected_count,
                "dread_evidence_present": any(item.get("dread_evidence_present") for item in decisions),
                "confidence_cap_reason": confidence_cap_reason,
                "asset_operational_risk_examples": _asset_examples(asset_rows),
                "explanation": _fallback_trace_explanation(cve_id, row, accepted_count, manual_count, rejected_count, confidence_cap_reason, asset_rows),
            }
        )
    return traces


def _risk_explanation_traces_markdown(traces: Sequence[Mapping[str, Any]]) -> str:
    required = {
        "CVE-2026-9001",
        "CVE-2026-9002",
        "CVE-2026-9007",
        "CVE-2026-9017",
        "CVE-2015-0001",
    }
    rows = [trace for trace in traces if trace.get("cve_id") in required]
    lines = [
        "# Risk Explanation Traces",
        "",
        "Deterministic traces link exported normalized signals, evidence-gate decisions, confidence context, and asset-aware operational risk examples.",
        "",
    ]
    for trace in rows:
        lines.extend(
            [
                f"## {trace.get('cve_id')}",
                f"- Generic risk: {trace.get('generic_cve_risk_score')}",
                f"- Confidence: {trace.get('confidence')}",
                f"- Risk level: {trace.get('risk_level')}",
                f"- Evidence counts: accepted={trace.get('accepted_evidence_count')}, manual_review={trace.get('manual_review_evidence_count')}, rejected={trace.get('rejected_evidence_count')}",
                f"- Confidence cap: {trace.get('confidence_cap_reason') or 'none'}",
                "",
                "Main contributors:",
                _markdown_table(
                    ["Signal", "Contribution", "Weight", "Signal Value"],
                    [
                        [
                            item.get("signal"),
                            item.get("contribution"),
                            item.get("weight"),
                            item.get("normalized_signal"),
                        ]
                        for item in trace.get("top_positive_risk_contributors", [])[:5]
                    ],
                    align=["left", "right", "right", "right"],
                ),
                "",
                "Evidence decisions:",
                _markdown_table(
                    ["Target", "Source", "Decision", "Reason", "Gate", "Confidence"],
                    [
                        [
                            item.get("target_identifier"),
                            item.get("source"),
                            item.get("decision"),
                            item.get("primary_reason"),
                            item.get("evidence_gate_passed"),
                            item.get("final_confidence"),
                        ]
                        for item in trace.get("top_evidence_decisions", [])[:5]
                    ]
                    or [["none", "", "", "", "", ""]],
                    align=["left", "left", "left", "left", "left", "right"],
                ),
                "",
                "Asset-aware operational risk:",
                _markdown_table(
                    ["Asset", "Applicable", "Operational Risk", "Delta", "Level"],
                    [
                        [
                            item.get("asset_id"),
                            item.get("asset_applicable"),
                            item.get("operational_risk_score"),
                            item.get("operational_risk_delta"),
                            item.get("final_risk_level"),
                        ]
                        for item in trace.get("asset_operational_risk_examples", [])[:5]
                    ]
                    or [["none", "", "", "", ""]],
                    align=["left", "left", "right", "right", "left"],
                ),
                "",
                f"Explanation: {trace.get('explanation')}",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def _risk_contributors(record: EvaluationRecord) -> list[dict[str, Any]]:
    contributions = _feature_value(record, "risk_signal_contributions", {})
    weights = _feature_value(record, "risk_signal_weights", {})
    if not isinstance(contributions, Mapping):
        contributions = {}
    if not isinstance(weights, Mapping):
        weights = {}
    rows = []
    for signal, contribution in contributions.items():
        value = safe_float(contribution)
        if value <= 0:
            continue
        rows.append(
            {
                "signal": signal,
                "contribution": round(value, 6),
                "weight": weights.get(signal, ""),
                "normalized_signal": _feature_value(record, signal, ""),
            }
        )
    return sorted(rows, key=lambda item: (-safe_float(item["contribution"]), str(item["signal"])))


def _decision_trace(decision: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "target_identifier": decision.get("target_identifier"),
        "source": decision.get("source") or decision.get("evidence_source"),
        "decision": decision.get("decision") or decision.get("status"),
        "primary_reason": decision.get("primary_reason") or (decision.get("reasons") or [""])[0],
        "final_confidence": decision.get("final_confidence"),
        "evidence_gate_passed": decision.get("evidence_gate_passed"),
        "evidence_gate_reason": decision.get("evidence_gate_reason"),
        "rejection_reason": decision.get("rejection_reason"),
        "manual_review_reason": decision.get("manual_review_reason"),
        "evidence_reliability": decision.get("evidence_reliability"),
        "dread_evidence_present": decision.get("dread_evidence_present"),
        "dread_only_evidence": decision.get("dread_only_evidence"),
        "corroborated_dread_evidence": decision.get("corroborated_dread_evidence"),
        "confidence_cap_reason": decision.get("confidence_cap_reason"),
        "false_positive_control": decision.get("false_positive_control"),
    }


def _asset_examples(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    selected: list[Mapping[str, Any]] = []
    for predicate in (
        lambda row: bool(row.get("asset_applicable")),
        lambda row: not bool(row.get("asset_applicable")),
        lambda row: safe_float(row.get("patch_state_contribution")) < 0,
        lambda row: safe_float(row.get("compensating_control_reduction")) > 0,
    ):
        match = next((row for row in rows if predicate(row) and row not in selected), None)
        if match is not None:
            selected.append(match)
    for row in sorted(rows, key=lambda item: str(item.get("asset_id"))):
        if len(selected) >= 5:
            break
        if row not in selected:
            selected.append(row)
    examples = []
    for row in selected[:5]:
        examples.append(
            {
                "asset_id": row.get("asset_id"),
                "asset_applicable": row.get("asset_applicable"),
                "asset_match_reason": row.get("asset_match_reason"),
                "generic_cve_risk_score": row.get("generic_cve_risk_score") or row.get("source_risk_score"),
                "operational_risk_score": row.get("final_operational_risk_score") or row.get("operational_risk_score"),
                "operational_risk_delta": row.get("operational_risk_delta"),
                "final_risk_level": row.get("final_risk_level"),
                "confidence": row.get("confidence"),
                "explanation": row.get("explanation"),
            }
        )
    return examples


def _trace_explanation(
    record: EvaluationRecord,
    contributors: Sequence[Mapping[str, Any]],
    accepted_count: int,
    manual_count: int,
    rejected_count: int,
    confidence_cap_reason: str,
    asset_rows: Sequence[Mapping[str, Any]],
) -> str:
    top = ", ".join(str(item.get("signal")) for item in contributors[:3]) or "no positive exported signal contributions"
    evidence = f"{accepted_count} accepted, {manual_count} manual-review, and {rejected_count} rejected evidence decision(s)"
    cap = f" Confidence is capped by {confidence_cap_reason}." if confidence_cap_reason else ""
    assets = f" {len(asset_rows)} asset-context row(s) show operational risk can differ from generic CVE risk." if asset_rows else ""
    return f"{record.cve_id} risk is driven mainly by {top}. The trace includes {evidence}.{cap}{assets}"


def _fallback_trace_explanation(
    cve_id: str,
    row: Mapping[str, Any],
    accepted_count: int,
    manual_count: int,
    rejected_count: int,
    confidence_cap_reason: str,
    asset_rows: Sequence[Mapping[str, Any]],
) -> str:
    cap = f" Confidence is capped by {confidence_cap_reason}." if confidence_cap_reason else ""
    assets = f" {len(asset_rows)} asset-context row(s) show operational risk context." if asset_rows else ""
    return (
        f"{cve_id} is traced from scenario source results rather than benchmark evaluation records. "
        f"Generic risk is {row.get('risk_score')} with confidence {row.get('confidence')}; "
        f"the trace includes {accepted_count} accepted, {manual_count} manual-review, and {rejected_count} rejected evidence decision(s)."
        f"{cap}{assets}"
    )


def _decision_sort_key(status: str) -> int:
    return {"accepted": 0, "manual_review": 1, "rejected": 2}.get(status, 3)


def _write_scoring_sensitivity(report: Mapping[str, Any], path: Path) -> None:
    rows = []
    for payload in report.get("variants") or []:
        metrics = payload.get("metrics") or {}
        rows.append(
            {
                "variant": payload.get("variant"),
                "changed_weight": payload.get("changed_weight"),
                "direction": payload.get("direction"),
                "precision_at_5": metrics.get("precision_at_5", ""),
                "recall_at_5": metrics.get("recall_at_5", ""),
                "ndcg_at_5": metrics.get("ndcg_at_5", ""),
                "mean_kev_rank": metrics.get("mean_kev_rank", ""),
                "top5_cves": ";".join(payload.get("top5_cves") or []),
                "top5_overlap_with_baseline": payload.get("top5_overlap_with_baseline", ""),
                "guardrails_passed": payload.get("guardrails_passed", ""),
                "notes": payload.get("notes", ""),
            }
        )
    _write_csv(
        rows,
        path,
        [
            "variant",
            "changed_weight",
            "direction",
            "precision_at_5",
            "recall_at_5",
            "ndcg_at_5",
            "mean_kev_rank",
            "top5_cves",
            "top5_overlap_with_baseline",
            "guardrails_passed",
            "notes",
        ],
    )


def _scoring_sensitivity_markdown(report: Mapping[str, Any]) -> str:
    variants = list(report.get("variants") or [])
    changed = [item for item in variants if not item.get("guardrails_passed")]
    rows = []
    for payload in variants:
        metrics = payload.get("metrics") or {}
        rows.append(
            [
                payload.get("variant"),
                payload.get("changed_weight"),
                payload.get("direction"),
                metrics.get("precision_at_5", ""),
                metrics.get("recall_at_5", ""),
                metrics.get("ndcg_at_5", ""),
                metrics.get("mean_kev_rank", ""),
                payload.get("top5_overlap_with_baseline", ""),
                payload.get("guardrails_passed"),
            ]
        )
    changed_rows = [
        [payload.get("variant"), payload.get("notes")]
        for payload in changed
    ] or [["None", "All evaluated variants preserved the qualitative guardrails."]]
    return "\n".join(
        [
            "# Scoring Sensitivity Analysis",
            "",
            "This deterministic offline analysis recomputes the 24-record thesis fixture from exported normalized signals under bounded scoring-weight perturbations.",
            "It is a robustness probe for thesis behavior, not statistical calibration and not a change to production/default weights.",
            f"Weight policy: `{report.get('weight_policy', 'bounded_multiplier_no_renormalization')}`. Variant weights are copied from the canonical defaults and are not renormalized.",
            "",
            "## Variant Summary",
            "",
            _markdown_table(
                [
                    "Variant",
                    "Changed Weight",
                    "Direction",
                    "Precision@5",
                    "Recall@5",
                    "NDCG@5",
                    "Mean KEV Rank",
                    "Top-5 Overlap",
                    "Guardrails Passed",
                ],
                rows,
                align=["left", "left", "left", "right", "right", "right", "right", "right", "left"],
            ),
            "",
            "## Qualitative Changes",
            "",
            _markdown_table(
                ["Variant", "Notes"],
                changed_rows,
                align=["left", "left"],
            ),
            "",
            "## Interpretation",
            "",
            "- Stable top-5 overlap and passing guardrails suggest the controlled fixture behavior is not dependent on one exact hand-picked weight setting.",
            "- This does not prove real-world calibration or statistical significance.",
            "- Larger NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets are still required for empirical calibration.",
        ]
    ) + "\n"


def _score_rank_table(
    records: Sequence[EvaluationRecord],
    *,
    model_rank: Mapping[str, int],
    cvss_rank: Mapping[str, int],
) -> str:
    return _markdown_table(
        ["CVE", "Model Rank", "CVSS Rank", "Risk", "Confidence", "CVSS", "EPSS", "KEV", "Rationale"],
        [
            [
                record.cve_id,
                model_rank[record.cve_id],
                cvss_rank[record.cve_id],
                record.model_risk_score,
                record.model_confidence,
                record.cvss_score,
                record.epss_score,
                record.is_kev,
                _feature_value(record, "fixture_rationale", ""),
            ]
            for record in records
        ],
        align=["left", "right", "right", "right", "right", "right", "right", "left", "left"],
    )


def _methodology_summary_markdown() -> str:
    return "\n".join(
        [
            "# Methodology Summary",
            "",
            "This methodology summary describes a deterministic controlled fixture used for behavioral validation of the thesis prototype. It is not a live CTI benchmark and should not be interpreted as statistical real-world validation.",
            "",
            "Risk score represents prioritization and operational urgency. Confidence represents reliability of the supporting evidence.",
            "",
            "Normalized signals are bounded in [0, 1]: CVSS severity, EPSS exploit likelihood, CISA KEV listing, recency, accepted correlation support, graph context, and bounded intrinsic NLP context.",
            "",
            "Baseline strategies include CVSS-only, EPSS-only, CVSS+EPSS, KEV-first, model-risk ranking, confidence-aware model rankings, and the signal-based model. Ranking metrics include Precision@K, Recall@K, NDCG@K, and mean KEV rank where labels are available.",
            "",
            "Ablation analysis removes supported exported signals to show behavioral changes. Unsupported ablations are labeled when exact removal would require recomputing upstream evidence, graph, temporal, or confidence state.",
            "",
            "Scoring weights are heuristic engineering choices. The bounded sensitivity analysis perturbs those weights to probe robustness, but it is not statistical calibration and does not produce statistically optimized weights.",
            "",
            "Accepted correlations can increase risk and confidence. Rejected candidates and manual-review candidates remain diagnostic and do not increase risk. False-positive stress cases cover keyword-only candidates, stale evidence, unrelated product overlap, and manual-review evidence that should not boost risk as accepted evidence.",
            "",
            "Dread is optional experimental intelligence and is disabled by default. Dread cases in thesis artifacts are local deterministic fixtures and do not require live Dread access. Dread-only evidence remains bounded and is not treated as ground truth.",
            "",
            "Explanation traces link CVSS, EPSS, KEV, normalized signals, weighted contributions, evidence decisions, confidence context, and asset-aware operational-risk examples. Asset-aware examples demonstrate applicability, exposure, criticality, patch state, and compensating-control effects without replacing generic CVE risk.",
            "",
            "The expanded deterministic fixture validates ranking behavior, ablation behavior, bounded sensitivity behavior, false-positive resistance, explanation trace generation, asset-aware operational-risk examples, and artifact generation. Real-world operational validation should use larger curated NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets with external validation.",
            "",
            "Citation placeholders: [CVSS-FIRST], [EPSS-FIRST], [CISA-KEV], [CISA-SSVC].",
        ]
    ) + "\n"


def _limitations_and_validity_markdown() -> str:
    return "\n".join(
        [
            "# Limitations and Validity",
            "",
            "## Claim Scope",
            "",
            "The thesis claims are limited to a deterministic, explainable CTI risk-analysis prototype. The artifacts support behavioral validation of scoring, confidence, evidence gating, sensitivity, explanation traces, and asset-aware operational-risk examples. They do not establish real-world effectiveness, deployment readiness, or statistical generalization.",
            "",
            "## Multi-Agent Interpretation",
            "",
            "The architecture is multi-agent-inspired and agent-supported: specialist modules coordinate collection, analysis, correlation, scoring, evaluation, and reporting responsibilities. It is not a fully autonomous LLM-agent system. Deterministic analysis services remain the source of scoring and evidence decisions.",
            "",
            "## Controlled Fixture Limitation",
            "",
            "The evaluation uses a deterministic controlled fixture for behavioral validation. The fixture is not a live CTI benchmark and does not support statistical significance, field prevalence, or operational prevalence claims.",
            "",
            "## Heuristic Scoring Weights Limitation",
            "",
            "The scoring weights are heuristic engineering choices that encode intended model semantics. They are not learned parameters and are not statistically optimized.",
            "",
            "## Sensitivity Analysis Limitation",
            "",
            "The sensitivity analysis is a bounded robustness probe over the controlled fixture. It tests whether qualitative behavior remains stable under small deterministic weight perturbations; it is not statistical calibration.",
            "",
            "## Dread Evidence Limitation",
            "",
            "Dread is optional, experimental, bounded, default-off, and not treated as ground truth. Dread-only evidence does not imply high confidence or CRITICAL risk by itself. Dread remains diagnostic/manual-review evidence around stronger signals and does not override CVSS, EPSS, KEV, or accepted structured evidence.",
            "",
            "## Asset-Aware Operational Risk Limitation",
            "",
            "Asset-aware operational risk depends on asset inventory quality, product/version matching, exposure classification, patch state, and compensating-control evidence. The deterministic asset examples demonstrate model behavior, not full organization-wide operational validation.",
            "",
            "## Graph Persistence Limitation",
            "",
            "Graph context is computed as bounded scenario context. Neo4j or other persistent graph databases are future work and are not implemented as the current thesis scope.",
            "",
            "## Real-World Generalization Limitation",
            "",
            "Generalization requires larger curated NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets, plus external validation criteria. The current deterministic artifacts should not be used to infer live operational prevalence or broad field performance.",
            "",
            "## Future Work",
            "",
            "Future work includes larger longitudinal evaluation, independent external labels, improved asset inventory integration, persistent graph storage, calibrated organization-specific risk thresholds, stronger provenance review, and production security hardening.",
        ]
    ) + "\n"


def _thesis_defense_pack_markdown() -> str:
    return "\n".join(
        [
            "# Thesis Defense Pack",
            "",
            "## One-Paragraph Thesis Claim",
            "",
            "This thesis presents a multi-agent-inspired, agent-supported modular architecture for cyber threat intelligence risk analysis. The prototype combines deterministic CVE scoring, confidence estimation, evidence-gated correlation, bounded Dread handling, sensitivity analysis, explanation traces, and asset-aware operational-risk examples. The evaluation uses a controlled deterministic fixture to validate behavior and reproducibility, not to claim live operational generalization.",
            "",
            "## Contributions",
            "",
            "- A modular CTI analysis architecture separating collection, scoring, confidence, correlation, evaluation, and reporting responsibilities.",
            "- A canonical signal-based CVE risk formula with normalized inputs and weighted contribution exports.",
            "- A confidence model that remains separate from risk and accounts for evidence quality.",
            "- Evidence-gated CVE-IOC correlation with accepted, rejected, and manual-review outcomes.",
            "- Bounded optional Dread evidence treatment with confidence caps and deterministic fixture cases.",
            "- Asset-aware operational-risk examples that preserve generic CVE risk separately.",
            "- Thesis artifacts for benchmark comparison, ablation, sensitivity, explanation traces, case studies, and quality validation.",
            "",
            "## What the System Does Not Claim",
            "",
            "- It does not claim to be a fully autonomous LLM-agent system.",
            "- It does not claim deployment readiness for SOC operations.",
            "- It does not claim statistical significance or broad real-world generalization.",
            "- It does not claim learned or statistically optimized scoring weights.",
            "- It does not claim Dread evidence is ground truth.",
            "- It does not claim persistent Neo4j-style graph storage is implemented.",
            "",
            "## Methodology Summary",
            "",
            "The methodology uses deterministic fixture records to exercise CVSS, EPSS, KEV, recency, accepted correlation, graph context, NLP context, confidence, false-positive controls, and asset-aware operational-risk examples. Metrics and artifacts are generated without live network access.",
            "",
            "## Evaluation Summary",
            "",
            "The evaluation compares baseline ranking strategies, supported ablations, bounded scoring-weight sensitivity variants, correlation decisions, explanation traces, and selected case studies. The results support controlled behavioral validation and auditability.",
            "",
            "## Key Limitations",
            "",
            "- The fixture is controlled and deterministic.",
            "- The fixture is not a live CTI benchmark.",
            "- The weights are heuristic engineering choices.",
            "- Sensitivity analysis probes robustness but is not calibration.",
            "- Dread is optional, experimental, bounded, and default-off.",
            "- Asset-aware operational risk depends on inventory and control quality.",
            "- Persistent graph databases are future work.",
            "",
            "## Suggested Defense Q&A",
            "",
            "### Is this a fully autonomous multi-agent system?",
            "",
            "No. It is a multi-agent-inspired and agent-supported modular decision architecture. Deterministic analysis services perform scoring, confidence, correlation, and evaluation.",
            "",
            "### Why are the weights heuristic?",
            "",
            "The weights encode transparent engineering assumptions about severity, exploit likelihood, active exploitation evidence, correlation support, recency, and context. They are exported and tested for bounded sensitivity, but they are not learned from a large labeled dataset.",
            "",
            "### Does the fixture prove real-world effectiveness?",
            "",
            "No. The fixture supports behavioral validation and reproducibility. Real-world operational validation would require larger curated datasets, asset inventory quality, and external validation criteria.",
            "",
            "### Why is Dread included if it is unreliable?",
            "",
            "Dread is included as bounded experimental intelligence to show how weak sources can be preserved diagnostically without becoming high-confidence evidence by themselves.",
            "",
            "### Why not use Neo4j?",
            "",
            "The thesis scope uses bounded graph context rather than persistent graph infrastructure. Neo4j or similar graph databases are appropriate future work for larger deployments.",
            "",
            "### What is the main contribution?",
            "",
            "The main contribution is an explainable, modular CTI risk-analysis architecture that separates risk, confidence, evidence gating, and asset-aware operational context while producing reproducible thesis artifacts.",
            "",
            "### What would be required for production use?",
            "",
            "Production use would require stronger authentication and authorization, deployment hardening, larger validated data feeds, asset inventory integration, external labels, monitoring, governance, and operational review workflows.",
        ]
    ) + "\n"


def _demo_walkthrough_markdown(
    *,
    scenario: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
    baselines: Mapping[str, Any],
    ablation_report: Mapping[str, Any],
) -> str:
    decision_counts = _decision_counts(scenario.get("correlation_decisions") or [])
    supported_ablation_count = len(ablation_report.get("supported") or {})
    unsupported_ablation_count = len(ablation_report.get("unsupported") or {})
    strategy_count = len(baselines)

    return "\n".join(
        [
            "# Thesis Demo Walkthrough",
            "",
            "## What This Demo Runs",
            "",
            "`make thesis-demo` runs the deterministic thesis scenario, regenerates the thesis artifact bundle, and then runs the artifact quality gate. The flow is local, deterministic, and does not require live network access.",
            "",
            "The demo uses a deterministic controlled fixture for behavioral validation. It is not a live CTI benchmark and does not support statistical significance or real-world validation claims.",
            "",
            "## Output Files",
            "",
            _markdown_table(
                ["Output", "Purpose"],
                [
                    ["`reports/thesis/deterministic/thesis_scenario_report.json`", "Structured deterministic scenario report."],
                    ["`reports/thesis/deterministic/manifest.json`", "Generated artifact inventory and record counts."],
                    ["`reports/thesis/deterministic/demo_walkthrough.md`", "This demo-oriented walkthrough."],
                    ["`reports/thesis/deterministic/thesis_defense_pack.md`", "Concise defense preparation summary and Q&A."],
                    ["`reports/thesis/deterministic/results_summary.md`", "Compact technical results summary."],
                    ["`reports/thesis/deterministic/risk_explanation_traces.md`", "Readable end-to-end explanation traces."],
                ],
                align=["left", "left"],
            ),
            "",
            "## Key Demonstrated Capabilities",
            "",
            f"- Deterministic controlled fixture with {len(records)} CVE-like evaluation records.",
            f"- Baseline ranking comparison across {strategy_count} ranking strategies.",
            f"- Ablation analysis with {supported_ablation_count} supported variant(s) and {unsupported_ablation_count} explicitly unsupported variant(s).",
            "- Bounded sensitivity analysis over heuristic scoring weights.",
            "- Explanation traces linking inputs, normalized signals, evidence decisions, confidence, and operational risk.",
            "- Evidence-gated correlation decisions with accepted, manual_review, and rejected outcomes.",
            "- Asset-aware operational-risk examples that remain separate from generic CVE risk.",
            "- Dread is optional, experimental, bounded, default-off, and not treated as ground truth.",
            "",
            "## How to Read the Results",
            "",
            "Start with `manifest.json` to verify the artifact inventory, then open this walkthrough and `thesis_defense_pack.md`. Use `benchmark_summary.md` for baseline ranking comparison, `ablation_summary.md` for ablation analysis, `scoring_sensitivity.md` for bounded sensitivity analysis, and `risk_explanation_traces.md` for explanation traces.",
            "",
            "The artifact quality gate checks that required files, headings, columns, case studies, traces, Markdown tables, and thesis-safe wording are present before material is copied into thesis text.",
            "",
            "## Asset-Aware Operational Risk Example",
            "",
            "The case studies include asset-aware operational-risk examples for applicability, public exposure, criticality, patch state, and compensating controls. These examples show how operational risk can differ from generic CVE risk while preserving both concepts separately.",
            "",
            "Open `case_studies.json` and `risk_explanation_traces.json` for machine-readable examples, or `risk_explanation_traces.md` for a concise readable trace.",
            "",
            "## Evidence-Gating and False-Positive Handling",
            "",
            "The correlation export demonstrates evidence-gated correlation decisions. Accepted decisions can support risk and confidence; rejected and manual-review decisions remain diagnostic and do not automatically increase risk as accepted evidence.",
            "",
            _markdown_table(
                ["Decision", "Count"],
                [[decision, count] for decision, count in sorted(decision_counts.items())],
                align=["left", "right"],
            ),
            "",
            "False-positive stress cases cover keyword-only evidence, stale evidence, unrelated product overlap, and manual-review evidence that should not boost risk like accepted correlation.",
            "",
            "## Reproducibility Notes",
            "",
            "Run the complete local demo with:",
            "",
            "```bash",
            "make thesis-demo",
            "```",
            "",
            "The flow regenerates artifacts and runs `make thesis-artifact-quality`. No live Dread access is required, and no live Dread crawling is performed.",
            "",
            "## Claim Boundaries",
            "",
            "- The project is a multi-agent-inspired and agent-supported modular CTI risk-analysis prototype.",
            "- It is not a fully autonomous LLM-agent system.",
            "- The evaluation is controlled behavioral validation, not statistical real-world validation.",
            "- Scoring weights are heuristic engineering choices tested through bounded sensitivity analysis.",
            "- Dread is optional, experimental, bounded, default-off, and not treated as ground truth.",
            "- Persistent graph databases such as Neo4j are future work, not current thesis scope.",
        ]
    ) + "\n"


def _results_summary_markdown(
    *,
    scenario: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
    baselines: Mapping[str, Any],
    ablation_report: Mapping[str, Any],
) -> str:
    level_counts = _risk_level_counts(records)
    risk_scores = [record.model_risk_score for record in records]
    model_ranked = sorted(records, key=lambda record: (-record.model_risk_score, record.cve_id))
    cvss_ranked = sorted(records, key=lambda record: (-record.cvss_score, record.cve_id))
    model_rank = {record.cve_id: index + 1 for index, record in enumerate(model_ranked)}
    cvss_rank = {record.cve_id: index + 1 for index, record in enumerate(cvss_ranked)}
    disagreements = sorted(
        records,
        key=lambda record: (abs(model_rank[record.cve_id] - cvss_rank[record.cve_id]), record.cve_id),
        reverse=True,
    )[:5]
    decision_counts = _decision_counts(scenario.get("correlation_decisions") or [])
    cases = list(scenario.get("notable_cases") or [])

    lines = [
        "# Thesis Results Summary",
        "",
        "## Evaluation Setup",
        "",
        f"The evaluation uses a controlled deterministic fixture with {len(records)} CVE-like records. It has no live network dependency and is intended for behavioral validation, not statistical real-world benchmarking.",
        "",
        "Compared strategies: `cvss_only`, `epss_only`, `cvss_epss`, `kev_first`, `model_risk`, `model_confidence_weighted`, `model_confidence_filtered`, and `signal_based_model`.",
        "",
        "## Benchmark Findings",
        "",
        "CVSS-only underperforms in this controlled fixture because high-severity records with weak exploitation evidence can outrank more operationally urgent cases. Signal/model-based rankings improve prioritization by combining severity with exploit likelihood, KEV status, recency, accepted correlation, graph context, and intrinsic context.",
        "",
        _benchmark_findings_sentence(baselines),
        "",
        "KEV-first is a useful baseline for active exploitation, but it is not the same as full risk modeling because it does not account for non-KEV high-EPSS records, correlation strength, confidence, or contextual signals.",
        "",
        _benchmark_results_table(baselines),
        "",
        "## Scoring Distribution Findings",
        "",
        "- Risk level distribution: "
        + ", ".join(f"{level}={count}" for level, count in sorted(level_counts.items()))
        + ".",
        f"- Risk score range: min={min(risk_scores) if risk_scores else 0.0}, max={max(risk_scores) if risk_scores else 0.0}, mean={round(mean(risk_scores), 4) if risk_scores else 0.0}.",
        "- High-CVSS / weak-evidence cases remain meaningful risk, but they are not automatically CRITICAL when confidence and exploitation evidence are weak.",
        "- Medium-CVSS records with high EPSS and KEV can outrank high-CVSS weak-evidence controls.",
        "",
        _ranking_disagreement_table(disagreements, model_rank=model_rank, cvss_rank=cvss_rank),
        "",
        "## Ablation Findings",
        "",
        "Removing EPSS weakens prioritization in the controlled fixture, while removing KEV weakens KEV ranking quality. Temporal/recency removal also changes ranking quality. The external-evidence ablation remains explicitly unsupported because accepted evidence, graph context, temporal caps, and confidence would need recomputation.",
        "",
        _ablation_results_table(ablation_report),
        "",
        "## Correlation Decision Findings",
        "",
        "Accepted, rejected, and manual-review correlation outcomes are exported. Accepted correlations can support risk and confidence, while rejected and manual-review cases remain diagnostic and do not automatically increase risk.",
        "",
        _markdown_table(
            ["Decision", "Count"],
            [[decision, count] for decision, count in sorted(decision_counts.items())],
            align=["left", "right"],
        ),
        "",
        "## Case Study Highlights",
        "",
        _case_study_highlights(cases),
        "",
        "## Limitations",
        "",
        "This fixture is deterministic and controlled. It is not a live operational benchmark and does not support statistical significance claims.",
        "",
        "Real-world validation requires larger NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context datasets. Dread remains optional and experimental.",
    ]
    return "\n".join(lines) + "\n"


def _thesis_results_section_markdown(
    *,
    scenario: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
    baselines: Mapping[str, Any],
    ablation_report: Mapping[str, Any],
) -> str:
    risk_scores = [record.model_risk_score for record in records]
    decision_counts = _decision_counts(scenario.get("correlation_decisions") or [])
    cases = list(scenario.get("notable_cases") or [])

    lines = [
        "# Results and Evaluation",
        "",
        "## Experimental Setup",
        "",
        f"The evaluation used a controlled deterministic fixture containing {len(records)} CVE-like records. The artifact generation path has no live network dependency and is intended for behavioral validation rather than live operational benchmarking.",
        "",
        "The compared ranking strategies were `cvss_only`, `epss_only`, `cvss_epss`, `kev_first`, `model_risk`, `model_confidence_weighted`, `model_confidence_filtered`, and `signal_based_model`.",
        "",
        "## Prioritization Results",
        "",
        "In the controlled fixture, the CVSS-only baseline underperforms because high-severity records with weak supporting evidence can be ranked ahead of records with stronger operational exploitation signals. Incorporating EPSS, KEV status, recency, accepted correlation, graph context, and confidence suggests prioritization behavior that is more aligned with operational urgency.",
        "",
        _thesis_benchmark_findings_sentence(baselines),
        "",
        "The KEV-first baseline is useful because it directly prioritizes known exploited vulnerabilities. However, it is not equivalent to full risk modeling because it does not jointly account for exploit likelihood, correlation quality, graph context, evidence freshness, and confidence.",
        "",
        _thesis_benchmark_table(baselines),
        "",
        "## Scoring Distribution",
        "",
        "- Risk level distribution: " + _risk_level_distribution(records) + ".",
        f"- Risk score range: min={min(risk_scores) if risk_scores else 0.0}, max={max(risk_scores) if risk_scores else 0.0}, mean={round(mean(risk_scores), 4) if risk_scores else 0.0}.",
        "- High-CVSS records with weak evidence remain meaningful risks, but they are not automatically treated as CRITICAL.",
        "- Medium-CVSS records with high EPSS and KEV evidence can outrank high-CVSS records that lack accepted external evidence.",
        "- Risk and confidence are interpreted separately: risk represents prioritization urgency, while confidence represents the reliability of supporting evidence.",
        "",
        "## Ablation Analysis",
        "",
        "Removing EPSS weakens prioritization in the controlled fixture, and removing KEV weakens the ranking quality for KEV-listed records. Removing temporal or recency signals also affects ranking behavior. The external-evidence ablation is marked unsupported because exact removal would require recomputing accepted matches, graph context, temporal caps, and confidence.",
        "",
        _thesis_ablation_table(ablation_report),
        "",
        "## Correlation Decision Analysis",
        "",
        "The correlation export separates `accepted`, `rejected`, and `manual_review` outcomes. Accepted correlations can support risk and confidence, while rejected and manual-review cases remain diagnostic and do not automatically increase risk.",
        "",
        _markdown_table(
            ["Decision", "Count"],
            [[decision, count] for decision, count in sorted(decision_counts.items())],
            align=["left", "right"],
        ),
        "",
        "## Case Study Highlights",
        "",
        _case_study_highlights(cases),
        "",
        "## Threats to Validity and Limitations",
        "",
        "The fixture is deterministic and controlled, so the results support behavioral validation but should not be interpreted as a live benchmark. The artifact does not support statistical significance claims.",
        "",
        "Generalization requires larger real-world datasets from NVD, EPSS, CISA KEV, URLhaus/Dread, and asset-context sources. Dread remains optional and experimental in this methodology.",
    ]
    return "\n".join(lines) + "\n"


def _thesis_benchmark_findings_sentence(baselines: Mapping[str, Any]) -> str:
    weighted = _metric(baselines, "model_confidence_weighted", "precision_at_5")
    model = _metric(baselines, "model_risk", "precision_at_5")
    if weighted != "" and model != "" and safe_float(weighted) >= safe_float(model):
        return "The confidence-weighted model shows stronger top-5 prioritization in this fixture."
    return "The confidence-weighted model is reported separately because confidence changes the interpretation of ranking quality."


def _thesis_benchmark_table(baselines: Mapping[str, Any]) -> str:
    strategies = [
        "cvss_only",
        "epss_only",
        "cvss_epss",
        "kev_first",
        "model_risk",
        "model_confidence_weighted",
        "model_confidence_filtered",
        "signal_based_model",
    ]
    return _markdown_table(
        ["Method", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank"],
        [
            [
                strategy,
                _metric(baselines, strategy, "precision_at_5"),
                _metric(baselines, strategy, "recall_at_5"),
                _metric(baselines, strategy, "ndcg_at_5"),
                _metric(baselines, strategy, "mean_kev_rank"),
            ]
            for strategy in strategies
        ],
        align=["left", "right", "right", "right", "right"],
    )


def _thesis_ablation_table(ablation_report: Mapping[str, Any]) -> str:
    rows = []
    for variant, payload in sorted((ablation_report.get("supported") or {}).items()):
        metrics = payload.get("metrics") or {}
        rows.append(
            [
                variant,
                payload.get("status"),
                metrics.get("precision_at_5", ""),
                metrics.get("recall_at_5", ""),
                metrics.get("ndcg_at_5", ""),
                metrics.get("mean_kev_rank", ""),
                "",
            ]
        )
    for variant, payload in sorted((ablation_report.get("unsupported") or {}).items()):
        rows.append([variant, payload.get("status"), "", "", "", "", payload.get("reason")])
    return _markdown_table(
        ["Variant", "Status", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank", "Explanation"],
        rows,
        align=["left", "left", "right", "right", "right", "right", "left"],
    )


def _risk_level_distribution(records: Sequence[EvaluationRecord]) -> str:
    counts = _risk_level_counts(records)
    ordered = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    return ", ".join(f"{level}={counts[level]}" for level in ordered if level in counts)


def _benchmark_findings_sentence(baselines: Mapping[str, Any]) -> str:
    weighted = _metric(baselines, "model_confidence_weighted", "precision_at_5")
    model = _metric(baselines, "model_risk", "precision_at_5")
    if weighted != "" and model != "" and safe_float(weighted) >= safe_float(model):
        return "The confidence-weighted model reaches stronger top-5 prioritization in this fixture."
    return "The confidence-weighted model is reported separately because confidence changes prioritization semantics."


def _benchmark_results_table(baselines: Mapping[str, Any]) -> str:
    strategies = [
        "cvss_only",
        "epss_only",
        "cvss_epss",
        "kev_first",
        "model_risk",
        "model_confidence_weighted",
        "model_confidence_filtered",
        "signal_based_model",
    ]
    return _markdown_table(
        ["Strategy", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank"],
        [
            [
                strategy,
                _metric(baselines, strategy, "precision_at_5"),
                _metric(baselines, strategy, "recall_at_5"),
                _metric(baselines, strategy, "ndcg_at_5"),
                _metric(baselines, strategy, "mean_kev_rank"),
            ]
            for strategy in strategies
        ],
        align=["left", "right", "right", "right", "right"],
    )


def _ablation_results_table(ablation_report: Mapping[str, Any]) -> str:
    rows = []
    for variant, payload in sorted((ablation_report.get("supported") or {}).items()):
        metrics = payload.get("metrics") or {}
        rows.append(
            [
                variant,
                payload.get("status"),
                metrics.get("precision_at_5", ""),
                metrics.get("recall_at_5", ""),
                metrics.get("ndcg_at_5", ""),
                metrics.get("mean_kev_rank", ""),
                "",
            ]
        )
    for variant, payload in sorted((ablation_report.get("unsupported") or {}).items()):
        rows.append([variant, payload.get("status"), "", "", "", "", payload.get("reason")])
    return _markdown_table(
        ["Variant", "Status", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank", "Reason"],
        rows,
        align=["left", "left", "right", "right", "right", "right", "left"],
    )


def _ranking_disagreement_table(
    records: Sequence[EvaluationRecord],
    *,
    model_rank: Mapping[str, int],
    cvss_rank: Mapping[str, int],
) -> str:
    return _markdown_table(
        ["CVE", "Model Rank", "CVSS Rank", "Risk", "CVSS", "EPSS", "KEV", "Rationale"],
        [
            [
                record.cve_id,
                model_rank[record.cve_id],
                cvss_rank[record.cve_id],
                record.model_risk_score,
                record.cvss_score,
                record.epss_score,
                record.is_kev,
                _feature_value(record, "fixture_rationale", ""),
            ]
            for record in records
        ],
        align=["left", "right", "right", "right", "right", "right", "left", "left"],
    )


def _case_study_highlights(cases: Sequence[Mapping[str, Any]]) -> str:
    required = [
        "high_risk_correlated",
        "medium_cvss_high_epss_kev",
        "high_cvss_low_external_evidence",
        "dread_only_manual_review",
        "dread_corroborated_by_urlhaus_or_kev",
        "weak_dread_rejected",
        "keyword_only_false_positive_rejected",
        "stale_evidence_rejected_or_capped",
        "unrelated_product_overlap_rejected",
        "manual_review_not_risk_boost",
        "asset_applicability_difference",
        "patched_asset_reduction",
        "compensating_control_reduction",
        "stale_low_risk",
    ]
    by_name = {case.get("case"): case for case in cases}
    rows = []
    for name in required:
        case = by_name.get(name)
        if not case:
            continue
        rows.append([name, case.get("entity_id", ""), _case_note(case)])
    return _markdown_table(["Case", "Entity", "Highlight"], rows, align=["left", "left", "left"])


def _case_note(case: Mapping[str, Any]) -> str:
    if case.get("case") == "high_risk_correlated":
        return f"High-risk correlated case with {case.get('accepted_decisions', 0)} accepted decision(s)."
    if case.get("case") == "medium_cvss_high_epss_kev":
        return "Medium CVSS is prioritized by high EPSS and KEV evidence."
    if case.get("case") == "high_cvss_low_external_evidence":
        return "High CVSS remains meaningful but lacks strong external support."
    if case.get("case") == "dread_only_manual_review":
        return f"Dread-only evidence remains manual review ({case.get('manual_review_decisions', 0)} decision) with cap {case.get('confidence_cap_reason', '')}."
    if case.get("case") == "dread_corroborated_by_urlhaus_or_kev":
        return (
            f"Dread exact-CVE support remains manual review "
            f"({case.get('manual_review_dread_decisions', 0)} decision) with cap {case.get('confidence_cap_reason', '')}."
        )
    if case.get("case") == "weak_dread_rejected":
        return f"Weak Dread mention rejected ({case.get('rejected_dread_decisions', 0)} decision)."
    if case.get("case") == "keyword_only_false_positive_rejected":
        return f"Keyword-only candidate decision: {case.get('decision')} ({case.get('rejection_reason', '')})."
    if case.get("case") == "stale_evidence_rejected_or_capped":
        return f"Stale evidence decision: {case.get('decision')} with confidence {case.get('final_confidence')}."
    if case.get("case") == "unrelated_product_overlap_rejected":
        return f"Unrelated product-overlap candidate decision: {case.get('decision')}."
    if case.get("case") == "manual_review_not_risk_boost":
        return f"Manual-review decisions {case.get('manual_review_decisions', 0)}; accepted evidence count {case.get('accepted_evidence_count', 0)}."
    if case.get("case") == "asset_applicability_difference":
        return f"Applicable asset score {case.get('applicable_asset_score')}; non-applicable asset score {case.get('non_applicable_asset_score')}."
    if case.get("case") == "patched_asset_reduction":
        return f"Patched asset score {case.get('patched_asset_score')}; unpatched asset score {case.get('unpatched_asset_score')}."
    if case.get("case") == "compensating_control_reduction":
        return f"Controlled asset score {case.get('controlled_asset_score')}; uncontrolled asset score {case.get('uncontrolled_asset_score')}."
    if case.get("case") == "stale_low_risk":
        return f"Stale case remains lower priority with risk score {case.get('risk_score')}."
    return str(case.get("description", ""))


def _metric(baselines: Mapping[str, Any], strategy: str, metric: str) -> Any:
    return ((baselines.get(strategy) or {}).get("metrics") or {}).get(metric, "")


def _decision_counts(decisions: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for decision in decisions:
        status = str(decision.get("decision") or decision.get("status") or "unknown")
        counts[status] = counts.get(status, 0) + 1
    return counts


def _risk_level_counts(records: Sequence[EvaluationRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        level = _risk_level(record.model_risk_score)
        counts[level] = counts.get(level, 0) + 1
    return counts


def _write_benchmark_summary(baselines: Mapping[str, Any], path: Path) -> None:
    rows = []
    for strategy, payload in sorted(baselines.items()):
        for metric, value in sorted((payload.get("metrics") or {}).items()):
            rows.append({"strategy": strategy, "metric": metric, "value": value})
    _write_csv(rows, path, ["strategy", "metric", "value"])


def _benchmark_summary_markdown(
    baselines: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
) -> str:
    table_rows = []
    for strategy, payload in sorted(baselines.items()):
        metrics = payload.get("metrics") or {}
        ranking = payload.get("ranking") or []
        table_rows.append(
            [
                strategy,
                ", ".join(ranking[:5]),
                metrics.get("precision_at_5", ""),
                metrics.get("recall_at_5", ""),
                metrics.get("ndcg_at_5", ""),
                metrics.get("mean_kev_rank", ""),
            ]
        )

    return "\n".join(
        [
            "# Benchmark Summary",
            "",
            f"Controlled fixture size: {len(records)} CVEs.",
            "",
            _markdown_table(
                ["Strategy", "Top 5 CVEs", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank"],
                table_rows,
                align=["left", "left", "right", "right", "right", "right"],
            ),
        ]
    ) + "\n"


def _write_ablation_summary(report: Mapping[str, Any], path: Path) -> None:
    rows = []
    for variant, payload in sorted((report.get("supported") or {}).items()):
        for metric, value in sorted((payload.get("metrics") or {}).items()):
            rows.append(
                {
                    "variant": variant,
                    "status": payload.get("status"),
                    "metric": metric,
                    "value": value,
                    "reason": "",
                }
            )
    for variant, payload in sorted((report.get("unsupported") or {}).items()):
        rows.append(
            {
                "variant": variant,
                "status": payload.get("status"),
                "metric": "",
                "value": "",
                "reason": payload.get("reason"),
            }
        )
    _write_csv(rows, path, ["variant", "status", "metric", "value", "reason"])


def _ablation_summary_markdown(report: Mapping[str, Any]) -> str:
    table_rows = []

    for variant, payload in sorted((report.get("supported") or {}).items()):
        metrics = payload.get("metrics") or {}
        table_rows.append(
            [
                variant,
                payload.get("status"),
                metrics.get("precision_at_5", ""),
                metrics.get("recall_at_5", ""),
                metrics.get("ndcg_at_5", ""),
                metrics.get("mean_kev_rank", ""),
                "",
            ]
        )

    for variant, payload in sorted((report.get("unsupported") or {}).items()):
        table_rows.append(
            [
                variant,
                payload.get("status"),
                "",
                "",
                "",
                "",
                payload.get("reason"),
            ]
        )

    return "\n".join(
        [
            "# Ablation Summary",
            "",
            _markdown_table(
                ["Variant", "Status", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank", "Reason"],
                table_rows,
                align=["left", "left", "right", "right", "right", "right", "left"],
            ),
        ]
    ) + "\n"


def _write_correlation_decisions(decisions: Sequence[Mapping[str, Any]], path: Path) -> None:
    rows = []
    for decision in decisions:
        provenance = decision.get("provenance_summary") or {}
        rows.append(
            {
                "source_identifier": decision.get("source_identifier"),
                "target_identifier": decision.get("target_identifier"),
                "source": ",".join(provenance.get("sources") or []),
                "lexical_score": decision.get("lexical_score", ""),
                "semantic_score": decision.get("semantic_score", ""),
                "temporal_score": decision.get("temporal_score", ""),
                "entity_score": decision.get("entity_score", ""),
                "shared_term_count": decision.get("shared_term_count", ""),
                "exact_cve": decision.get("exact_cve", ""),
                "high_signal_term_hits": decision.get("high_signal_term_hits", ""),
                "decision": decision.get("decision") or decision.get("status"),
                "primary_reason": decision.get("primary_reason") or (decision.get("reasons") or [""])[0],
                "final_confidence": decision.get("final_confidence"),
                "evidence_source": decision.get("evidence_source", ""),
                "evidence_reliability": decision.get("evidence_reliability", ""),
                "dread_evidence_present": decision.get("dread_evidence_present", ""),
                "dread_only_evidence": decision.get("dread_only_evidence", ""),
                "corroborated_dread_evidence": decision.get("corroborated_dread_evidence", ""),
                "manual_review_reason": decision.get("manual_review_reason", ""),
                "confidence_cap_reason": decision.get("confidence_cap_reason", ""),
                "evidence_gate_passed": decision.get("evidence_gate_passed", ""),
                "evidence_gate_reason": decision.get("evidence_gate_reason", ""),
                "rejection_reason": decision.get("rejection_reason", ""),
                "accepted_evidence_count": decision.get("accepted_evidence_count", ""),
                "rejected_evidence_count": decision.get("rejected_evidence_count", ""),
                "manual_review_evidence_count": decision.get("manual_review_evidence_count", ""),
                "false_positive_control": decision.get("false_positive_control", ""),
            }
        )

    _write_csv(
        rows,
        path,
        [
            "source_identifier",
            "target_identifier",
            "source",
            "lexical_score",
            "semantic_score",
            "temporal_score",
            "entity_score",
            "shared_term_count",
            "exact_cve",
            "high_signal_term_hits",
            "decision",
            "primary_reason",
            "final_confidence",
            "evidence_source",
            "evidence_reliability",
            "dread_evidence_present",
            "dread_only_evidence",
            "corroborated_dread_evidence",
            "manual_review_reason",
            "confidence_cap_reason",
            "evidence_gate_passed",
            "evidence_gate_reason",
            "rejection_reason",
            "accepted_evidence_count",
            "rejected_evidence_count",
            "manual_review_evidence_count",
            "false_positive_control",
        ],
    )


def _write_csv(rows: Iterable[Mapping[str, Any]], path: Path, fields: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _markdown_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    align: Sequence[str],
) -> str:
    if len(headers) != len(align):
        raise ValueError("headers and align must have the same length")

    separator = []
    for item in align:
        if item == "right":
            separator.append("---:")
        elif item == "center":
            separator.append(":---:")
        else:
            separator.append("---")

    rendered = [
        _markdown_row(headers),
        _markdown_row(separator),
    ]

    for row in rows:
        if len(row) != len(headers):
            raise ValueError("row length must match header length")
        rendered.append(_markdown_row(row))

    return "\n".join(rendered)


def _markdown_row(values: Sequence[Any]) -> str:
    cells = [_markdown_cell(value) for value in values]
    return "| " + " | ".join(cells) + " |"


def _markdown_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _feature_value(record: EvaluationRecord, key: str, default: Any = "") -> Any:
    feature_breakdown = record.feature_breakdown or {}
    if key in feature_breakdown:
        return feature_breakdown.get(key, default)

    evidence = feature_breakdown.get("evidence") or {}
    if isinstance(evidence, Mapping):
        return evidence.get(key, default)

    return default


def _risk_level(score: float) -> str:
    if score >= 8.5:
        return "CRITICAL"
    if score >= 6.5:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic thesis artifact bundle")
    parser.add_argument("--scenario-report", default=str(DEFAULT_SCENARIO_REPORT))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    manifest = generate_thesis_artifacts(
        scenario_report_path=args.scenario_report,
        output_dir=args.output_dir,
    )
    print(json.dumps({"output_dir": manifest["output_dir"], "record_count": manifest["record_count"]}, sort_keys=True))


if __name__ == "__main__":
    main()
