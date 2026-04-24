from __future__ import annotations

from typing import Any, Dict, Iterable, List

from evaluation.comparative import build_case_study_rows, build_comparison_summary, build_cve_comparison_frame
from evaluation.ml_refinement import summarize_refinement_model


def build_report_brief(rows: Iterable[Dict[str, Any]], top_k: int = 10) -> Dict[str, Any]:
    frame = build_cve_comparison_frame(rows)
    records = frame.to_dict(orient="records") if not frame.empty else []
    summary = build_comparison_summary(records, top_k=top_k) if records else {}
    case_studies = build_case_study_rows(records, limit=5) if records else []
    refinement = summarize_refinement_model(records) if records else {}

    paragraphs: List[str] = []
    if summary:
        paragraphs.append(
            "The hybrid model raises prioritization above CVSS-only scoring by combining lexical, semantic, temporal and graph evidence. "
            f"Average lift from CVSS-only scoring is {summary.get('avg_lift_from_cvss_only', 0.0)}, while average semantic-only lift is {summary.get('avg_semantic_only_delta', 0.0)}."
        )
        paragraphs.append(
            f"Graph support appears in {summary.get('graph_supported_count', 0)} records, and semantic support appears in {summary.get('semantic_supported_count', 0)} records. "
            f"Dynamic-vs-CVSS top-{summary.get('top_k', top_k)} overlap is {summary.get('top_overlap_cvss_vs_dynamic', 0)}, indicating meaningful reprioritization."
        )
    if refinement:
        paragraphs.append(
            f"The refinement layer was fit on {refinement.get('record_count', 0)} records with positive-rate {refinement.get('positive_rate', 0.0)}. "
            "This supports an explainable second-stage adjustment rather than replacing the transparent hybrid score."
        )
    if case_studies:
        top = case_studies[0]
        paragraphs.append(
            f"Representative case study: {top.get('cve_id')} moves from {top.get('baseline_cvss_only_score')} to {top.get('final_dynamic_score')} "
            f"with semantic signal {top.get('semantic_signal')} and graph delta {top.get('graph_only_delta')}."
        )

    markdown = "\n\n".join(paragraphs)
    return {
        "summary": summary,
        "case_studies": case_studies,
        "refinement": refinement,
        "markdown": markdown,
    }
