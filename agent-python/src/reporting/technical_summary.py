from __future__ import annotations

from typing import Any, Dict, Iterable, List

from config import APP_VERSION, get_settings
from evaluation.comparative import build_case_study_rows, build_comparison_summary, build_cve_comparison_frame
from evaluation.ml_refinement import summarize_refinement_model


def build_methodology_summary(rows: Iterable[Dict[str, Any]], top_k: int = 10) -> Dict[str, Any]:
    settings = get_settings()
    frame = build_cve_comparison_frame(rows)
    records = frame.to_dict(orient="records") if not frame.empty else []
    summary = build_comparison_summary(records, top_k=top_k) if records else {}
    refinement = summarize_refinement_model(records) if records else {}
    case_studies = build_case_study_rows(records, limit=3) if records else []

    methodology = {
        "pipeline_version": APP_VERSION,
        "analysis_layers": [
            "lexical correlation",
            "semantic similarity",
            "temporal recency",
            "graph centrality and structure",
            "rule-based explainable scoring",
            "optional learned refinement",
            "agent orchestration with critic review",
        ],
        "retrieval_scope": ["cve", "urlhaus", "dread"],
        "graph_metrics": [
            "degree centrality",
            "betweenness centrality",
            "closeness centrality",
            "eigenvector centrality",
            "pagerank",
            "graph density",
            "average clustering",
            "structural strength",
        ],
        "evaluation_outputs": [
            "baseline comparison",
            "ablation deltas",
            "top-k overlap",
            "hit rate",
            "MAP-style comparison",
            "nDCG",
            "case studies",
            "refinement feature importance",
        ],
        "configuration": settings.to_dict(),
    }

    strengths = []
    if summary:
        strengths.append(
            f"Average lift from CVSS-only scoring is {summary.get('avg_lift_from_cvss_only', 0.0)}, showing reprioritization beyond static severity."
        )
        strengths.append(
            f"Semantic support appears in {summary.get('semantic_supported_count', 0)} records and graph support appears in {summary.get('graph_supported_count', 0)} records after strict filtering of invalid CVEs."
        )
        strengths.append(
            f"Dynamic-vs-CVSS top-{summary.get('top_k', top_k)} overlap is {summary.get('top_overlap_cvss_vs_dynamic', 0)}, indicating non-trivial ranking changes."
        )
    if refinement and refinement.get("status") != "degenerate_labels":
        strengths.append(
            f"The second-stage refinement model was fitted on {refinement.get('record_count', 0)} records with positive rate {refinement.get('positive_rate', 0.0)}."
        )

    markdown_lines: List[str] = [
        "# Technical Methodology Summary",
        "",
        f"Pipeline version: **{APP_VERSION}**.",
        "",
        "## System architecture",
        "- Multi-stage threat analysis pipeline over CVE, URLHaus, and Dread intelligence.",
        "- Agent-oriented orchestration with planning, correlation, graph analysis, risk assessment, recommendation, and critic review.",
        "- Config-driven scoring and evaluation settings for reproducibility.",
        "",
        "## Analytical layers",
    ]
    markdown_lines.extend([f"- {item}." for item in methodology["analysis_layers"]])
    markdown_lines.extend([
        "",
        "## Graph analysis",
    ])
    markdown_lines.extend([f"- {item}." for item in methodology["graph_metrics"]])
    markdown_lines.extend([
        "",
        "## Evaluation outputs",
    ])
    markdown_lines.extend([f"- {item}." for item in methodology["evaluation_outputs"]])
    if strengths:
        markdown_lines.extend(["", "## Empirical signals"])
        markdown_lines.extend([f"- {item}" for item in strengths])
    if case_studies:
        markdown_lines.extend(["", "## Representative case studies"])
        for row in case_studies:
            markdown_lines.append(
                f"- {row.get('cve_id')}: CVSS-only {row.get('baseline_cvss_only_score')} -> dynamic {row.get('final_dynamic_score')} (semantic={row.get('semantic_signal')}, graph_delta={row.get('graph_only_delta')})."
            )

    return {
        "methodology": methodology,
        "summary": summary,
        "refinement": refinement,
        "case_studies": case_studies,
        "strengths": strengths,
        "markdown": "\n".join(markdown_lines),
    }
