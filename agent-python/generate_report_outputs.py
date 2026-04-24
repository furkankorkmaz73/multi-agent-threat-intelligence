from pathlib import Path
import json

import matplotlib.pyplot as plt
import pandas as pd
from pymongo import MongoClient

from src.evaluation.comparative import (
    build_case_study_rows,
    build_comparison_summary,
    build_cve_comparison_frame,
    build_cve_rows_from_docs,
)
from src.evaluation.ml_refinement import (
    attach_refinement_preview,
    summarize_refinement_model,
)
from src.reporting.narrative import build_report_brief
from src.reporting.technical_summary import build_methodology_summary

out = Path("report_outputs")
out.mkdir(exist_ok=True)

db = MongoClient("mongodb://127.0.0.1:27017")["threat_intel"]

projection = {
    "_id": 1,
    "published": 1,
    "descriptions": 1,
    "analysis.risk_score": 1,
    "analysis.risk_level": 1,
    "analysis.confidence": 1,
    "analysis.counterfactuals": 1,
    "analysis.source_contributions": 1,
    "analysis.relation_summary": 1,
    "analysis.evidence.cvss_score": 1,
    "analysis.evidence.age_days": 1,
    "analysis.evidence.related_urlhaus_count": 1,
    "analysis.evidence.related_dread_count": 1,
    "analysis.evidence.keywords": 1,
    "analysis.feature_breakdown.base_cvss_component": 1,
    "analysis.feature_breakdown.recentness_bonus": 1,
    "analysis.feature_breakdown.urlhaus_correlation_bonus": 1,
    "analysis.feature_breakdown.dread_correlation_bonus": 1,
    "analysis.feature_breakdown.graph_bonus": 1,
    "analysis.feature_breakdown.pre_graph_score": 1,
    "analysis.feature_breakdown.final_score": 1,
    "analysis.feature_breakdown.urlhaus_avg_semantic_score": 1,
    "analysis.feature_breakdown.dread_avg_semantic_score": 1,
    "analysis.graph_summary.centrality_score": 1,
    "analysis.graph_summary.average_edge_confidence": 1,
    "analysis.graph_summary.graph_density": 1,
    "analysis.graph_summary.structural_strength": 1,
    "analysis.diagnosis": 1,
}

cve_docs = list(db.cve_intel.find({"analysis": {"$exists": True}}, projection))
rows = build_cve_rows_from_docs(cve_docs)
frame = build_cve_comparison_frame(rows)
if not frame.empty:
    frame = pd.DataFrame(attach_refinement_preview(frame.to_dict(orient="records")))
    frame = frame.sort_values(["risk_score", "cvss_score"], ascending=[False, False])
    frame.head(20).to_csv(out / "top20_cves.csv", index=False)
    frame.sort_values(["lift_from_cvss_only", "final_dynamic_score"], ascending=[False, False]).head(25).to_csv(out / "cve_reprioritized.csv", index=False)

    case_studies = pd.DataFrame(build_case_study_rows(frame.to_dict(orient="records"), limit=20))
    if not case_studies.empty:
        case_studies.to_csv(out / "cve_case_studies.csv", index=False)

    summary = build_comparison_summary(frame.to_dict(orient="records"), top_k=10)
    (out / "comparison_summary.json").write_text(json.dumps(summary, indent=2))

    refinement = summarize_refinement_model(frame.to_dict(orient="records"))
    (out / "refinement_summary.json").write_text(json.dumps(refinement, indent=2))

    brief = build_report_brief(frame.to_dict(orient="records"), top_k=10)
    (out / "report_brief.json").write_text(json.dumps(brief, indent=2))
    (out / "report_brief.md").write_text(brief.get("markdown", ""))

    methodology = build_methodology_summary(frame.to_dict(orient="records"), top_k=10)
    (out / "methodology_summary.json").write_text(json.dumps(methodology, indent=2))
    (out / "methodology_summary.md").write_text(methodology.get("markdown", ""))

    plt.figure(figsize=(8, 5))
    semantic_cols = frame[["cve_id", "semantic_signal", "lift_from_cvss_only"]].sort_values("semantic_signal", ascending=False).head(20)
    plt.bar(semantic_cols["cve_id"], semantic_cols["semantic_signal"])
    plt.xticks(rotation=75, ha="right")
    plt.tight_layout()
    plt.savefig(out / "semantic_vs_lift.png")
    plt.close()

    plt.figure(figsize=(8, 5))
    top = frame.sort_values(["final_dynamic_score"], ascending=[False]).head(15)
    plt.plot(top["cve_id"], top["baseline_cvss_only_score"], label="CVSS only")
    plt.plot(top["cve_id"], top["baseline_plus_correlation"], label="+ correlation")
    plt.plot(top["cve_id"], top["baseline_plus_semantic"], label="+ semantic")
    plt.plot(top["cve_id"], top["baseline_plus_graph"], label="+ graph")
    plt.plot(top["cve_id"], top["final_dynamic_score"], label="final")
    plt.xticks(rotation=75, ha="right")
    plt.legend()
    plt.tight_layout()
    plt.savefig(out / "cve_ablation_lines.png")
    plt.close()
