from __future__ import annotations

from typing import Any, Dict, Iterable, List

import math

import pandas as pd


THRESHOLDS = {
    "strong_reprioritization": 1.0,
    "semantic_support": 0.05,
    "graph_support": 0.05,
}


def _is_valid_cve_record(cve_id: str, description: str) -> bool:
    lowered = f"{cve_id} {description}".lower()
    invalid_markers = ["rejected", "do not use", "reserved", "candidate was issued in error"]
    return not any(marker in lowered for marker in invalid_markers)


def _safe_level(score: float) -> str:
    if score >= 8.5:
        return "CRITICAL"
    if score >= 6.5:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _dcg(values: List[float]) -> float:
    total = 0.0
    for idx, value in enumerate(values, start=1):
        total += float(value) / math.log2(idx + 1)
    return total


def _top_k_hit_rate(reference: List[str], comparator: List[str], k: int) -> float:
    if k <= 0:
        return 0.0
    ref = set(reference[:k])
    if not ref:
        return 0.0
    return round(len(ref.intersection(set(comparator[:k]))) / len(ref), 4)


def _average_precision(reference: List[str], comparator: List[str], k: int) -> float:
    relevant = set(reference[:k])
    if not relevant:
        return 0.0
    hits = 0
    precision_sum = 0.0
    for idx, item in enumerate(comparator[:k], start=1):
        if item in relevant:
            hits += 1
            precision_sum += hits / idx
    return round(precision_sum / len(relevant), 4)


def build_cve_comparison_frame(rows: Iterable[Dict[str, Any]]) -> pd.DataFrame:
    df = pd.DataFrame(list(rows))
    if df.empty:
        return df

    defaults = {
        "cvss_score": 0.0,
        "base_cvss_component": 0.0,
        "recentness_bonus": 0.0,
        "urlhaus_correlation_bonus": 0.0,
        "dread_correlation_bonus": 0.0,
        "graph_bonus": 0.0,
        "risk_score": 0.0,
        "score_without_graph": 0.0,
        "score_without_urlhaus": 0.0,
        "score_without_dread": 0.0,
        "score_without_llm_context": 0.0,
        "urlhaus_avg_semantic_score": 0.0,
        "dread_avg_semantic_score": 0.0,
        "centrality_score": 0.0,
        "avg_edge_confidence": 0.0,
        "relation_count": 0,
        "related_urlhaus_count": 0,
        "related_dread_count": 0,
        "age_days": 0,
    }
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default

    df["baseline_cvss_only_score"] = (df["cvss_score"].fillna(0).astype(float) * 0.55).round(2)
    df["baseline_cvss_only_level"] = df["baseline_cvss_only_score"].apply(_safe_level)
    df["lexical_correlation_component"] = (
        df["urlhaus_correlation_bonus"].fillna(0).astype(float)
        + df["dread_correlation_bonus"].fillna(0).astype(float)
    ).round(2)
    df["semantic_signal"] = df[["urlhaus_avg_semantic_score", "dread_avg_semantic_score"]].fillna(0).max(axis=1).round(4)
    df["correlation_count"] = df["related_urlhaus_count"].fillna(0).astype(int) + df["related_dread_count"].fillna(0).astype(int)
    df["source_diversity_score"] = (df["related_urlhaus_count"].fillna(0).astype(int) > 0).astype(int) + (df["related_dread_count"].fillna(0).astype(int) > 0).astype(int)
    df["graph_support_ratio"] = (df["graph_bonus"].fillna(0).astype(float) / df["risk_score"].replace(0, 1)).round(4)
    df["freshness_signal"] = (1 / (1 + df["age_days"].fillna(0).astype(float).clip(lower=0))).round(6)
    df["baseline_plus_correlation"] = (
        df["base_cvss_component"].fillna(0).astype(float)
        + df["recentness_bonus"].fillna(0).astype(float)
        + df["urlhaus_correlation_bonus"].fillna(0).astype(float)
        + df["dread_correlation_bonus"].fillna(0).astype(float)
    ).round(2)
    df["baseline_plus_semantic"] = (df["baseline_plus_correlation"] + (df["semantic_signal"] * 0.5)).round(2)
    df["baseline_plus_graph"] = (df["baseline_plus_correlation"] + df["graph_bonus"].fillna(0).astype(float)).round(2)
    df["final_dynamic_score"] = df["risk_score"].fillna(0).astype(float).round(2)
    df["lift_from_cvss_only"] = (df["final_dynamic_score"] - df["baseline_cvss_only_score"]).round(2)
    df["lift_from_correlation"] = (df["final_dynamic_score"] - df["baseline_plus_correlation"]).round(2)
    df["graph_only_delta"] = (df["baseline_plus_graph"] - df["baseline_plus_correlation"]).round(2)
    df["semantic_only_delta"] = (df["baseline_plus_semantic"] - df["baseline_plus_correlation"]).round(2)
    return df


def build_comparison_summary(rows: Iterable[Dict[str, Any]], top_k: int = 10) -> Dict[str, Any]:
    df = build_cve_comparison_frame(rows)
    if df.empty:
        return {}

    dynamic_top = df.sort_values(["final_dynamic_score", "cvss_score"], ascending=[False, False]).head(top_k)
    cvss_top = df.sort_values(["baseline_cvss_only_score", "cvss_score"], ascending=[False, False]).head(top_k)
    graph_top = df.sort_values(["baseline_plus_graph", "cvss_score"], ascending=[False, False]).head(top_k)
    semantic_top = df.sort_values(["baseline_plus_semantic", "cvss_score"], ascending=[False, False]).head(top_k)

    dynamic_top_ids = list(dynamic_top["cve_id"].dropna().astype(str))
    cvss_top_ids = list(cvss_top["cve_id"].dropna().astype(str))
    graph_top_ids = list(graph_top["cve_id"].dropna().astype(str))
    semantic_top_ids = list(semantic_top["cve_id"].dropna().astype(str))

    strongly_reprioritized = df[df["lift_from_cvss_only"] >= THRESHOLDS["strong_reprioritization"]]
    graph_supported = df[df["graph_only_delta"] > THRESHOLDS["graph_support"]]
    semantic_supported = df[df["semantic_signal"] >= THRESHOLDS["semantic_support"]]

    relevance = df.set_index("cve_id")["final_dynamic_score"].to_dict()
    ranked = [relevance.get(cve_id, 0.0) for cve_id in dynamic_top_ids]
    ideal = sorted(relevance.values(), reverse=True)[: len(ranked)]
    ndcg_dynamic = round((_dcg(ranked) / max(_dcg(ideal), 1e-8)), 4) if ranked else 0.0

    semantic_delta_mean = float(df["semantic_only_delta"].mean()) if "semantic_only_delta" in df else 0.0
    top_decile = max(int(len(df) * 0.1), 1)
    top_decile_df = df.sort_values(["final_dynamic_score", "cvss_score"], ascending=[False, False]).head(top_decile)

    return {
        "record_count": int(len(df)),
        "avg_cvss_only_score": round(float(df["baseline_cvss_only_score"].mean()), 3),
        "avg_cvss_plus_correlated": round(float(df["baseline_plus_correlation"].mean()), 3),
        "avg_cvss_plus_graph": round(float(df["baseline_plus_graph"].mean()), 3),
        "avg_cvss_plus_semantic": round(float(df["baseline_plus_semantic"].mean()), 3),
        "avg_final_dynamic_score": round(float(df["final_dynamic_score"].mean()), 3),
        "avg_lift_from_cvss_only": round(float(df["lift_from_cvss_only"].mean()), 3),
        "avg_lift_from_correlation": round(float(df["lift_from_correlation"].mean()), 3),
        "avg_graph_only_delta": round(float(df["graph_only_delta"].mean()), 3),
        "avg_semantic_only_delta": round(semantic_delta_mean, 3),
        "avg_semantic_signal": round(float(df["semantic_signal"].mean()), 3),
        "avg_source_diversity_score": round(float(df["source_diversity_score"].mean()), 3),
        "avg_graph_support_ratio": round(float(df["graph_support_ratio"].mean()), 3),
        "top_k": int(top_k),
        "top_overlap_cvss_vs_dynamic": int(len(set(dynamic_top_ids).intersection(set(cvss_top_ids)))),
        "top_overlap_graph_vs_dynamic": int(len(set(dynamic_top_ids).intersection(set(graph_top_ids)))),
        "top_overlap_semantic_vs_dynamic": int(len(set(dynamic_top_ids).intersection(set(semantic_top_ids)))),
        "dynamic_vs_cvss_hit_rate": _top_k_hit_rate(dynamic_top_ids, cvss_top_ids, top_k),
        "dynamic_vs_graph_hit_rate": _top_k_hit_rate(dynamic_top_ids, graph_top_ids, top_k),
        "dynamic_vs_semantic_hit_rate": _top_k_hit_rate(dynamic_top_ids, semantic_top_ids, top_k),
        "map_dynamic_vs_cvss": _average_precision(dynamic_top_ids, cvss_top_ids, top_k),
        "map_dynamic_vs_graph": _average_precision(dynamic_top_ids, graph_top_ids, top_k),
        "map_dynamic_vs_semantic": _average_precision(dynamic_top_ids, semantic_top_ids, top_k),
        "reprioritized_count_lift_ge_1_5": int(len(strongly_reprioritized)),
        "graph_supported_count": int(len(graph_supported)),
        "semantic_supported_count": int(len(semantic_supported)),
        "top_decile_avg_dynamic_score": round(float(top_decile_df["final_dynamic_score"].mean()), 3),
        "top_decile_avg_semantic_signal": round(float(top_decile_df["semantic_signal"].mean()), 3),
        "ndcg_dynamic_top_k": ndcg_dynamic,
        "reprioritized_examples": strongly_reprioritized.sort_values(["lift_from_cvss_only", "final_dynamic_score"], ascending=[False, False])[["cve_id", "baseline_cvss_only_score", "final_dynamic_score", "lift_from_cvss_only", "semantic_signal", "graph_only_delta"]].head(5).to_dict(orient="records"),
    }


def build_case_study_rows(rows: Iterable[Dict[str, Any]], limit: int = 12) -> List[Dict[str, Any]]:
    df = build_cve_comparison_frame(rows)
    if df.empty:
        return []
    defaults = {
        "risk_level": None,
        "confidence": None,
        "description": "",
    }
    for column, default in defaults.items():
        if column not in df.columns:
            df[column] = default
    focus = df.copy()
    focus["case_study_priority"] = (
        focus["lift_from_cvss_only"].fillna(0).astype(float)
        + (focus["semantic_signal"].fillna(0).astype(float) * 2.2)
        + focus["graph_only_delta"].fillna(0).astype(float)
    )
    focus = focus.sort_values(["case_study_priority", "final_dynamic_score"], ascending=[False, False])
    cols = [
        "cve_id",
        "baseline_cvss_only_score",
        "baseline_plus_correlation",
        "baseline_plus_semantic",
        "baseline_plus_graph",
        "final_dynamic_score",
        "lift_from_cvss_only",
        "lift_from_correlation",
        "graph_only_delta",
        "semantic_only_delta",
        "semantic_signal",
        "correlation_count",
        "source_diversity_score",
        "risk_level",
        "confidence",
        "description",
    ]
    return focus[cols].head(limit).to_dict(orient="records")


def build_cve_rows_from_docs(docs: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for d in docs:
        analysis = d.get("analysis", {}) or {}
        ev = analysis.get("evidence", {}) or {}
        fb = analysis.get("feature_breakdown", {}) or {}
        gs = analysis.get("graph_summary", {}) or {}
        cf = analysis.get("counterfactuals", {}) or {}
        sc = analysis.get("source_contributions", {}) or {}
        rs = analysis.get("relation_summary", {}) or {}
        descs = d.get("descriptions", []) or []
        desc = ""
        for item in descs:
            if item.get("lang") == "en":
                desc = item.get("value", "")
                break
        if not desc and descs:
            desc = descs[0].get("value", "")
        if not _is_valid_cve_record(str(d.get("_id") or ""), desc):
            continue
        rows.append({
            "cve_id": d.get("_id"),
            "published": d.get("published"),
            "risk_score": analysis.get("risk_score"),
            "risk_level": analysis.get("risk_level"),
            "confidence": analysis.get("confidence"),
            "cvss_score": ev.get("cvss_score"),
            "age_days": ev.get("age_days"),
            "related_urlhaus_count": ev.get("related_urlhaus_count", 0),
            "related_dread_count": ev.get("related_dread_count", 0),
            "centrality_score": gs.get("centrality_score"),
            "avg_edge_confidence": gs.get("average_edge_confidence"),
            "graph_density": gs.get("graph_density"),
            "structural_strength": gs.get("structural_strength"),
            "base_cvss_component": fb.get("base_cvss_component"),
            "recentness_bonus": fb.get("recentness_bonus"),
            "urlhaus_correlation_bonus": fb.get("urlhaus_correlation_bonus"),
            "dread_correlation_bonus": fb.get("dread_correlation_bonus"),
            "urlhaus_avg_semantic_score": fb.get("urlhaus_avg_semantic_score"),
            "dread_avg_semantic_score": fb.get("dread_avg_semantic_score"),
            "graph_bonus": fb.get("graph_bonus"),
            "pre_graph_score": fb.get("pre_graph_score"),
            "final_score": fb.get("final_score"),
            "score_without_graph": cf.get("score_without_graph"),
            "score_without_urlhaus": cf.get("score_without_urlhaus"),
            "score_without_dread": cf.get("score_without_dread"),
            "score_without_llm_context": cf.get("score_without_llm_context"),
            "base_component": sc.get("base_component"),
            "graph_component": sc.get("graph_component"),
            "relation_count": rs.get("relation_count"),
            "diagnosis": analysis.get("diagnosis"),
            "pipeline_version": analysis.get("pipeline_version") or (analysis.get("persistence_meta", {}) or {}).get("pipeline_version"),
            "recommendation_count": len(analysis.get("recommendations", []) or []),
            "critic_status": (analysis.get("critic_review", {}) or {}).get("status"),
            "description": desc[:300],
            "keywords": ", ".join(ev.get("keywords", [])[:8]),
        })
    return rows
