from __future__ import annotations

from typing import Any, Dict, List


def calculate_cve_graph_bonus(graph_summary: Dict[str, Any], *, graph_bonus_multiplier: float, graph_bonus_cap: float) -> float:
    centrality = float(graph_summary.get("centrality_score", 0.0) or 0.0)
    ioc_edges = int(graph_summary.get("ioc_edge_count", 0) or 0)
    cross_source_edges = int(graph_summary.get("cross_source_edge_count", 0) or 0)
    avg_conf = float(graph_summary.get("average_edge_confidence", 0.0) or 0.0)

    if ioc_edges <= 0 or cross_source_edges <= 0:
        return 0.0

    support_factor = min(ioc_edges / 4.0, 1.0)
    confidence_factor = max(0.25, min(avg_conf, 1.0))
    raw = centrality * graph_bonus_multiplier * support_factor * confidence_factor
    return round(min(raw, graph_bonus_cap), 2)


def calculate_urlhaus_graph_bonus(graph_summary: Dict[str, Any]) -> float:
    centrality = float(graph_summary.get("centrality_score", 0.0) or 0.0)
    structural_strength = float(graph_summary.get("structural_strength", 0.0) or 0.0)
    return round(min(centrality * 0.35 * max(structural_strength, 0.25), 0.65), 2)


def build_counterfactuals(
    final_score: float,
    graph_bonus: float,
    urlhaus_bonus: float,
    dread_bonus: float,
    llm_bonus: float,
) -> Dict[str, float]:
    return {
        "score_without_graph": round(max(final_score - graph_bonus, 0.0), 2),
        "score_without_urlhaus": round(max(final_score - urlhaus_bonus, 0.0), 2),
        "score_without_dread": round(max(final_score - dread_bonus, 0.0), 2),
        "score_without_llm_context": round(max(final_score - llm_bonus, 0.0), 2),
    }


def build_counterfactual_explanations(counterfactuals: Dict[str, float]) -> List[str]:
    return [
        f"Without graph support, the score would be {counterfactuals.get('score_without_graph', 0.0)}.",
        f"Without URLhaus corroboration, the score would be {counterfactuals.get('score_without_urlhaus', 0.0)}.",
        f"Without Dread corroboration, the score would be {counterfactuals.get('score_without_dread', 0.0)}.",
    ]


def build_source_contributions(
    entity_type: str,
    base_score: float,
    urlhaus_score: float,
    dread_score: float,
    llm_bonus: float,
    graph_bonus: float,
    penalties: Dict[str, float],
) -> Dict[str, float]:
    return {
        "entity_type": entity_type,
        "base_component": round(base_score, 2),
        "urlhaus_component": round(urlhaus_score, 2),
        "dread_component": round(dread_score, 2),
        "llm_component": round(llm_bonus, 2),
        "graph_component": round(graph_bonus, 2),
        **{key: round(float(value), 2) for key, value in penalties.items()},
    }


def summarize_relations(graph_edges: List[Dict[str, Any]]) -> Dict[str, Any]:
    relation_types = sorted({str(edge.get("relation")) for edge in graph_edges if edge.get("relation")})
    provenance = sorted({str(edge.get("provenance")) for edge in graph_edges if edge.get("provenance")})
    avg_confidence = round(sum(float(edge.get("confidence", 0.0)) for edge in graph_edges) / max(len(graph_edges), 1), 4)
    return {
        "relation_count": len(graph_edges),
        "relation_types": relation_types,
        "provenance_sources": provenance,
        "average_confidence": avg_confidence,
    }


def sample_urlhaus_hits(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "url": item.get("url"),
            "threat": item.get("threat"),
            "tags": item.get("tags", []),
            "url_status": item.get("url_status"),
        }
        for item in matches[:5]
    ]


def sample_dread_hits(matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "title": item.get("title"),
            "category": item.get("category"),
            "author": item.get("author"),
        }
        for item in matches[:5]
    ]


def count_non_empty_llm_fields(llm_info: Dict[str, Any]) -> int:
    count = 0
    for key in ["products", "versions", "vuln_type", "impact"]:
        value = llm_info.get(key)
        if isinstance(value, list) and value:
            count += 1
        elif value:
            count += 1
    return count
