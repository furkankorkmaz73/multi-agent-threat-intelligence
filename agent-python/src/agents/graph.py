from __future__ import annotations

from typing import Any, Dict


class GraphAnalysisAgent:
    def summarize_for_trace(self, graph_summary: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "node_count": int(graph_summary.get("node_count", 0) or 0),
            "edge_count": int(graph_summary.get("edge_count", 0) or 0),
            "centrality_score": float(graph_summary.get("centrality_score", 0.0) or 0.0),
            "graph_density": float(graph_summary.get("graph_density", 0.0) or 0.0),
            "structural_strength": float(graph_summary.get("structural_strength", 0.0) or 0.0),
        }
