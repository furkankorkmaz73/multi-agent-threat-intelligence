from __future__ import annotations

from typing import Any, Dict


class CorrelationAgent:
    def summarize(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        evidence = analysis_result.get("evidence", {}) or {}
        feature_breakdown = analysis_result.get("feature_breakdown", {}) or {}
        return {
            "related_urlhaus_count": int(evidence.get("related_urlhaus_count", 0) or 0),
            "related_dread_count": int(evidence.get("related_dread_count", 0) or 0),
            "urlhaus_avg_semantic_score": float(feature_breakdown.get("urlhaus_avg_semantic_score", 0.0) or 0.0),
            "dread_avg_semantic_score": float(feature_breakdown.get("dread_avg_semantic_score", 0.0) or 0.0),
            "urlhaus_overlap": float(feature_breakdown.get("urlhaus_avg_overlap_ratio", 0.0) or 0.0),
            "dread_overlap": float(feature_breakdown.get("dread_avg_overlap_ratio", 0.0) or 0.0),
        }
