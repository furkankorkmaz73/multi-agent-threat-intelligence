from __future__ import annotations

from typing import Any, Dict


class RiskAssessmentAgent:
    def summarize(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        feature_breakdown = analysis_result.get("feature_breakdown", {}) or {}
        return {
            "risk_score": float(analysis_result.get("risk_score", 0.0) or 0.0),
            "risk_level": str(analysis_result.get("risk_level", "UNKNOWN")),
            "base_cvss_component": float(feature_breakdown.get("base_cvss_component", 0.0) or 0.0),
            "graph_bonus": float(feature_breakdown.get("graph_bonus", 0.0) or 0.0),
            "final_score": float(feature_breakdown.get("final_score", analysis_result.get("risk_score", 0.0)) or 0.0),
        }
