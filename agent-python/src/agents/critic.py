from __future__ import annotations

from typing import Any, Dict, List


class CriticAgent:
    def review(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        feature_breakdown = analysis_result.get("feature_breakdown", {}) or {}
        graph_summary = analysis_result.get("graph_summary", {}) or {}
        evidence = analysis_result.get("evidence", {}) or {}

        issues: List[str] = []
        warnings: List[str] = []
        score = float(analysis_result.get("risk_score", 0.0))
        confidence = float(analysis_result.get("confidence", 0.0))
        semantic_signal = max(
            float(feature_breakdown.get("urlhaus_avg_semantic_score", 0.0) or 0.0),
            float(feature_breakdown.get("dread_avg_semantic_score", 0.0) or 0.0),
        )
        graph_bonus = float(feature_breakdown.get("graph_bonus", 0.0) or 0.0)
        centrality = float(graph_summary.get("centrality_score", 0.0) or 0.0)
        correlation_count = int(evidence.get("related_urlhaus_count", 0) or 0) + int(evidence.get("related_dread_count", 0) or 0)

        if score >= 8.5 and correlation_count == 0:
            warnings.append("High score relies mostly on intrinsic severity rather than cross-source corroboration.")
        if graph_bonus > 0 and centrality == 0:
            issues.append("Graph bonus present without non-zero centrality score.")
        if confidence < 0.55 and score >= 7.0:
            warnings.append("Risk is high but confidence remains moderate; analyst review is recommended.")
        if semantic_signal >= 0.25 and correlation_count == 0:
            warnings.append("Semantic signal exists without explicit correlated record counts; retrieval thresholds may be strict.")

        return {
            "status": "passed" if not issues else "needs-review",
            "issues": issues,
            "warnings": warnings,
            "summary": self._build_summary(score=score, confidence=confidence, correlation_count=correlation_count, semantic_signal=semantic_signal, centrality=centrality),
        }

    def _build_summary(self, score: float, confidence: float, correlation_count: int, semantic_signal: float, centrality: float) -> str:
        return (
            f"Critic review: score={round(score,2)}, confidence={round(confidence,2)}, "
            f"correlations={correlation_count}, semantic_signal={round(semantic_signal,3)}, centrality={round(centrality,3)}."
        )
