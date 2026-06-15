from __future__ import annotations

from typing import Any, Dict, List


class CriticAgent:
    def review(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        feature_breakdown = analysis_result.get("feature_breakdown", {}) or {}
        graph_summary = analysis_result.get("graph_summary", {}) or {}
        evidence = analysis_result.get("evidence", {}) or {}

        issues: List[str] = []
        warnings: List[str] = []
        recommended_actions: List[str] = []
        score = float(analysis_result.get("risk_score", 0.0))
        confidence = float(analysis_result.get("confidence", 0.0))
        semantic_signal = max(
            float(feature_breakdown.get("urlhaus_avg_semantic_score", 0.0) or 0.0),
            float(feature_breakdown.get("dread_avg_semantic_score", 0.0) or 0.0),
        )
        graph_bonus = float(feature_breakdown.get("graph_bonus", 0.0) or 0.0)
        graph_signal = float(feature_breakdown.get("graph_signal", 0.0) or 0.0)
        correlation_signal = float(feature_breakdown.get("correlation_signal", 0.0) or 0.0)
        centrality = float(graph_summary.get("centrality_score", 0.0) or 0.0)
        correlation_count = int(evidence.get("related_urlhaus_count", 0) or 0) + int(evidence.get("related_dread_count", 0) or 0)
        rejected_or_manual_count = self._rejected_or_manual_count(evidence)
        cross_source_edge_count = int(graph_summary.get("cross_source_edge_count", 0) or 0)
        dread_only = int(evidence.get("related_dread_count", 0) or 0) > 0 and int(evidence.get("related_urlhaus_count", 0) or 0) == 0
        llm_context_present = bool(
            evidence.get("llm_products")
            or evidence.get("llm_versions")
            or evidence.get("llm_vuln_type")
            or evidence.get("llm_impact")
        )

        if score >= 8.5 and correlation_count == 0:
            warnings.append("High score relies mostly on intrinsic severity rather than cross-source corroboration.")
        if graph_bonus > 0 and centrality == 0:
            issues.append("Graph bonus present without non-zero centrality score.")
        if confidence < 0.55 and score >= 7.0:
            warnings.append("Risk is high but confidence remains moderate; analyst review is recommended.")
            recommended_actions.append("Queue for analyst review before escalation.")
        if dread_only and score >= 8.5:
            issues.append("Dread-only accepted evidence is associated with CRITICAL risk; verify that stronger corroboration is not required.")
            recommended_actions.append("Require stronger corroboration before treating Dread-only support as critical escalation.")
        elif dread_only and score >= 7.0:
            warnings.append("Dread-only accepted evidence is associated with high risk; keep confidence bounded and review manually.")
            recommended_actions.append("Review Dread-only high-risk item for corroborating URLhaus, KEV, EPSS, or exact CVE evidence.")
        if rejected_or_manual_count > 0 and correlation_signal > 0 and correlation_count == 0:
            issues.append("Rejected or manual-review correlation appears to contribute positive correlation_signal.")
            recommended_actions.append("Inspect correlation decision gates and exclude rejected/manual-review evidence from risk signals.")
        if graph_signal > 0 and correlation_count == 0 and cross_source_edge_count == 0:
            issues.append("graph_signal is positive without accepted graph or correlation evidence.")
            recommended_actions.append("Inspect graph evidence inputs and require accepted evidence for graph risk support.")
        if llm_context_present and correlation_signal > 0 and correlation_count == 0:
            warnings.append("LLM-derived context appears near a positive correlation signal without accepted deterministic evidence.")
            recommended_actions.append("Treat LLM output as assistive context only, not accepted evidence.")
        if (evidence.get("epss_available") is False or evidence.get("kev_status_known") is False) and confidence < 0.7:
            recommended_actions.append("Explain missing EPSS/KEV or weak external evidence as a confidence limitation, not risk-zeroing.")
        if semantic_signal >= 0.25 and correlation_count == 0:
            warnings.append("Semantic signal exists without explicit correlated record counts; retrieval thresholds may be strict.")

        return {
            "status": "passed" if not issues else "needs-review",
            "issues": issues,
            "warnings": warnings,
            "recommended_actions": recommended_actions,
            "summary": self._build_summary(score=score, confidence=confidence, correlation_count=correlation_count, semantic_signal=semantic_signal, centrality=centrality),
        }

    def _rejected_or_manual_count(self, evidence: Dict[str, Any]) -> int:
        total = 0
        for key in ("urlhaus_match_stats", "dread_match_stats"):
            stats = evidence.get(key, {}) or {}
            total += int(stats.get("rejected_evidence_count", stats.get("rejected_match_count", 0)) or 0)
            total += int(stats.get("manual_review_evidence_count", stats.get("manual_review_match_count", 0)) or 0)
        return total

    def _build_summary(self, score: float, confidence: float, correlation_count: int, semantic_signal: float, centrality: float) -> str:
        return (
            f"Critic review: score={round(score,2)}, confidence={round(confidence,2)}, "
            f"correlations={correlation_count}, semantic_signal={round(semantic_signal,3)}, centrality={round(centrality,3)}."
        )
