from __future__ import annotations

from typing import Any, Dict, List, Optional

from agents.llm_helper import generate_explanation
from analysis.correlator import DREAD_CLASSIFIERS, score_dread_matches, score_urlhaus_matches
from analysis.graph_builder import GraphBuilder
from analysis.keyword_extractor import extract_keywords
from analysis.scoring import calculate_age_days, calculate_age_penalty, calculate_recentness_bonus, extract_cvss_score, level_from_score
from config import get_settings


SETTINGS = get_settings()


class RiskEngine:
    def __init__(self) -> None:
        self.graph_builder = GraphBuilder()
        self.weights = SETTINGS.scoring

    def evaluate_cve(
        self,
        data: Dict[str, Any],
        db: Optional[Any] = None,
        llm_info: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cve_id = data.get("_id", "unknown-cve")
        description = self._get_primary_description(data)
        llm_info = llm_info or {}

        if self._is_invalid_cve_record(cve_id, description):
            return self._build_invalid_cve_analysis(cve_id, description)

        cvss_score, cvss_version = extract_cvss_score(data.get("metrics", {}))
        keywords = extract_keywords(description, cve_id)
        age_days = calculate_age_days(data.get("published"))
        recentness_bonus = calculate_recentness_bonus(age_days)
        age_penalty = calculate_age_penalty(age_days)

        urlhaus_matches = db.find_related_urlhaus(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []
        dread_matches = db.find_related_dread(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []

        urlhaus_score, urlhaus_explanations, urlhaus_stats = score_urlhaus_matches(urlhaus_matches, keywords, data.get("published"))
        dread_score, dread_explanations, dread_categories, dread_stats = score_dread_matches(dread_matches, keywords, data.get("published"))
        llm_bonus, llm_explanations = self._score_llm_cve_info(llm_info)

        base_score = self.weights.zero_cvss_fallback if cvss_score == 0 else cvss_score * self.weights.base_cvss_multiplier
        pre_graph_score = base_score + recentness_bonus + urlhaus_score + dread_score + llm_bonus - age_penalty

        graph = self.graph_builder.build_entity_graph(
            entity_type="cve",
            entity_id=cve_id,
            record=data,
            evidence={
                "keywords": keywords,
                "cvss_score": cvss_score,
                "llm_products": llm_info.get("products", []),
                "llm_vuln_type": llm_info.get("vuln_type"),
                "llm_impact": llm_info.get("impact"),
                "dread_categories": dread_categories,
                "sample_urlhaus_hits": self._sample_urlhaus_hits(urlhaus_matches),
                "sample_dread_hits": self._sample_dread_hits(dread_matches),
            },
        )
        graph_summary = self.graph_builder.summarize_graph(graph, root_node=f"cve:{cve_id}")
        graph_edges = self.graph_builder.export_graph_edges(graph, limit=25)
        graph_bonus = self._calculate_graph_bonus(graph_summary)

        raw_score = pre_graph_score + graph_bonus
        final_score = max(0.0, min(round(raw_score, 2), 10.0))
        risk_level = level_from_score(final_score)

        counterfactuals = self._build_counterfactuals(final_score, graph_bonus, urlhaus_score, dread_score, llm_bonus)
        source_contributions = self._build_source_contributions("cve", base_score, urlhaus_score, dread_score, llm_bonus, graph_bonus, {"age_penalty": age_penalty})
        relation_summary = self._summarize_relations(graph_edges)
        confidence = self._calculate_confidence(
            has_cvss=cvss_score > 0,
            urlhaus_match_count=len(urlhaus_matches),
            dread_match_count=len(dread_matches),
            keyword_count=len(keywords),
            llm_fields_count=self._count_non_empty_llm_fields(llm_info),
            graph_score=float(graph_summary.get("centrality_score", 0.0)),
        )

        explanations = [f"Base risk derived from CVSS ({cvss_version}) score: {cvss_score}."]
        if age_days is not None:
            explanations.append(f"Estimated vulnerability age: {age_days} day(s).")
        if recentness_bonus > 0:
            explanations.append("Recently published or updated vulnerability increased priority.")
        if age_penalty > 0:
            explanations.append("Older vulnerability record reduced current priority score.")
        explanations.extend(urlhaus_explanations)
        explanations.extend(dread_explanations)
        explanations.extend(llm_explanations)
        if graph_bonus > 0:
            explanations.append(f"Graph connectivity increased the score by {round(graph_bonus, 2)}.")
        explanations.extend(self._build_counterfactual_explanations(counterfactuals))
        if not urlhaus_matches and not dread_matches:
            explanations.append("No cross-source corroboration found; score relies mainly on CVE metadata.")

        llm_text = generate_explanation({
            "entity_type": "cve",
            "entity_id": cve_id,
            "risk_score": final_score,
            "risk_level": risk_level,
            "cvss_score": cvss_score,
            "graph_summary": graph_summary,
            "counterfactuals": counterfactuals,
            "semantic_overlap": {
                "urlhaus": urlhaus_stats.get("avg_semantic_score", 0.0),
                "dread": dread_stats.get("avg_semantic_score", 0.0),
            },
        })
        if llm_text:
            explanations = [llm_text] + explanations

        orchestration_trace = [
            {"agent": "planner", "action": "build-analysis-plan", "status": "completed", "details": {"source": "cve", "keyword_count": len(keywords)}},
            {"agent": "correlation", "action": "collect-cross-source-evidence", "status": "completed", "details": {"urlhaus_candidates": len(urlhaus_matches), "dread_candidates": len(dread_matches), "semantic_urlhaus": urlhaus_stats.get("avg_semantic_score", 0.0), "semantic_dread": dread_stats.get("avg_semantic_score", 0.0)}},
            {"agent": "graph", "action": "build-entity-graph", "status": "completed", "details": {"node_count": graph_summary.get("node_count", 0), "edge_count": graph_summary.get("edge_count", 0)}},
            {"agent": "risk", "action": "score-risk", "status": "completed", "details": {"pre_graph_score": round(pre_graph_score, 2), "graph_bonus": round(graph_bonus, 2), "final_score": final_score}},
            {"agent": "critic", "action": "sanity-check-score", "status": "completed", "details": {"confidence": confidence, "risk_level": risk_level}},
        ]

        return {
            "entity_type": "cve",
            "entity_id": cve_id,
            "risk_score": final_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "diagnosis": f"{cve_id} evaluated as {risk_level} (dynamic score={final_score}, base CVSS={cvss_score}).",
            "explanation": explanations,
            "evidence": {
                "keywords": keywords,
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "age_days": age_days,
                "related_urlhaus_count": len(urlhaus_matches),
                "related_dread_count": len(dread_matches),
                "dread_categories": dread_categories,
                "sample_urlhaus_hits": self._sample_urlhaus_hits(urlhaus_matches),
                "sample_dread_hits": self._sample_dread_hits(dread_matches),
                "llm_products": llm_info.get("products", []),
                "llm_versions": llm_info.get("versions", []),
                "llm_vuln_type": llm_info.get("vuln_type"),
                "llm_impact": llm_info.get("impact"),
                "urlhaus_match_stats": urlhaus_stats,
                "dread_match_stats": dread_stats,
            },
            "feature_breakdown": {
                "base_cvss_component": round(base_score, 2),
                "recentness_bonus": round(recentness_bonus, 2),
                "urlhaus_correlation_bonus": round(urlhaus_score, 2),
                "dread_correlation_bonus": round(dread_score, 2),
                "llm_context_bonus": round(llm_bonus, 2),
                "age_penalty": round(age_penalty, 2),
                "graph_centrality_score": round(float(graph_summary.get("centrality_score", 0.0)), 4),
                "graph_bonus": round(graph_bonus, 2),
                "urlhaus_avg_overlap_ratio": round(urlhaus_stats.get("avg_overlap_ratio", 0.0), 4),
                "dread_avg_overlap_ratio": round(dread_stats.get("avg_overlap_ratio", 0.0), 4),
                "urlhaus_avg_semantic_score": round(urlhaus_stats.get("avg_semantic_score", 0.0), 4),
                "dread_avg_semantic_score": round(dread_stats.get("avg_semantic_score", 0.0), 4),
                "pre_graph_score": round(pre_graph_score, 2),
                "raw_score_before_clamp": round(raw_score, 2),
                "ml_refinement_delta": 0.0,
                "final_score": final_score,
            },
            "graph_summary": graph_summary,
            "graph_edges": graph_edges,
            "counterfactuals": counterfactuals,
            "source_contributions": source_contributions,
            "relation_summary": relation_summary,
            "orchestration_trace": orchestration_trace,
        }

    def evaluate_urlhaus(self, data: Dict[str, Any], db: Optional[Any] = None) -> Dict[str, Any]:
        threat = (data.get("threat") or "unknown").lower()
        tags = [str(tag).lower() for tag in (data.get("tags") or [])]
        url = data.get("url", "")
        status = (data.get("url_status") or "").lower()
        text = " ".join([threat, url, " ".join(tags)])
        keywords = extract_keywords(text)

        related_cves = db.find_related_cves(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []
        related_dread = db.find_related_dread(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []

        base_score = 1.8
        explanations = ["Base risk assigned from malicious URL / IOC feed presence."]
        category_score, category_notes = self._score_urlhaus_category(threat, tags)
        status_score, status_notes = self._score_urlhaus_status(status)
        structure_score, structure_notes = self._score_url_structure(url)
        correlation_score = min((len(related_cves) * 0.12) + (len(related_dread) * 0.10), 1.2)
        score = base_score + category_score + status_score + structure_score + correlation_score
        explanations.extend(category_notes + status_notes + structure_notes)
        if correlation_score > 0:
            explanations.append("Cross-source evidence raised the IOC priority.")

        graph = self.graph_builder.build_entity_graph(
            entity_type="urlhaus",
            entity_id=url or data.get("urlhaus_id") or "unknown-urlhaus",
            record=data,
            evidence={
                "threat": threat,
                "url_status": status,
                "tags": tags,
                "keywords": keywords,
                "sample_related_cves": [{"cve_id": item.get("_id")} for item in related_cves[:5]],
                "sample_dread_hits": self._sample_dread_hits(related_dread),
            },
        )
        graph_summary = self.graph_builder.summarize_graph(graph, root_node=f"urlhaus:{url or data.get('urlhaus_id') or 'unknown-urlhaus'}")
        graph_edges = self.graph_builder.export_graph_edges(graph, limit=20)
        graph_bonus = min(float(graph_summary.get("centrality_score", 0.0)) * 0.9, 1.1)
        final_score = max(0.0, min(round(score + graph_bonus, 2), 10.0))
        risk_level = level_from_score(final_score)
        confidence = self._calculate_confidence(False, len(related_cves), len(related_dread), len(keywords), 0, float(graph_summary.get("centrality_score", 0.0)))
        counterfactuals = self._build_counterfactuals(final_score, graph_bonus, correlation_score, 0.0, 0.0)
        entity_id = data.get("urlhaus_id") or data.get("url") or "unknown-urlhaus"

        return {
            "entity_type": "urlhaus",
            "entity_id": entity_id,
            "risk_score": final_score,
            "risk_score": final_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "diagnosis": f"IOC evaluated as {risk_level} (dynamic score={final_score}).",
            "explanation": explanations,
            "evidence": {
                "keywords": keywords,
                "threat": threat,
                "url_status": status,
                "tags": tags,
                "related_cve_count": len(related_cves),
                "related_dread_count": len(related_dread),
                "sample_related_cves": [{"cve_id": item.get("_id")} for item in related_cves[:5]],
                "sample_dread_hits": self._sample_dread_hits(related_dread),
            },
            "feature_breakdown": {
                "base_feed_component": round(base_score, 2),
                "category_bonus": round(category_score, 2),
                "status_bonus": round(status_score, 2),
                "url_structure_bonus": round(structure_score, 2),
                "cross_source_bonus": round(correlation_score, 2),
                "graph_bonus": round(graph_bonus, 2),
                "final_score": final_score,
            },
            "graph_summary": graph_summary,
            "graph_edges": graph_edges,
            "counterfactuals": counterfactuals,
            "source_contributions": {"base_component": round(base_score, 2), "graph_component": round(graph_bonus, 2)},
            "relation_summary": self._summarize_relations(graph_edges),
            "orchestration_trace": [{"agent": "ioc-risk", "action": "score-urlhaus-ioc", "status": "completed", "details": {"related_cves": len(related_cves), "related_dread": len(related_dread)}}],
        }

    def evaluate_dread(self, data: Dict[str, Any], db: Optional[Any] = None, llm_cls: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        llm_cls = llm_cls or {}
        combined = f"{data.get('title', '')} {data.get('content', '')}".strip().lower()
        keywords = extract_keywords(combined)
        related_cves = db.find_related_cves(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []
        related_urlhaus = db.find_related_urlhaus(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []
        categories = self._classify_dread_post(combined)
        matched_terms = self._extract_dread_matched_terms(combined)

        base_score = 1.2
        category_bonus = min(len(categories) * 0.4, 1.4)
        cve_bonus = min(len(related_cves) * 0.12, 1.0)
        urlhaus_bonus = min(len(related_urlhaus) * 0.10, 0.9)
        llm_bonus = 0.25 if llm_cls.get("category") else 0.0
        final_pre_graph = base_score + category_bonus + cve_bonus + urlhaus_bonus + llm_bonus

        graph = self.graph_builder.build_entity_graph(
            entity_type="dread",
            entity_id=str(data.get("title") or data.get("_id") or "unknown-dread").strip().lower()[:80],
            record=data,
            evidence={
                "keywords": keywords,
                "matched_terms": matched_terms,
                "categories": categories,
                "llm_category": llm_cls.get("category"),
                "sample_related_cves": [{"cve_id": item.get("_id")} for item in related_cves[:5]],
                "sample_related_urlhaus": self._sample_urlhaus_hits(related_urlhaus),
            },
        )
        root = f"dread:{str((data.get('title') or data.get('_id') or 'unknown-dread')).strip().lower()[:80]}"
        graph_summary = self.graph_builder.summarize_graph(graph, root_node=root)
        graph_edges = self.graph_builder.export_graph_edges(graph, limit=20)
        graph_bonus = min(float(graph_summary.get("centrality_score", 0.0)) * 0.95, 1.0)
        final_score = max(0.0, min(round(final_pre_graph + graph_bonus, 2), 10.0))
        risk_level = level_from_score(final_score)
        confidence = self._calculate_confidence(False, len(related_urlhaus), len(related_cves), len(keywords), 1 if llm_cls else 0, float(graph_summary.get("centrality_score", 0.0)))

        return {
            "entity_type": "dread",
            "entity_id": data.get("_id") or data.get("title") or "unknown-dread",
            "risk_score": final_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "diagnosis": f"Dark-web post evaluated as {risk_level} (dynamic score={final_score}).",
            "explanation": [
                "Dark-web forum presence created a base risk signal.",
                "Rule-based and cross-source evidence were combined for prioritization.",
            ],
            "evidence": {
                "keywords": keywords,
                "categories": categories,
                "matched_terms": matched_terms,
                "llm_category": llm_cls.get("category"),
                "related_cve_count": len(related_cves),
                "related_urlhaus_count": len(related_urlhaus),
                "sample_related_cves": [{"cve_id": item.get("_id")} for item in related_cves[:5]],
                "sample_related_urlhaus": self._sample_urlhaus_hits(related_urlhaus),
            },
            "feature_breakdown": {
                "base_darkweb_component": round(base_score, 2),
                "category_bonus": round(category_bonus, 2),
                "related_cve_bonus": round(cve_bonus, 2),
                "related_urlhaus_bonus": round(urlhaus_bonus, 2),
                "llm_bonus": round(llm_bonus, 2),
                "graph_bonus": round(graph_bonus, 2),
                "final_score": final_score,
            },
            "graph_summary": graph_summary,
            "graph_edges": graph_edges,
            "counterfactuals": self._build_counterfactuals(final_score, graph_bonus, urlhaus_bonus, cve_bonus, llm_bonus),
            "source_contributions": {"base_component": round(base_score, 2), "graph_component": round(graph_bonus, 2)},
            "relation_summary": self._summarize_relations(graph_edges),
            "orchestration_trace": [{"agent": "darkweb-risk", "action": "score-dread-post", "status": "completed", "details": {"category_count": len(categories), "related_cves": len(related_cves), "related_urlhaus": len(related_urlhaus)}}],
        }


    def _calculate_graph_bonus(self, graph_summary: Dict[str, Any]) -> float:
        centrality = float(graph_summary.get("centrality_score", 0.0) or 0.0)
        ioc_edges = int(graph_summary.get("ioc_edge_count", 0) or 0)
        cross_source_edges = int(graph_summary.get("cross_source_edge_count", 0) or 0)
        avg_conf = float(graph_summary.get("average_edge_confidence", 0.0) or 0.0)

        if ioc_edges <= 0 or cross_source_edges <= 0:
            return 0.0

        support_factor = min(ioc_edges / 4.0, 1.0)
        confidence_factor = max(0.25, min(avg_conf, 1.0))
        raw = centrality * self.weights.graph_bonus_multiplier * support_factor * confidence_factor
        return round(min(raw, self.weights.graph_bonus_cap), 2)

    def _is_invalid_cve_record(self, cve_id: str, description: str) -> bool:
        lowered = f"{cve_id} {description}".lower()
        invalid_markers = ["rejected", "do not use", "reserved", "candidate was issued in error"]
        return any(marker in lowered for marker in invalid_markers)

    def _build_invalid_cve_analysis(self, cve_id: str, description: str) -> Dict[str, Any]:
        note = "Record was excluded from prioritization because the CVE entry is rejected, reserved, or explicitly marked invalid."
        return {
            "entity_type": "cve",
            "entity_id": cve_id,
            "risk_score": 0.0,
            "risk_level": "LOW",
            "confidence": 0.95,
            "diagnosis": f"{cve_id} excluded from dynamic prioritization as an invalid CVE record.",
            "explanation": [note],
            "evidence": {"keywords": [], "cvss_score": 0.0, "age_days": None, "related_urlhaus_count": 0, "related_dread_count": 0},
            "feature_breakdown": {
                "base_cvss_component": 0.0, "recentness_bonus": 0.0, "urlhaus_correlation_bonus": 0.0,
                "dread_correlation_bonus": 0.0, "llm_context_bonus": 0.0, "age_penalty": 0.0,
                "graph_centrality_score": 0.0, "graph_bonus": 0.0, "pre_graph_score": 0.0,
                "raw_score_before_clamp": 0.0, "ml_refinement_delta": 0.0, "final_score": 0.0,
                "urlhaus_avg_overlap_ratio": 0.0, "dread_avg_overlap_ratio": 0.0,
                "urlhaus_avg_semantic_score": 0.0, "dread_avg_semantic_score": 0.0,
            },
            "graph_summary": {"node_count": 0, "edge_count": 0, "centrality_score": 0.0, "cross_source_edge_count": 0, "ioc_edge_count": 0},
            "graph_edges": [],
            "counterfactuals": {"score_without_graph": 0.0, "score_without_urlhaus": 0.0, "score_without_dread": 0.0, "score_without_llm_context": 0.0},
            "source_contributions": {"entity_type": "cve", "base_component": 0.0, "urlhaus_component": 0.0, "dread_component": 0.0, "llm_component": 0.0, "graph_component": 0.0},
            "relation_summary": {"relation_count": 0, "relation_types": [], "provenance_sources": [], "average_confidence": 0.0},
            "orchestration_trace": [{"agent": "risk", "action": "skip-invalid-cve", "status": "completed", "details": {"reason": "invalid_cve_marker"}}],
        }

    def _get_primary_description(self, data: Dict[str, Any]) -> str:
        descriptions = data.get("descriptions", []) or []
        for item in descriptions:
            if item.get("lang", "").lower() == "en":
                return item.get("value", "")
        return descriptions[0].get("value", "") if descriptions else ""

    def _score_llm_cve_info(self, llm_info: Dict[str, Any]) -> tuple[float, List[str]]:
        if not llm_info:
            return 0.0, []
        score = 0.0
        explanations: List[str] = []
        if llm_info.get("products"):
            score += min(len(llm_info.get("products", [])) * 0.08, 0.24)
            explanations.append("Extracted affected product context strengthened exposure reasoning.")
        if llm_info.get("vuln_type"):
            score += 0.12
            explanations.append("Identified vulnerability type improved contextual scoring.")
        if llm_info.get("impact"):
            score += 0.10
            explanations.append("Attacker impact context increased prioritization confidence.")
        return min(score, self.weights.llm_bonus_cap), explanations

    def _calculate_confidence(self, has_cvss: bool, urlhaus_match_count: int, dread_match_count: int, keyword_count: int, llm_fields_count: int, graph_score: float) -> float:
        confidence = 0.35
        if has_cvss:
            confidence += 0.15
        confidence += min(urlhaus_match_count * 0.03, 0.12)
        confidence += min(dread_match_count * 0.03, 0.12)
        confidence += min(keyword_count * 0.01, 0.10)
        confidence += min(llm_fields_count * 0.03, 0.09)
        confidence += min(graph_score * 0.15, 0.12)
        return round(min(confidence, 0.98), 3)

    def _count_non_empty_llm_fields(self, llm_info: Dict[str, Any]) -> int:
        count = 0
        for key in ["products", "versions", "vuln_type", "impact"]:
            value = llm_info.get(key)
            if isinstance(value, list) and value:
                count += 1
            elif value:
                count += 1
        return count

    def _sample_urlhaus_hits(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [{"url": item.get("url"), "threat": item.get("threat"), "tags": item.get("tags", []), "url_status": item.get("url_status")} for item in matches[:5]]

    def _sample_dread_hits(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [{"title": item.get("title"), "category": item.get("category"), "author": item.get("author")} for item in matches[:5]]

    def _build_counterfactuals(self, final_score: float, graph_bonus: float, urlhaus_bonus: float, dread_bonus: float, llm_bonus: float) -> Dict[str, float]:
        return {
            "score_without_graph": round(max(final_score - graph_bonus, 0.0), 2),
            "score_without_urlhaus": round(max(final_score - urlhaus_bonus, 0.0), 2),
            "score_without_dread": round(max(final_score - dread_bonus, 0.0), 2),
            "score_without_llm_context": round(max(final_score - llm_bonus, 0.0), 2),
        }

    def _build_counterfactual_explanations(self, counterfactuals: Dict[str, float]) -> List[str]:
        return [
            f"Without graph support, the score would be {counterfactuals.get('score_without_graph', 0.0)}.",
            f"Without URLhaus corroboration, the score would be {counterfactuals.get('score_without_urlhaus', 0.0)}.",
            f"Without Dread corroboration, the score would be {counterfactuals.get('score_without_dread', 0.0)}.",
        ]

    def _build_source_contributions(self, entity_type: str, base_score: float, urlhaus_score: float, dread_score: float, llm_bonus: float, graph_bonus: float, penalties: Dict[str, float]) -> Dict[str, float]:
        return {
            "entity_type": entity_type,
            "base_component": round(base_score, 2),
            "urlhaus_component": round(urlhaus_score, 2),
            "dread_component": round(dread_score, 2),
            "llm_component": round(llm_bonus, 2),
            "graph_component": round(graph_bonus, 2),
            **{key: round(float(value), 2) for key, value in penalties.items()},
        }

    def _summarize_relations(self, graph_edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        relation_types = sorted({str(edge.get("relation")) for edge in graph_edges if edge.get("relation")})
        provenance = sorted({str(edge.get("provenance")) for edge in graph_edges if edge.get("provenance")})
        avg_confidence = round(sum(float(edge.get("confidence", 0.0)) for edge in graph_edges) / max(len(graph_edges), 1), 4)
        return {"relation_count": len(graph_edges), "relation_types": relation_types, "provenance_sources": provenance, "average_confidence": avg_confidence}

    def _score_urlhaus_category(self, threat: str, tags: List[str]) -> tuple[float, List[str]]:
        notes: List[str] = []
        score = 0.0
        combined = {threat, *tags}
        if "ransomware" in combined:
            score += 1.1
            notes.append("Ransomware indicator increased risk.")
        if "phishing" in combined or "cobaltstrike" in combined:
            score += 0.8
            notes.append("Known high-impact threat family increased risk.")
        if "malware" in combined or "loader" in combined or "stealer" in combined:
            score += 0.6
            notes.append("Commodity malware or loader labeling raised the IOC priority.")
        return min(score, 1.6), notes

    def _score_urlhaus_status(self, status: str) -> tuple[float, List[str]]:
        if status == "online":
            return 0.7, ["IOC is still online, increasing operational urgency."]
        if status == "offline":
            return 0.2, ["IOC is offline, but still relevant for retrospective hunting."]
        return 0.0, []

    def _score_url_structure(self, url: str) -> tuple[float, List[str]]:
        notes: List[str] = []
        score = 0.0
        lowered = (url or "").lower()
        if any(token in lowered for token in ["/login", "/update", "/verify", ".zip", ".exe", ".js"]):
            score += 0.45
            notes.append("URL structure looks aligned with phishing or malware delivery patterns.")
        if lowered.startswith("http://"):
            score += 0.15
            notes.append("Plain HTTP transport slightly raises suspicion.")
        return min(score, 0.6), notes

    def _classify_dread_post(self, text: str) -> List[str]:
        categories: List[str] = []
        for category, terms in DREAD_CLASSIFIERS.items():
            if any(term in text for term in terms):
                categories.append(category)
        return sorted(set(categories))

    def _extract_dread_matched_terms(self, text: str) -> List[str]:
        terms: List[str] = []
        for term_list in DREAD_CLASSIFIERS.values():
            for term in term_list:
                if term in text:
                    terms.append(term)
        return sorted(set(terms))[:10]
