from __future__ import annotations

from typing import Any, Dict, List, Optional

from agents.llm_helper import generate_explanation
from analysis.correlator import DREAD_CLASSIFIERS, score_dread_matches, score_urlhaus_matches
from analysis.features.cve_temporal import evaluate_cve_temporal_features
from analysis.graph_builder import GraphBuilder
from analysis.keyword_extractor import extract_keywords
from analysis.nlp_features import extract_nlp_features
from analysis.scoring import calculate_age_days, extract_cvss_score, level_from_score
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
        nlp_features = extract_nlp_features(description, cve_id)
        keywords = nlp_features.all_terms[:18]

        urlhaus_matches = db.find_related_urlhaus(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []
        dread_matches = db.find_related_dread(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []

        urlhaus_score, urlhaus_explanations, urlhaus_stats = score_urlhaus_matches(urlhaus_matches, keywords, data.get("published"))
        dread_score, dread_explanations, dread_categories, dread_stats = score_dread_matches(dread_matches, keywords, data.get("published"))
        accepted_urlhaus_matches = list(urlhaus_stats.get("accepted_matches") or [])
        accepted_dread_matches = list(dread_stats.get("accepted_matches") or [])
        llm_bonus, llm_explanations = self._score_llm_cve_info(llm_info)
        nlp_bonus, nlp_explanations = self._score_nlp_context(nlp_features.to_dict())

        active_evidence_count = len(accepted_urlhaus_matches) + len(accepted_dread_matches)
        temporal_features = evaluate_cve_temporal_features(
            data.get("published"),
            active_evidence_count=active_evidence_count,
            age_calculator=calculate_age_days,
        )
        age_days = temporal_features.age_days
        recentness_bonus = temporal_features.recentness_bonus
        raw_age_penalty = temporal_features.raw_age_penalty
        age_penalty = temporal_features.age_penalty
        base_score = self._score_cvss_severity(cvss_score)
        # Calibrated scoring: CVSS remains the severity anchor. External evidence and
        # NLP context adjust priority, while missing corroboration primarily affects
        # confidence rather than forcing high-severity CVEs into LOW risk.
        cross_source_score = urlhaus_score + dread_score
        pre_graph_score = base_score + recentness_bonus + cross_source_score + llm_bonus + nlp_bonus - age_penalty

        graph = self.graph_builder.build_entity_graph(
            entity_type="cve",
            entity_id=cve_id,
            record=data,
            evidence={
                "keywords": keywords,
                "nlp_entities": nlp_features.to_dict(),
                "cvss_score": cvss_score,
                "llm_products": llm_info.get("products", []),
                "llm_vuln_type": llm_info.get("vuln_type"),
                "llm_impact": llm_info.get("impact"),
                "dread_categories": dread_categories,
                "sample_urlhaus_hits": self._sample_urlhaus_hits(accepted_urlhaus_matches),
                "sample_dread_hits": self._sample_dread_hits(accepted_dread_matches),
            },
        )
        graph_summary = self.graph_builder.summarize_graph(graph, root_node=f"cve:{cve_id}")
        graph_edges = self.graph_builder.export_graph_edges(graph, limit=25)
        graph_bonus = self._calculate_graph_bonus(graph_summary)

        raw_score = pre_graph_score + graph_bonus
        final_score = max(0.0, min(round(raw_score, 2), 10.0))
        risk_level = level_from_score(final_score)

        counterfactuals = self._build_counterfactuals(final_score, graph_bonus, urlhaus_score, dread_score, llm_bonus + nlp_bonus)
        source_contributions = self._build_source_contributions("cve", base_score, urlhaus_score, dread_score, llm_bonus + nlp_bonus, graph_bonus, {"age_penalty": age_penalty})
        relation_summary = self._summarize_relations(graph_edges)
        confidence_details = self._calculate_confidence_details(
            has_cvss=cvss_score > 0,
            cvss_score=cvss_score,
            cvss_version=cvss_version,
            description=description,
            age_days=age_days,
            urlhaus_match_count=len(accepted_urlhaus_matches),
            dread_match_count=len(accepted_dread_matches),
            keyword_count=len(keywords),
            llm_fields_count=self._count_non_empty_llm_fields(llm_info),
            graph_score=float(graph_summary.get("centrality_score", 0.0)),
            nlp_entities=nlp_features.to_dict(),
            urlhaus_stats=urlhaus_stats,
            dread_stats=dread_stats,
        )
        confidence = confidence_details["confidence"]

        explanations = [f"Base risk derived from CVSS ({cvss_version}) score: {cvss_score}."]
        if age_days is not None:
            explanations.append(f"Estimated vulnerability age: {age_days} day(s).")
        if recentness_bonus > 0:
            explanations.append("Recently published or updated vulnerability increased priority.")
        if age_penalty > 0:
            if raw_age_penalty > age_penalty:
                explanations.append("Older vulnerability record reduced current priority score, but active evidence capped the age penalty.")
            else:
                explanations.append("Older vulnerability record modestly reduced current priority score.")
        explanations.extend(urlhaus_explanations)
        explanations.extend(dread_explanations)
        explanations.extend(nlp_explanations)
        explanations.extend(llm_explanations)
        if graph_bonus > 0:
            explanations.append(f"Graph connectivity increased the score by {round(graph_bonus, 2)}.")
        explanations.extend(self._build_counterfactual_explanations(counterfactuals))
        if not accepted_urlhaus_matches and not accepted_dread_matches:
            explanations.append("No accepted cross-source corroboration found; score relies mainly on CVE metadata and intrinsic context.")

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
            {"agent": "correlation", "action": "collect-cross-source-evidence", "status": "completed", "details": {"urlhaus_candidates": len(urlhaus_matches), "urlhaus_accepted": len(accepted_urlhaus_matches), "dread_candidates": len(dread_matches), "dread_accepted": len(accepted_dread_matches), "semantic_urlhaus": urlhaus_stats.get("avg_semantic_score", 0.0), "semantic_dread": dread_stats.get("avg_semantic_score", 0.0)}},
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
            "confidence_breakdown": confidence_details["breakdown"],
            "diagnosis": f"{cve_id} evaluated as {risk_level} (dynamic score={final_score}, base CVSS={cvss_score}).",
            "explanation": explanations,
            "evidence": {
                "keywords": keywords,
                "nlp_entities": nlp_features.to_dict(),
                "cvss_score": cvss_score,
                "cvss_version": cvss_version,
                "age_days": age_days,
                "related_urlhaus_count": len(accepted_urlhaus_matches),
                "related_dread_count": len(accepted_dread_matches),
                "candidate_urlhaus_count": len(urlhaus_matches),
                "candidate_dread_count": len(dread_matches),
                "dread_categories": dread_categories,
                "sample_urlhaus_hits": self._sample_urlhaus_hits(accepted_urlhaus_matches),
                "sample_dread_hits": self._sample_dread_hits(accepted_dread_matches),
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
                "nlp_context_bonus": round(nlp_bonus, 2),
                "llm_context_bonus": round(llm_bonus, 2),
                "cross_source_bonus": round(cross_source_score, 2),
                "age_penalty": round(age_penalty, 2),
                "raw_age_penalty": round(raw_age_penalty, 2),
                "severity_score": round(base_score, 2),
                "exploitability_score": round(nlp_bonus + llm_bonus, 2),
                "active_threat_score": round(cross_source_score, 2),
                "temporal_score": round(recentness_bonus - age_penalty, 2),
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
        tags = [str(tag).lower() for tag in (data.get("tags") or []) if tag]
        url = data.get("url", "")
        status = (data.get("url_status") or "").lower()
        date_added = data.get("date_added") or data.get("created_at")
        text = " ".join([threat, url, " ".join(tags)])
        keywords = extract_keywords(text)

        related_cves = db.find_related_cves(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []
        related_dread = db.find_related_dread(keywords, limit=SETTINGS.retrieval.candidate_limit) if db else []

        base_score = 1.4
        explanations = ["Base risk assigned from URLhaus malicious IOC feed presence."]
        threat_score, threat_notes = self._score_urlhaus_threat_type(threat)
        status_score, status_notes = self._score_urlhaus_status(status)
        payload_score, payload_notes = self._score_urlhaus_payload(url, tags)
        family_score, family_notes = self._score_urlhaus_malware_family(tags)
        delivery_score, delivery_notes = self._score_urlhaus_delivery_pattern(url, tags)
        tag_density_score, tag_density_notes = self._score_urlhaus_tag_density(tags)
        freshness_score, freshness_notes = self._score_urlhaus_freshness(date_added)
        correlation_score = self._score_urlhaus_cross_source_support(related_cves, related_dread, keywords)

        score = (
            base_score
            + threat_score
            + status_score
            + payload_score
            + family_score
            + delivery_score
            + tag_density_score
            + freshness_score
            + correlation_score
        )
        explanations.extend(
            threat_notes
            + status_notes
            + payload_notes
            + family_notes
            + delivery_notes
            + tag_density_notes
            + freshness_notes
        )
        if correlation_score > 0:
            explanations.append("Cross-source evidence modestly raised the IOC priority.")

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
        graph_bonus = self._calculate_urlhaus_graph_bonus(graph_summary)
        pre_graph_score = max(0.0, min(round(score, 2), 10.0))
        final_score = max(0.0, min(round(score + graph_bonus, 2), 10.0))
        risk_level = level_from_score(final_score)
        confidence_details = self._calculate_urlhaus_confidence(
            threat=threat,
            tags=tags,
            url=url,
            status=status,
            date_added=date_added,
            related_cves=len(related_cves),
            related_dread=len(related_dread),
            graph_summary=graph_summary,
        )
        confidence = confidence_details["confidence"]
        counterfactuals = self._build_counterfactuals(final_score, graph_bonus, correlation_score, 0.0, 0.0)
        entity_id = data.get("urlhaus_id") or data.get("url") or "unknown-urlhaus"

        return {
            "entity_type": "urlhaus",
            "entity_id": entity_id,
            "risk_score": final_score,
            "risk_level": risk_level,
            "confidence": confidence,
            "confidence_breakdown": confidence_details["breakdown"],
            "diagnosis": f"IOC evaluated as {risk_level} (dynamic score={final_score}).",
            "explanation": explanations,
            "evidence": {
                "keywords": keywords,
                "threat": threat,
                "url_status": status,
                "tags": tags,
                "date_added": date_added,
                "payload_signals": self._urlhaus_payload_signals(url, tags),
                "malware_family_signals": self._urlhaus_malware_family_signals(tags),
                "related_cve_count": len(related_cves),
                "related_dread_count": len(related_dread),
                "sample_related_cves": [{"cve_id": item.get("_id")} for item in related_cves[:5]],
                "sample_dread_hits": self._sample_dread_hits(related_dread),
            },
            "feature_breakdown": {
                "base_feed_component": round(base_score, 2),
                "threat_type_score": round(threat_score, 2),
                "status_score": round(status_score, 2),
                "payload_score": round(payload_score, 2),
                "malware_family_score": round(family_score, 2),
                "delivery_pattern_score": round(delivery_score, 2),
                "tag_density_score": round(tag_density_score, 2),
                "freshness_score": round(freshness_score, 2),
                "cross_source_score": round(correlation_score, 2),
                "graph_bonus": round(graph_bonus, 2),
                "pre_graph_score": pre_graph_score,
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
            # Confidence represents risk-scoring reliability, not certainty that
            # the record is invalid. Rejected/reserved CVE records carry no
            # actionable vulnerability evidence and must not appear as
            # high-confidence LOW findings.
            "confidence": 0.25,
            "confidence_breakdown": {
                "base_confidence": 0.0,
                "metadata_confidence": 0.0,
                "entity_confidence": 0.0,
                "external_evidence_confidence": 0.0,
                "correlation_confidence": 0.0,
                "freshness_confidence": 0.0,
                "penalties": -0.25,
                "raw_confidence": 0.25,
                "final_confidence": 0.25,
                "signals": {"validity_status": "invalid_or_rejected"},
            },
            "diagnosis": f"{cve_id} excluded from dynamic prioritization as an invalid CVE record.",
            "explanation": [note, "Risk confidence is intentionally low because the record is not actionable vulnerability evidence."],
            "evidence": {"keywords": [], "cvss_score": 0.0, "age_days": None, "related_urlhaus_count": 0, "related_dread_count": 0, "validity_status": "invalid_or_rejected"},
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

    def _score_cvss_severity(self, cvss_score: float) -> float:
        if cvss_score <= 0:
            return self.weights.zero_cvss_fallback
        return round(min(cvss_score * self.weights.base_cvss_multiplier, 7.4), 2)

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

    def _score_nlp_context(self, entities: Dict[str, Any]) -> tuple[float, List[str]]:
        """Score intrinsic exploitability context extracted from text only.

        This is intentionally capped so NLP cannot turn a low-severity, uncorroborated
        vulnerability into a high-risk item by itself. Cross-source evidence still carries
        the main dynamic-priority signal.
        """
        score = 0.0
        explanations: List[str] = []
        vuln_types = set(entities.get("vuln_types") or [])
        impacts = set(entities.get("impacts") or [])
        threat_terms = set(entities.get("threat_terms") or [])
        products = set(entities.get("products") or [])

        if {"remote_code_execution", "authentication_bypass", "privilege_escalation"} & vuln_types:
            score += 0.65
            explanations.append("NLP identified a high-impact vulnerability type in the CVE description.")
        elif vuln_types:
            score += 0.30
            explanations.append("NLP identified a concrete vulnerability type in the CVE description.")

        if {"takeover", "credential_theft", "initial_access", "data_leak"} & impacts:
            score += 0.40
            explanations.append("NLP extracted attacker-impact context from the description.")
        elif impacts:
            score += 0.15
            explanations.append("NLP extracted operational impact context from the description.")

        if {"exploit", "zero-day", "0day", "rce", "ransomware", "malware"} & threat_terms:
            score += 0.35
            explanations.append("Threat/exploit terminology in the text increased intrinsic prioritization.")

        critical_product_terms = {"vpn", "firewall", "identity", "exchange", "sharepoint", "router", "gateway", "remote access"}
        if products:
            product_text = " ".join(products)
            score += min(len(products) * 0.04, 0.16)
            if any(term in product_text for term in critical_product_terms):
                score += 0.18
                explanations.append("Affected product context suggests exposed or security-critical infrastructure.")

        return min(round(score, 2), 1.20), explanations

    def _calculate_confidence_details(
        self,
        has_cvss: bool,
        urlhaus_match_count: int,
        dread_match_count: int,
        keyword_count: int,
        llm_fields_count: int,
        graph_score: float,
        *,
        cvss_score: float = 0.0,
        cvss_version: str = "Unknown",
        description: str = "",
        age_days: Optional[int] = None,
        nlp_entities: Optional[Dict[str, Any]] = None,
        urlhaus_stats: Optional[Dict[str, Any]] = None,
        dread_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return component-based confidence for the current risk assessment.

        Confidence is evidence reliability, not risk severity. High technical
        severity may justify HIGH risk with only medium confidence, while
        accepted external evidence should move confidence upward only when it is
        supported by exact identifiers, meaningful shared terms, high-signal
        malware/exploit context, or semantic corroboration.
        """
        urlhaus_stats = urlhaus_stats or {}
        dread_stats = dread_stats or {}
        nlp_entities = nlp_entities or {}

        accepted_external = urlhaus_match_count + dread_match_count
        exact_hits = int(urlhaus_stats.get("exact_cve_hits", 0) or 0) + int(dread_stats.get("exact_cve_hits", 0) or 0)
        high_signal_hits = int(urlhaus_stats.get("high_signal_hits", 0) or 0) + int(dread_stats.get("high_signal_hits", 0) or 0)
        entity_hits = int(urlhaus_stats.get("entity_overlap_hits", 0) or 0) + int(dread_stats.get("entity_overlap_hits", 0) or 0)
        shared_terms = set(urlhaus_stats.get("shared_terms") or []) | set(dread_stats.get("shared_terms") or [])
        acceptance_reasons = set(urlhaus_stats.get("acceptance_reasons") or []) | set(dread_stats.get("acceptance_reasons") or [])
        semantic_signal = max(
            float(urlhaus_stats.get("avg_semantic_score", 0.0) or 0.0),
            float(dread_stats.get("avg_semantic_score", 0.0) or 0.0),
        )
        entity_alignment_only = bool(
            accepted_external > 0
            and acceptance_reasons
            and acceptance_reasons <= {"entity_alignment"}
            and exact_hits == 0
            and high_signal_hits == 0
        )

        # Stable floor for valid, analyzable CVE records. Invalid/rejected CVEs
        # bypass this path and receive a low fixed confidence.
        base_confidence = 0.12

        metadata_confidence = 0.0
        if has_cvss:
            metadata_confidence += 0.22
            if cvss_version in {"CVSS v4.0", "CVSS v3.1", "CVSS v3.0"}:
                metadata_confidence += 0.04
            elif cvss_version == "CVSS v2.0":
                metadata_confidence += 0.02
            if cvss_score >= 9.0:
                metadata_confidence += 0.02
        desc_len = len((description or "").strip())
        if desc_len >= 180:
            metadata_confidence += 0.10
        elif desc_len >= 80:
            metadata_confidence += 0.07
        elif desc_len >= 30:
            metadata_confidence += 0.03
        if age_days is not None:
            metadata_confidence += 0.04
        metadata_confidence = min(metadata_confidence, 0.42)

        entity_confidence = 0.0
        products = nlp_entities.get("products") or []
        vuln_types = nlp_entities.get("vuln_types") or []
        impacts = nlp_entities.get("impacts") or []
        threat_terms = nlp_entities.get("threat_terms") or []
        cve_ids = nlp_entities.get("cve_ids") or []
        if products:
            entity_confidence += min(len(products) * 0.012, 0.07)
        if vuln_types:
            entity_confidence += 0.05
        if impacts:
            entity_confidence += 0.04
        if threat_terms:
            entity_confidence += 0.04
        if cve_ids:
            entity_confidence += 0.02
        entity_confidence += min(keyword_count * 0.003, 0.03)
        entity_confidence += min(llm_fields_count * 0.02, 0.05)
        entity_confidence = min(entity_confidence, 0.18)

        external_evidence_confidence = 0.0
        if accepted_external:
            # Entity-alignment-only evidence is weaker than exact CVE, high-signal
            # malware/exploit overlap, or multi-signal corroboration. It can raise
            # confidence, but it must not make old/generic IOC matches look highly
            # reliable by itself.
            if entity_alignment_only:
                external_evidence_confidence += min(accepted_external * 0.025, 0.07)
            else:
                external_evidence_confidence += min(accepted_external * 0.055, 0.16)
        if exact_hits:
            external_evidence_confidence += min(exact_hits * 0.16, 0.26)
        if high_signal_hits:
            external_evidence_confidence += min(high_signal_hits * 0.05, 0.12)
        if entity_hits:
            external_evidence_confidence += min(entity_hits * (0.015 if entity_alignment_only else 0.035), 0.08)
        if shared_terms:
            external_evidence_confidence += min(len(shared_terms) * (0.008 if entity_alignment_only else 0.015), 0.06)
        if semantic_signal >= SETTINGS.semantic.similarity_floor:
            external_evidence_confidence += min(semantic_signal * (0.045 if entity_alignment_only else 0.10), 0.08)
        external_evidence_confidence = min(external_evidence_confidence, 0.38)

        correlation_confidence = 0.0
        if accepted_external > 0:
            correlation_confidence += min(graph_score * 0.04, 0.05)
        if accepted_external > 0 and (exact_hits or high_signal_hits or shared_terms or semantic_signal >= SETTINGS.semantic.similarity_floor):
            correlation_confidence += 0.02 if entity_alignment_only else 0.04
        correlation_confidence = min(correlation_confidence, 0.09)

        freshness_confidence = 0.0
        if age_days is not None:
            if age_days <= 30:
                freshness_confidence += 0.04
            elif age_days <= 365:
                freshness_confidence += 0.02

        penalties = 0.0
        if accepted_external == 0:
            penalties -= 0.08
            if exact_hits == 0 and high_signal_hits == 0 and entity_hits == 0 and semantic_signal == 0:
                penalties -= 0.03
        if not has_cvss:
            penalties -= 0.12
        if desc_len < 30:
            penalties -= 0.05
        if not products and not vuln_types and not impacts and not threat_terms:
            penalties -= 0.04
        if entity_alignment_only and semantic_signal < 0.30:
            penalties -= 0.03
        if age_days is not None and age_days > 3650 and accepted_external == 0:
            penalties -= 0.04

        raw_confidence = (
            base_confidence
            + metadata_confidence
            + entity_confidence
            + external_evidence_confidence
            + correlation_confidence
            + freshness_confidence
            + penalties
        )

        # Hard guardrails for metadata-poor records. Text extraction can provide
        # useful context, but missing CVSS and missing accepted external evidence
        # should keep the reliability of CVE prioritization low.
        if not has_cvss and accepted_external == 0:
            raw_confidence = min(raw_confidence, 0.35)
            if keyword_count <= 3 and llm_fields_count == 0:
                raw_confidence = min(raw_confidence, 0.28)

        confidence = round(max(0.05, min(raw_confidence, 0.95)), 3)
        breakdown = {
            "base_confidence": round(base_confidence, 3),
            "metadata_confidence": round(metadata_confidence, 3),
            "entity_confidence": round(entity_confidence, 3),
            "external_evidence_confidence": round(external_evidence_confidence, 3),
            "correlation_confidence": round(correlation_confidence, 3),
            "freshness_confidence": round(freshness_confidence, 3),
            "penalties": round(penalties, 3),
            "raw_confidence": round(raw_confidence, 3),
            "final_confidence": confidence,
            "signals": {
                "has_cvss": has_cvss,
                "cvss_version": cvss_version,
                "description_length": desc_len,
                "accepted_external_evidence": accepted_external,
                "exact_hits": exact_hits,
                "high_signal_hits": high_signal_hits,
                "entity_hits": entity_hits,
                "shared_term_count": len(shared_terms),
                "acceptance_reasons": sorted(acceptance_reasons),
                "entity_alignment_only": entity_alignment_only,
                "semantic_signal": round(semantic_signal, 4),
            },
        }
        return {"confidence": confidence, "breakdown": breakdown}

    def _calculate_confidence(
        self,
        has_cvss: bool,
        urlhaus_match_count: int,
        dread_match_count: int,
        keyword_count: int,
        llm_fields_count: int,
        graph_score: float,
        *,
        nlp_entities: Optional[Dict[str, Any]] = None,
        urlhaus_stats: Optional[Dict[str, Any]] = None,
        dread_stats: Optional[Dict[str, Any]] = None,
    ) -> float:
        """Backward-compatible confidence API for non-CVE paths and tests."""
        return self._calculate_confidence_details(
            has_cvss=has_cvss,
            urlhaus_match_count=urlhaus_match_count,
            dread_match_count=dread_match_count,
            keyword_count=keyword_count,
            llm_fields_count=llm_fields_count,
            graph_score=graph_score,
            nlp_entities=nlp_entities,
            urlhaus_stats=urlhaus_stats,
            dread_stats=dread_stats,
        )["confidence"]

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

    def _score_urlhaus_threat_type(self, threat: str) -> tuple[float, List[str]]:
        notes: List[str] = []
        threat = (threat or "").lower()
        if threat == "malware_download":
            return 0.9, ["URLhaus classifies the IOC as malware download infrastructure."]
        if "phish" in threat:
            return 0.7, ["URLhaus phishing classification raised operational priority."]
        if threat:
            return 0.45, ["URLhaus threat classification provided a weak operational signal."]
        return 0.0, notes

    def _score_urlhaus_status(self, status: str) -> tuple[float, List[str]]:
        if status == "online":
            return 1.25, ["IOC is still online, increasing operational urgency."]
        if status == "offline":
            return 0.15, ["IOC is offline, but still relevant for retrospective hunting."]
        return 0.0, []

    def _score_urlhaus_payload(self, url: str, tags: List[str]) -> tuple[float, List[str]]:
        signals = self._urlhaus_payload_signals(url, tags)
        notes: List[str] = []
        score = 0.0
        if signals.get("script_payload"):
            score += 0.75
            notes.append("Script payload indicators raised the IOC priority.")
        if signals.get("binary_payload"):
            score += 0.65
            notes.append("Executable or ELF payload indicators raised the IOC priority.")
        if signals.get("archive_payload"):
            score += 0.35
            notes.append("Archive delivery pattern added a payload-delivery signal.")
        if signals.get("living_off_land_delivery"):
            score += 0.35
            notes.append("Living-off-the-land delivery indicator was observed in the IOC metadata.")
        return min(score, 1.35), notes

    def _score_urlhaus_malware_family(self, tags: List[str]) -> tuple[float, List[str]]:
        families = self._urlhaus_malware_family_signals(tags)
        notes: List[str] = []
        if not families:
            return 0.0, notes
        score = 0.0
        high_impact = {"acrstealer", "guloader", "smartloader", "netsupport", "cobaltstrike", "ransomware"}
        botnet = {"mirai", "mozi"}
        if any(item in high_impact for item in families):
            score += 0.9
            notes.append("Known loader, stealer, or remote-access malware family tag raised priority.")
        if any(item in botnet for item in families):
            score += 0.55
            notes.append("Known botnet malware family tag raised priority.")
        if families and score == 0.0:
            score += 0.35
            notes.append("Malware family tagging increased confidence in IOC relevance.")
        return min(score, 1.1), notes

    def _score_urlhaus_delivery_pattern(self, url: str, tags: List[str]) -> tuple[float, List[str]]:
        lowered = (url or "").lower()
        tag_set = set(tags or [])
        notes: List[str] = []
        score = 0.0
        if lowered.startswith("http://"):
            score += 0.15
            notes.append("Plain HTTP transport slightly raises suspicion.")
        if any(token in lowered for token in ["/bin.sh", "/update", "/download", "/load", "/payload", "/cloud/"]):
            score += 0.35
            notes.append("URL path resembles malware staging or payload delivery.")
        if any(tag in tag_set for tag in {"opendir", "ua-wget"}):
            score += 0.25
            notes.append("URLhaus tags indicate automated retrieval or exposed directory delivery behavior.")
        return min(score, 0.75), notes

    def _score_urlhaus_tag_density(self, tags: List[str]) -> tuple[float, List[str]]:
        count = len([tag for tag in tags if tag])
        if count >= 5:
            return 0.35, ["Dense URLhaus tagging increased IOC metadata richness."]
        if count >= 3:
            return 0.2, ["Multiple URLhaus tags increased IOC metadata richness."]
        return 0.0, []

    def _score_urlhaus_freshness(self, date_added: Any) -> tuple[float, List[str]]:
        age_days = calculate_age_days(str(date_added)) if date_added else None
        if age_days is None:
            return 0.0, []
        if age_days <= 3:
            return 0.7, ["Recently added URLhaus IOC increased operational urgency."]
        if age_days <= 14:
            return 0.45, ["Recent URLhaus IOC increased operational urgency."]
        if age_days <= 30:
            return 0.25, ["URLhaus IOC was added within the last month."]
        return 0.0, []

    def _score_urlhaus_cross_source_support(self, related_cves: List[Dict[str, Any]], related_dread: List[Dict[str, Any]], keywords: List[str]) -> float:
        # Cross-source retrieval for IOC URLs is keyword based and can match generic terms.
        # Keep this conservative; it should not dominate URLhaus IOC prioritization.
        keyword_count = len([term for term in keywords if term])
        if keyword_count < 2:
            return 0.0
        cve_bonus = min(len(related_cves) * 0.04, 0.25)
        dread_bonus = min(len(related_dread) * 0.08, 0.35)
        return round(min(cve_bonus + dread_bonus, 0.5), 2)

    def _calculate_urlhaus_graph_bonus(self, graph_summary: Dict[str, Any]) -> float:
        centrality = float(graph_summary.get("centrality_score", 0.0) or 0.0)
        structural_strength = float(graph_summary.get("structural_strength", 0.0) or 0.0)
        # Graph context is useful for pivoting but should not make an offline IOC look urgent by itself.
        return round(min(centrality * 0.35 * max(structural_strength, 0.25), 0.65), 2)

    def _calculate_urlhaus_confidence(
        self,
        *,
        threat: str,
        tags: List[str],
        url: str,
        status: str,
        date_added: Any,
        related_cves: int,
        related_dread: int,
        graph_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload_signals = self._urlhaus_payload_signals(url, tags)
        family_signals = self._urlhaus_malware_family_signals(tags)
        feed_confidence = 0.22
        status_confidence = 0.10 if status in {"online", "offline"} else 0.0
        threat_label_confidence = 0.12 if threat and threat != "unknown" else 0.0
        tag_confidence = min(len(tags) * 0.035, 0.16)
        payload_confidence = min(sum(1 for value in payload_signals.values() if value) * 0.045, 0.14)
        family_confidence = min(len(family_signals) * 0.055, 0.16)
        freshness_confidence = 0.0
        age_days = calculate_age_days(str(date_added)) if date_added else None
        if age_days is not None:
            freshness_confidence = 0.08 if age_days <= 14 else 0.04 if age_days <= 30 else 0.0
        cross_source_confidence = min((related_cves * 0.025) + (related_dread * 0.05), 0.12)
        graph_confidence = min(float(graph_summary.get("structural_strength", 0.0) or 0.0) * 0.06, 0.06)
        penalties = 0.0
        if not tags:
            penalties -= 0.08
        if status == "offline":
            penalties -= 0.04
        if not date_added:
            penalties -= 0.05
        raw = (
            feed_confidence
            + status_confidence
            + threat_label_confidence
            + tag_confidence
            + payload_confidence
            + family_confidence
            + freshness_confidence
            + cross_source_confidence
            + graph_confidence
            + penalties
        )
        final = round(min(max(raw, 0.25), 0.92), 3)
        breakdown = {
            "feed_confidence": round(feed_confidence, 3),
            "status_confidence": round(status_confidence, 3),
            "threat_label_confidence": round(threat_label_confidence, 3),
            "tag_confidence": round(tag_confidence, 3),
            "payload_confidence": round(payload_confidence, 3),
            "family_confidence": round(family_confidence, 3),
            "freshness_confidence": round(freshness_confidence, 3),
            "cross_source_confidence": round(cross_source_confidence, 3),
            "graph_confidence": round(graph_confidence, 3),
            "penalties": round(penalties, 3),
            "raw_confidence": round(raw, 3),
            "final_confidence": final,
            "signals": {
                "url_status": status or "unknown",
                "tag_count": len(tags),
                "payload_signals": payload_signals,
                "malware_family_signals": family_signals,
                "related_cves": related_cves,
                "related_dread": related_dread,
                "date_added_present": bool(date_added),
            },
        }
        return {"confidence": final, "breakdown": breakdown}

    def _urlhaus_payload_signals(self, url: str, tags: List[str]) -> Dict[str, bool]:
        lowered = (url or "").lower()
        tag_set = set(tags or [])
        script_exts = (".ps1", ".vbs", ".js", ".jse", ".wsf", ".bat", ".cmd", ".sh")
        binary_exts = (".exe", ".dll", ".scr", ".elf", ".mips", ".arm", ".x86", ".m68k", ".armv5l")
        archive_exts = (".zip", ".rar", ".7z", ".tar", ".gz")
        script_tags = {"ps1", "powershell", "vbs", "lnk", "js", "jse", "bat", "shell", "ua-wget"}
        binary_tags = {"elf", "mips", "arm", "32-bit", "64-bit", "x86", "m68k"}
        archive_tags = {"zip", "rar", "7z"}
        lotl_tags = {"powershell", "ua-wget", "wget", "curl"}
        return {
            "script_payload": any(ext in lowered for ext in script_exts) or bool(tag_set & script_tags),
            "binary_payload": any(ext in lowered for ext in binary_exts) or bool(tag_set & binary_tags),
            "archive_payload": any(ext in lowered for ext in archive_exts) or bool(tag_set & archive_tags),
            "living_off_land_delivery": bool(tag_set & lotl_tags),
        }

    def _urlhaus_malware_family_signals(self, tags: List[str]) -> List[str]:
        known = {
            "mozi", "mirai", "clearfake", "netsupport", "acrstealer", "smartloader",
            "guloader", "cobaltstrike", "phantomstealer", "ransomware", "ddos",
        }
        return sorted({str(tag).lower() for tag in tags if str(tag).lower() in known})

    # Backward-compatible wrappers retained for existing tests/import expectations.
    def _score_urlhaus_category(self, threat: str, tags: List[str]) -> tuple[float, List[str]]:
        threat_score, threat_notes = self._score_urlhaus_threat_type(threat)
        family_score, family_notes = self._score_urlhaus_malware_family(tags)
        payload_score, payload_notes = self._score_urlhaus_payload("", tags)
        return min(threat_score + family_score + payload_score, 1.8), threat_notes + family_notes + payload_notes

    def _score_url_structure(self, url: str) -> tuple[float, List[str]]:
        payload_score, payload_notes = self._score_urlhaus_payload(url, [])
        delivery_score, delivery_notes = self._score_urlhaus_delivery_pattern(url, [])
        return min(payload_score + delivery_score, 1.2), payload_notes + delivery_notes

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
