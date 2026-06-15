from __future__ import annotations

from typing import Any, Dict, List, Optional

from agents.llm_helper import generate_explanation
from analysis.correlator import DREAD_CLASSIFIERS
from analysis.evidence import coerce_related_evidence_provider
from analysis.graph_builder import GraphBuilder
from analysis.keyword_extractor import extract_keywords
from analysis.scoring import calculate_age_days, level_from_score
from analysis.scorers.common import (
    build_counterfactual_explanations,
    build_counterfactuals,
    build_source_contributions,
    calculate_cve_graph_bonus,
    calculate_urlhaus_graph_bonus,
    count_non_empty_llm_fields,
    sample_dread_hits,
    sample_urlhaus_hits,
    summarize_relations,
)
from analysis.scorers.cve import (
    CveRiskScorer,
    build_invalid_cve_analysis,
    calculate_cve_confidence_details,
    get_primary_description,
    is_invalid_cve_record,
    score_cvss_severity,
    score_llm_cve_info,
    score_nlp_context,
)
from analysis.scorers.urlhaus import (
    UrlhausRiskScorer,
    calculate_urlhaus_confidence_details,
    score_urlhaus_cross_source_support,
    score_urlhaus_delivery_pattern,
    score_urlhaus_freshness,
    score_urlhaus_malware_family,
    score_urlhaus_payload,
    score_urlhaus_status,
    score_urlhaus_tag_density,
    score_urlhaus_threat_type,
    urlhaus_malware_family_signals,
    urlhaus_payload_signals,
)
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
        external_signals: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        scorer = CveRiskScorer(
            graph_builder=self.graph_builder,
            explanation_generator=generate_explanation,
            age_calculator=calculate_age_days,
        )
        kwargs = {
            "data": data,
            "evidence_provider": coerce_related_evidence_provider(db),
            "llm_info": llm_info,
        }
        if external_signals is not None:
            kwargs["external_signals"] = external_signals
        return scorer.evaluate(**kwargs)

    def evaluate_urlhaus(self, data: Dict[str, Any], db: Optional[Any] = None) -> Dict[str, Any]:
        scorer = UrlhausRiskScorer(graph_builder=self.graph_builder, age_calculator=calculate_age_days)
        return scorer.evaluate(data=data, evidence_provider=coerce_related_evidence_provider(db))

    def evaluate_dread(
        self,
        data: Dict[str, Any],
        db: Optional[Any] = None,
        llm_cls: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        llm_cls = llm_cls or {}
        evidence_provider = coerce_related_evidence_provider(db)
        combined = f"{data.get('title', '')} {data.get('content', '')}".strip().lower()
        keywords = extract_keywords(combined)
        related_cves = evidence_provider.find_related_cves(keywords, limit=SETTINGS.retrieval.candidate_limit)
        related_urlhaus = evidence_provider.find_related_urlhaus(keywords, limit=SETTINGS.retrieval.candidate_limit)
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
                "sample_related_urlhaus": sample_urlhaus_hits(related_urlhaus),
            },
        )
        root = f"dread:{str((data.get('title') or data.get('_id') or 'unknown-dread')).strip().lower()[:80]}"
        graph_summary = self.graph_builder.summarize_graph(graph, root_node=root)
        graph_edges = self.graph_builder.export_graph_edges(graph, limit=20)
        graph_bonus = min(float(graph_summary.get("centrality_score", 0.0)) * 0.95, 1.0)
        final_score = max(0.0, min(round(final_pre_graph + graph_bonus, 2), 10.0))
        risk_level = level_from_score(final_score)
        confidence = self._calculate_confidence(
            False,
            len(related_urlhaus),
            len(related_cves),
            len(keywords),
            1 if llm_cls else 0,
            float(graph_summary.get("centrality_score", 0.0)),
        )

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
                "sample_related_urlhaus": sample_urlhaus_hits(related_urlhaus),
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
            "counterfactuals": build_counterfactuals(final_score, graph_bonus, urlhaus_bonus, cve_bonus, llm_bonus),
            "source_contributions": {"base_component": round(base_score, 2), "graph_component": round(graph_bonus, 2)},
            "relation_summary": summarize_relations(graph_edges),
            "orchestration_trace": [
                {
                    "agent": "darkweb-risk",
                    "action": "score-dread-post",
                    "status": "completed",
                    "details": {
                        "category_count": len(categories),
                        "related_cves": len(related_cves),
                        "related_urlhaus": len(related_urlhaus),
                    },
                }
            ],
        }

    def _calculate_graph_bonus(self, graph_summary: Dict[str, Any]) -> float:
        return calculate_cve_graph_bonus(
            graph_summary,
            graph_bonus_multiplier=self.weights.graph_bonus_multiplier,
            graph_bonus_cap=self.weights.graph_bonus_cap,
        )

    def _is_invalid_cve_record(self, cve_id: str, description: str) -> bool:
        return is_invalid_cve_record(cve_id, description)

    def _build_invalid_cve_analysis(self, cve_id: str, description: str) -> Dict[str, Any]:
        return build_invalid_cve_analysis(cve_id, description)

    def _score_cvss_severity(self, cvss_score: float) -> float:
        return score_cvss_severity(
            cvss_score,
            zero_cvss_fallback=self.weights.zero_cvss_fallback,
            base_cvss_multiplier=self.weights.base_cvss_multiplier,
        )

    def _get_primary_description(self, data: Dict[str, Any]) -> str:
        return get_primary_description(data)

    def _score_llm_cve_info(self, llm_info: Dict[str, Any]) -> tuple[float, List[str]]:
        return score_llm_cve_info(llm_info, llm_bonus_cap=self.weights.llm_bonus_cap)

    def _score_nlp_context(self, entities: Dict[str, Any]) -> tuple[float, List[str]]:
        return score_nlp_context(entities)

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
        epss_available: bool = False,
        kev_status_known: bool = False,
        kev_listed: bool = False,
    ) -> Dict[str, Any]:
        return calculate_cve_confidence_details(
            has_cvss=has_cvss,
            urlhaus_match_count=urlhaus_match_count,
            dread_match_count=dread_match_count,
            keyword_count=keyword_count,
            llm_fields_count=llm_fields_count,
            graph_score=graph_score,
            cvss_score=cvss_score,
            cvss_version=cvss_version,
            description=description,
            age_days=age_days,
            nlp_entities=nlp_entities,
            urlhaus_stats=urlhaus_stats,
            dread_stats=dread_stats,
            epss_available=epss_available,
            kev_status_known=kev_status_known,
            kev_listed=kev_listed,
        )

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
        return count_non_empty_llm_fields(llm_info)

    def _sample_urlhaus_hits(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sample_urlhaus_hits(matches)

    def _sample_dread_hits(self, matches: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return sample_dread_hits(matches)

    def _build_counterfactuals(
        self,
        final_score: float,
        graph_bonus: float,
        urlhaus_bonus: float,
        dread_bonus: float,
        llm_bonus: float,
    ) -> Dict[str, float]:
        return build_counterfactuals(final_score, graph_bonus, urlhaus_bonus, dread_bonus, llm_bonus)

    def _build_counterfactual_explanations(self, counterfactuals: Dict[str, float]) -> List[str]:
        return build_counterfactual_explanations(counterfactuals)

    def _build_source_contributions(
        self,
        entity_type: str,
        base_score: float,
        urlhaus_score: float,
        dread_score: float,
        llm_bonus: float,
        graph_bonus: float,
        penalties: Dict[str, float],
    ) -> Dict[str, float]:
        return build_source_contributions(entity_type, base_score, urlhaus_score, dread_score, llm_bonus, graph_bonus, penalties)

    def _summarize_relations(self, graph_edges: List[Dict[str, Any]]) -> Dict[str, Any]:
        return summarize_relations(graph_edges)

    def _score_urlhaus_threat_type(self, threat: str) -> tuple[float, List[str]]:
        return score_urlhaus_threat_type(threat)

    def _score_urlhaus_status(self, status: str) -> tuple[float, List[str]]:
        return score_urlhaus_status(status)

    def _score_urlhaus_payload(self, url: str, tags: List[str]) -> tuple[float, List[str]]:
        return score_urlhaus_payload(url, tags)

    def _score_urlhaus_malware_family(self, tags: List[str]) -> tuple[float, List[str]]:
        return score_urlhaus_malware_family(tags)

    def _score_urlhaus_delivery_pattern(self, url: str, tags: List[str]) -> tuple[float, List[str]]:
        return score_urlhaus_delivery_pattern(url, tags)

    def _score_urlhaus_tag_density(self, tags: List[str]) -> tuple[float, List[str]]:
        return score_urlhaus_tag_density(tags)

    def _score_urlhaus_freshness(self, date_added: Any) -> tuple[float, List[str]]:
        return score_urlhaus_freshness(date_added, age_calculator=calculate_age_days)

    def _score_urlhaus_cross_source_support(
        self,
        related_cves: List[Dict[str, Any]],
        related_dread: List[Dict[str, Any]],
        keywords: List[str],
    ) -> float:
        return score_urlhaus_cross_source_support(related_cves, related_dread, keywords)

    def _calculate_urlhaus_graph_bonus(self, graph_summary: Dict[str, Any]) -> float:
        return calculate_urlhaus_graph_bonus(graph_summary)

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
        return calculate_urlhaus_confidence_details(
            threat=threat,
            tags=tags,
            url=url,
            status=status,
            date_added=date_added,
            related_cves=related_cves,
            related_dread=related_dread,
            graph_summary=graph_summary,
            age_calculator=calculate_age_days,
        )

    def _urlhaus_payload_signals(self, url: str, tags: List[str]) -> Dict[str, bool]:
        return urlhaus_payload_signals(url, tags)

    def _urlhaus_malware_family_signals(self, tags: List[str]) -> List[str]:
        return urlhaus_malware_family_signals(tags)

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
