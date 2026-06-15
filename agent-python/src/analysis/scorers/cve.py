from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from analysis.correlator import score_dread_matches, score_urlhaus_matches
from analysis.evidence import RelatedEvidenceProvider
from analysis.features.confidence import calculate_cve_confidence, calculate_rejected_cve_confidence
from analysis.features.cve_temporal import evaluate_cve_temporal_features
from analysis.graph_builder import GraphBuilder
from analysis.nlp_features import extract_nlp_features
from analysis.scoring import calculate_age_days, extract_cvss_score, level_from_score
from analysis.scoring_signals import (
    RiskSignalInputs,
    calculate_risk_signal_breakdown,
    extract_external_risk_signals,
)
from analysis.scorers.common import (
    build_counterfactual_explanations,
    build_counterfactuals,
    build_source_contributions,
    calculate_cve_graph_bonus,
    count_non_empty_llm_fields,
    sample_dread_hits,
    sample_urlhaus_hits,
    summarize_relations,
)
from config import get_settings


SETTINGS = get_settings()
ExplanationGenerator = Callable[[Dict[str, Any]], str]
AgeCalculator = Callable[[Optional[Any]], Optional[int]]


class CveRiskScorer:
    def __init__(
        self,
        *,
        graph_builder: GraphBuilder | None = None,
        explanation_generator: Optional[ExplanationGenerator] = None,
        age_calculator: AgeCalculator = calculate_age_days,
    ) -> None:
        self.graph_builder = graph_builder or GraphBuilder()
        self.weights = SETTINGS.scoring
        self.explanation_generator = explanation_generator or (lambda _context: "")
        self.age_calculator = age_calculator

    def evaluate(
        self,
        data: Dict[str, Any],
        evidence_provider: RelatedEvidenceProvider,
        llm_info: Optional[Dict[str, Any]] = None,
        external_signals: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        cve_id = data.get("_id", "unknown-cve")
        description = get_primary_description(data)
        llm_info = llm_info or {}

        if is_invalid_cve_record(cve_id, description):
            return build_invalid_cve_analysis(cve_id, description)

        cvss_score, cvss_version = extract_cvss_score(data.get("metrics", {}))
        cisa_signals = extract_external_risk_signals(data, external_signals)
        nlp_features = extract_nlp_features(description, cve_id)
        keywords = nlp_features.all_terms[:18]

        urlhaus_matches = evidence_provider.find_related_urlhaus(keywords, limit=SETTINGS.retrieval.candidate_limit)
        dread_matches = evidence_provider.find_related_dread(keywords, limit=SETTINGS.retrieval.candidate_limit)

        urlhaus_score, urlhaus_explanations, urlhaus_stats = score_urlhaus_matches(
            urlhaus_matches,
            keywords,
            data.get("published"),
        )
        dread_score, dread_explanations, dread_categories, dread_stats = score_dread_matches(
            dread_matches,
            keywords,
            data.get("published"),
        )
        observed_dread_categories = list(dread_stats.get("observed_dread_categories") or [])
        accepted_urlhaus_matches = list(urlhaus_stats.get("accepted_matches") or [])
        accepted_dread_matches = list(dread_stats.get("accepted_matches") or [])
        llm_bonus, llm_explanations = score_llm_cve_info(llm_info, llm_bonus_cap=self.weights.llm_bonus_cap)
        nlp_bonus, nlp_explanations = score_nlp_context(nlp_features.to_dict())

        active_evidence_count = len(accepted_urlhaus_matches) + len(accepted_dread_matches)
        temporal_features = evaluate_cve_temporal_features(
            data.get("published"),
            active_evidence_count=active_evidence_count,
            age_calculator=self.age_calculator,
        )
        age_days = temporal_features.age_days
        recentness_bonus = temporal_features.recentness_bonus
        raw_age_penalty = temporal_features.raw_age_penalty
        age_penalty = temporal_features.age_penalty
        base_score = score_cvss_severity(
            cvss_score,
            zero_cvss_fallback=self.weights.zero_cvss_fallback,
            base_cvss_multiplier=self.weights.base_cvss_multiplier,
        )
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
                "observed_dread_categories": observed_dread_categories,
                "sample_urlhaus_hits": sample_urlhaus_hits(accepted_urlhaus_matches),
                "sample_dread_hits": sample_dread_hits(accepted_dread_matches),
            },
        )
        graph_summary = self.graph_builder.summarize_graph(graph, root_node=f"cve:{cve_id}")
        graph_edges = self.graph_builder.export_graph_edges(graph, limit=25)
        graph_bonus = calculate_cve_graph_bonus(
            graph_summary,
            graph_bonus_multiplier=self.weights.graph_bonus_multiplier,
            graph_bonus_cap=self.weights.graph_bonus_cap,
        )

        raw_score = pre_graph_score + graph_bonus
        signal_breakdown = calculate_risk_signal_breakdown(
            RiskSignalInputs(
                cvss_score=cvss_score,
                epss_probability=cisa_signals.epss_probability,
                kev_listed=cisa_signals.kev_listed,
                age_days=age_days,
                urlhaus_score=urlhaus_score,
                dread_score=dread_score,
                graph_centrality=graph_bonus / self.weights.graph_bonus_cap if self.weights.graph_bonus_cap > 0 else 0.0,
                nlp_context_score=nlp_bonus,
            )
        )
        final_score = max(signal_breakdown["risk_score_from_signals"], round(base_score, 2) if cvss_score <= 0 else 0.0)
        risk_level = level_from_score(final_score)

        counterfactuals = build_counterfactuals(final_score, graph_bonus, urlhaus_score, dread_score, llm_bonus + nlp_bonus)
        source_contributions = build_source_contributions(
            "cve",
            base_score,
            urlhaus_score,
            dread_score,
            llm_bonus + nlp_bonus,
            graph_bonus,
            {"age_penalty": age_penalty},
        )
        relation_summary = summarize_relations(graph_edges)
        confidence_details = calculate_cve_confidence_details(
            has_cvss=cvss_score > 0,
            cvss_score=cvss_score,
            cvss_version=cvss_version,
            description=description,
            age_days=age_days,
            urlhaus_match_count=len(accepted_urlhaus_matches),
            dread_match_count=len(accepted_dread_matches),
            keyword_count=len(keywords),
            llm_fields_count=count_non_empty_llm_fields(llm_info),
            graph_score=float(graph_summary.get("centrality_score", 0.0)),
            nlp_entities=nlp_features.to_dict(),
            urlhaus_stats=urlhaus_stats,
            dread_stats=dread_stats,
            epss_available=cisa_signals.epss_available,
            kev_status_known=cisa_signals.kev_status_known,
            kev_listed=cisa_signals.kev_listed is True,
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
        explanations.extend(build_counterfactual_explanations(counterfactuals))
        ignored_urlhaus = int(urlhaus_stats.get("ignored_low_signal_count", 0) or 0)
        ignored_dread = int(dread_stats.get("ignored_low_signal_count", 0) or 0)
        if ignored_urlhaus:
            explanations.append(f"Ignored {ignored_urlhaus} URLhaus candidate(s) as low-signal retrieval noise; ignored candidates did not affect risk or confidence.")
        if ignored_dread:
            explanations.append(f"Ignored {ignored_dread} Dread candidate(s) as low-signal retrieval noise; ignored candidates did not affect risk or confidence.")
        if not accepted_urlhaus_matches and not accepted_dread_matches:
            explanations.append("No accepted cross-source corroboration found; score relies mainly on CVE metadata and intrinsic context.")

        llm_text = self.explanation_generator(
            {
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
            }
        )
        if llm_text:
            explanations = [llm_text] + explanations

        orchestration_trace = [
            {
                "agent": "planner",
                "action": "build-analysis-plan",
                "status": "completed",
                "details": {"source": "cve", "keyword_count": len(keywords)},
            },
            {
                "agent": "correlation",
                "action": "collect-cross-source-evidence",
                "status": "completed",
                "details": {
                    "urlhaus_candidates": len(urlhaus_matches),
                    "urlhaus_accepted": len(accepted_urlhaus_matches),
                    "urlhaus_ignored_low_signal": ignored_urlhaus,
                    "dread_candidates": len(dread_matches),
                    "dread_accepted": len(accepted_dread_matches),
                    "dread_ignored_low_signal": ignored_dread,
                    "semantic_urlhaus": urlhaus_stats.get("avg_semantic_score", 0.0),
                    "semantic_dread": dread_stats.get("avg_semantic_score", 0.0),
                },
            },
            {
                "agent": "graph",
                "action": "build-entity-graph",
                "status": "completed",
                "details": {"node_count": graph_summary.get("node_count", 0), "edge_count": graph_summary.get("edge_count", 0)},
            },
            {
                "agent": "risk",
                "action": "score-risk",
                "status": "completed",
                "details": {"pre_graph_score": round(pre_graph_score, 2), "graph_bonus": round(graph_bonus, 2), "final_score": final_score},
            },
            {
                "agent": "critic",
                "action": "sanity-check-score",
                "status": "completed",
                "details": {"confidence": confidence, "risk_level": risk_level},
            },
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
                "epss_probability": cisa_signals.epss_probability,
                "epss_available": cisa_signals.epss_available,
                "kev_listed": cisa_signals.kev_listed,
                "kev_status_known": cisa_signals.kev_status_known,
                "age_days": age_days,
                "related_urlhaus_count": len(accepted_urlhaus_matches),
                "related_dread_count": len(accepted_dread_matches),
                "candidate_urlhaus_count": len(urlhaus_matches),
                "candidate_dread_count": len(dread_matches),
                "dread_categories": dread_categories,
                "accepted_dread_categories": dread_categories,
                "observed_dread_categories": observed_dread_categories,
                "sample_urlhaus_hits": sample_urlhaus_hits(accepted_urlhaus_matches),
                "sample_dread_hits": sample_dread_hits(accepted_dread_matches),
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
                **signal_breakdown,
            },
            "graph_summary": graph_summary,
            "graph_edges": graph_edges,
            "counterfactuals": counterfactuals,
            "source_contributions": source_contributions,
            "relation_summary": relation_summary,
            "orchestration_trace": orchestration_trace,
        }


def is_invalid_cve_record(cve_id: str, description: str) -> bool:
    lowered = f"{cve_id} {description}".lower()
    invalid_markers = ["rejected", "do not use", "reserved", "candidate was issued in error"]
    return any(marker in lowered for marker in invalid_markers)


def build_invalid_cve_analysis(cve_id: str, description: str) -> Dict[str, Any]:
    note = "Record was excluded from prioritization because the CVE entry is rejected, reserved, or explicitly marked invalid."
    confidence_details = calculate_rejected_cve_confidence().to_dict()
    return {
        "entity_type": "cve",
        "entity_id": cve_id,
        "risk_score": 0.0,
        "risk_level": "LOW",
        "confidence": confidence_details["confidence"],
        "confidence_breakdown": confidence_details["breakdown"],
        "diagnosis": f"{cve_id} excluded from dynamic prioritization as an invalid CVE record.",
        "explanation": [
            note,
            "Risk confidence is intentionally low because the record is not actionable vulnerability evidence.",
        ],
        "evidence": {
            "keywords": [],
            "cvss_score": 0.0,
            "age_days": None,
            "related_urlhaus_count": 0,
            "related_dread_count": 0,
            "validity_status": "invalid_or_rejected",
        },
        "feature_breakdown": {
            "base_cvss_component": 0.0,
            "recentness_bonus": 0.0,
            "urlhaus_correlation_bonus": 0.0,
            "dread_correlation_bonus": 0.0,
            "llm_context_bonus": 0.0,
            "age_penalty": 0.0,
            "graph_centrality_score": 0.0,
            "graph_bonus": 0.0,
            "pre_graph_score": 0.0,
            "raw_score_before_clamp": 0.0,
            "ml_refinement_delta": 0.0,
            "final_score": 0.0,
            "severity_signal": 0.0,
            "epss_signal": 0.0,
            "kev_signal": 0.0,
            "recency_signal": 0.0,
            "correlation_signal": 0.0,
            "graph_signal": 0.0,
            "nlp_context_signal": 0.0,
            "risk_raw": 0.0,
            "risk_score_from_signals": 0.0,
            "urlhaus_avg_overlap_ratio": 0.0,
            "dread_avg_overlap_ratio": 0.0,
            "urlhaus_avg_semantic_score": 0.0,
            "dread_avg_semantic_score": 0.0,
        },
        "graph_summary": {
            "node_count": 0,
            "edge_count": 0,
            "centrality_score": 0.0,
            "cross_source_edge_count": 0,
            "ioc_edge_count": 0,
        },
        "graph_edges": [],
        "counterfactuals": {
            "score_without_graph": 0.0,
            "score_without_urlhaus": 0.0,
            "score_without_dread": 0.0,
            "score_without_llm_context": 0.0,
        },
        "source_contributions": {
            "entity_type": "cve",
            "base_component": 0.0,
            "urlhaus_component": 0.0,
            "dread_component": 0.0,
            "llm_component": 0.0,
            "graph_component": 0.0,
        },
        "relation_summary": {
            "relation_count": 0,
            "relation_types": [],
            "provenance_sources": [],
            "average_confidence": 0.0,
        },
        "orchestration_trace": [
            {
                "agent": "risk",
                "action": "skip-invalid-cve",
                "status": "completed",
                "details": {"reason": "invalid_cve_marker"},
            }
        ],
    }


def score_cvss_severity(cvss_score: float, *, zero_cvss_fallback: float, base_cvss_multiplier: float) -> float:
    if cvss_score <= 0:
        return zero_cvss_fallback
    return round(min(cvss_score * base_cvss_multiplier, 7.4), 2)


def get_primary_description(data: Dict[str, Any]) -> str:
    descriptions = data.get("descriptions", []) or []
    for item in descriptions:
        if item.get("lang", "").lower() == "en":
            return item.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def score_llm_cve_info(llm_info: Dict[str, Any], *, llm_bonus_cap: float) -> tuple[float, List[str]]:
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
    return min(score, llm_bonus_cap), explanations


def score_nlp_context(entities: Dict[str, Any]) -> tuple[float, List[str]]:
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


def calculate_cve_confidence_details(
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
    return calculate_cve_confidence(
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
    ).to_dict()
