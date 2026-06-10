from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from analysis.evidence import RelatedEvidenceProvider
from analysis.features.confidence import calculate_urlhaus_confidence
from analysis.graph_builder import GraphBuilder
from analysis.keyword_extractor import extract_keywords
from analysis.scoring import calculate_age_days, level_from_score
from analysis.scorers.common import (
    build_counterfactuals,
    calculate_urlhaus_graph_bonus,
    sample_dread_hits,
    summarize_relations,
)
from config import get_settings


SETTINGS = get_settings()
AgeCalculator = Callable[[Optional[Any]], Optional[int]]


class UrlhausRiskScorer:
    def __init__(
        self,
        graph_builder: GraphBuilder | None = None,
        age_calculator: AgeCalculator = calculate_age_days,
    ) -> None:
        self.graph_builder = graph_builder or GraphBuilder()
        self.age_calculator = age_calculator

    def evaluate(self, data: Dict[str, Any], evidence_provider: RelatedEvidenceProvider) -> Dict[str, Any]:
        threat = (data.get("threat") or "unknown").lower()
        tags = [str(tag).lower() for tag in (data.get("tags") or []) if tag]
        url = data.get("url", "")
        status = (data.get("url_status") or "").lower()
        date_added = data.get("date_added") or data.get("created_at")
        text = " ".join([threat, url, " ".join(tags)])
        keywords = extract_keywords(text)

        related_cves = evidence_provider.find_related_cves(keywords, limit=SETTINGS.retrieval.candidate_limit)
        related_dread = evidence_provider.find_related_dread(keywords, limit=SETTINGS.retrieval.candidate_limit)

        base_score = 1.4
        explanations = ["Base risk assigned from URLhaus malicious IOC feed presence."]
        threat_score, threat_notes = score_urlhaus_threat_type(threat)
        status_score, status_notes = score_urlhaus_status(status)
        payload_score, payload_notes = score_urlhaus_payload(url, tags)
        family_score, family_notes = score_urlhaus_malware_family(tags)
        delivery_score, delivery_notes = score_urlhaus_delivery_pattern(url, tags)
        tag_density_score, tag_density_notes = score_urlhaus_tag_density(tags)
        freshness_score, freshness_notes = score_urlhaus_freshness(date_added, age_calculator=self.age_calculator)
        correlation_score = score_urlhaus_cross_source_support(related_cves, related_dread, keywords)

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
                "sample_dread_hits": sample_dread_hits(related_dread),
            },
        )
        root_node = f"urlhaus:{url or data.get('urlhaus_id') or 'unknown-urlhaus'}"
        graph_summary = self.graph_builder.summarize_graph(graph, root_node=root_node)
        graph_edges = self.graph_builder.export_graph_edges(graph, limit=20)
        graph_bonus = calculate_urlhaus_graph_bonus(graph_summary)
        pre_graph_score = max(0.0, min(round(score, 2), 10.0))
        final_score = max(0.0, min(round(score + graph_bonus, 2), 10.0))
        risk_level = level_from_score(final_score)
        confidence_details = calculate_urlhaus_confidence_details(
            threat=threat,
            tags=tags,
            url=url,
            status=status,
            date_added=date_added,
            related_cves=len(related_cves),
            related_dread=len(related_dread),
            graph_summary=graph_summary,
            age_calculator=self.age_calculator,
        )
        confidence = confidence_details["confidence"]
        counterfactuals = build_counterfactuals(final_score, graph_bonus, correlation_score, 0.0, 0.0)
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
                "payload_signals": urlhaus_payload_signals(url, tags),
                "malware_family_signals": urlhaus_malware_family_signals(tags),
                "related_cve_count": len(related_cves),
                "related_dread_count": len(related_dread),
                "sample_related_cves": [{"cve_id": item.get("_id")} for item in related_cves[:5]],
                "sample_dread_hits": sample_dread_hits(related_dread),
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
            "relation_summary": summarize_relations(graph_edges),
            "orchestration_trace": [
                {
                    "agent": "ioc-risk",
                    "action": "score-urlhaus-ioc",
                    "status": "completed",
                    "details": {"related_cves": len(related_cves), "related_dread": len(related_dread)},
                }
            ],
        }


def score_urlhaus_threat_type(threat: str) -> tuple[float, List[str]]:
    notes: List[str] = []
    threat = (threat or "").lower()
    if threat == "malware_download":
        return 0.9, ["URLhaus classifies the IOC as malware download infrastructure."]
    if "phish" in threat:
        return 0.7, ["URLhaus phishing classification raised operational priority."]
    if threat:
        return 0.45, ["URLhaus threat classification provided a weak operational signal."]
    return 0.0, notes


def score_urlhaus_status(status: str) -> tuple[float, List[str]]:
    if status == "online":
        return 1.25, ["IOC is still online, increasing operational urgency."]
    if status == "offline":
        return 0.15, ["IOC is offline, but still relevant for retrospective hunting."]
    return 0.0, []


def score_urlhaus_payload(url: str, tags: List[str]) -> tuple[float, List[str]]:
    signals = urlhaus_payload_signals(url, tags)
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


def score_urlhaus_malware_family(tags: List[str]) -> tuple[float, List[str]]:
    families = urlhaus_malware_family_signals(tags)
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


def score_urlhaus_delivery_pattern(url: str, tags: List[str]) -> tuple[float, List[str]]:
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


def score_urlhaus_tag_density(tags: List[str]) -> tuple[float, List[str]]:
    count = len([tag for tag in tags if tag])
    if count >= 5:
        return 0.35, ["Dense URLhaus tagging increased IOC metadata richness."]
    if count >= 3:
        return 0.2, ["Multiple URLhaus tags increased IOC metadata richness."]
    return 0.0, []


def score_urlhaus_freshness(date_added: Any, *, age_calculator=calculate_age_days) -> tuple[float, List[str]]:
    age_days = age_calculator(str(date_added)) if date_added else None
    if age_days is None:
        return 0.0, []
    if age_days <= 3:
        return 0.7, ["Recently added URLhaus IOC increased operational urgency."]
    if age_days <= 14:
        return 0.45, ["Recent URLhaus IOC increased operational urgency."]
    if age_days <= 30:
        return 0.25, ["URLhaus IOC was added within the last month."]
    return 0.0, []


def score_urlhaus_cross_source_support(
    related_cves: List[Dict[str, Any]],
    related_dread: List[Dict[str, Any]],
    keywords: List[str],
) -> float:
    keyword_count = len([term for term in keywords if term])
    if keyword_count < 2:
        return 0.0
    cve_bonus = min(len(related_cves) * 0.04, 0.25)
    dread_bonus = min(len(related_dread) * 0.08, 0.35)
    return round(min(cve_bonus + dread_bonus, 0.5), 2)


def calculate_urlhaus_confidence_details(
    *,
    threat: str,
    tags: List[str],
    url: str,
    status: str,
    date_added: Any,
    related_cves: int,
    related_dread: int,
    graph_summary: Dict[str, Any],
    age_calculator=calculate_age_days,
) -> Dict[str, Any]:
    return calculate_urlhaus_confidence(
        threat=threat,
        tags=tags,
        status=status,
        date_added=date_added,
        related_cves=related_cves,
        related_dread=related_dread,
        graph_summary=graph_summary,
        payload_signals=urlhaus_payload_signals(url, tags),
        family_signals=urlhaus_malware_family_signals(tags),
        age_calculator=age_calculator,
    ).to_dict()


def urlhaus_payload_signals(url: str, tags: List[str]) -> Dict[str, bool]:
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


def urlhaus_malware_family_signals(tags: List[str]) -> List[str]:
    known = {
        "mozi",
        "mirai",
        "clearfake",
        "netsupport",
        "acrstealer",
        "smartloader",
        "guloader",
        "cobaltstrike",
        "phantomstealer",
        "ransomware",
        "ddos",
    }
    return sorted({str(tag).lower() for tag in tags if str(tag).lower() in known})
