from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from config import get_settings
from analysis.semantic_similarity import semantic_similarity, tokenize, top_shared_terms, token_jaccard, weighted_jaccard

SETTINGS = get_settings()

DREAD_CLASSIFIERS = {
    "exploit_sale": ["exploit", "0day", "zero-day", "zeroday", "rce", "weaponized"],
    "data_leak": ["leak", "database", "dump", "breach", "records"],
    "access_sale": ["access", "vpn", "rdp", "foothold", "initial access"],
    "malware_activity": ["malware", "stealer", "ransomware", "botnet", "loader"],
}

THREAT_NORMALIZATION = {
    "cobaltstrike": "cobaltstrike",
    "cobalt_strike": "cobaltstrike",
    "cobalt strike": "cobaltstrike",
    "ransomware": "ransomware",
    "botnet": "botnet",
    "stealer": "stealer",
    "phishing": "phishing",
    "malware": "malware",
    "loader": "loader",
    "dropper": "dropper",
    "backdoor": "backdoor",
}

HIGH_IMPACT_TERMS = {
    "cobaltstrike",
    "ransomware",
    "botnet",
    "stealer",
    "loader",
    "dropper",
    "backdoor",
    "exploit",
    "rce",
    "zeroday",
    "zero-day",
    "0day",
}


GENERIC_FILTER_TERMS = {
    "remote", "code", "execution", "vulnerability", "attack", "attacker", "allows",
    "allow", "module", "system", "issue", "affects", "affected", "buffer",
    "overflow", "memory", "kernel", "linux", "function", "input", "output",
    "network", "service", "request", "response", "fix", "fixed", "update"
}

CVE_RE = re.compile(r"cve-\d{4}-\d{4,7}", re.I)


def score_urlhaus_matches(
    matches: List[Dict[str, Any]],
    base_keywords: Optional[List[str]] = None,
    entity_time: Optional[str] = None,
) -> Tuple[float, List[str], Dict[str, Any]]:
    return _score_matches(matches, base_keywords, entity_time, source="urlhaus")


def score_dread_matches(
    matches: List[Dict[str, Any]],
    base_keywords: Optional[List[str]] = None,
    entity_time: Optional[str] = None,
) -> Tuple[float, List[str], List[str], Dict[str, Any]]:
    score, explanations, stats = _score_matches(matches, base_keywords, entity_time, source="dread")
    categories: List[str] = []
    for match in matches[:5]:
        combined_text = f"{match.get('title', '')} {match.get('content', '')}".lower()
        for category, terms in DREAD_CLASSIFIERS.items():
            if any(term in combined_text for term in terms):
                categories.append(category)
    return score, explanations, sorted(set(categories)), stats


def _score_matches(
    matches: List[Dict[str, Any]],
    base_keywords: Optional[List[str]],
    entity_time: Optional[str],
    source: str,
) -> Tuple[float, List[str], Dict[str, Any]]:
    if not matches:
        return 0.0, [], _empty_match_stats()

    cfg = SETTINGS.scoring
    base_terms = _normalize_terms(base_keywords or [])
    cve_terms = {term for term in base_terms if CVE_RE.fullmatch(term)}
    explanations = [f"Cross-source {source} correlation found ({len(matches)} match)."]

    total_score = 0.0
    lexical_scores: List[float] = []
    semantic_scores: List[float] = []
    temporal_scores: List[float] = []
    entity_hits = 0
    exact_cve_hits = 0
    high_signal_hits = 0
    online_hits = 0
    shared_terms: List[str] = []
    strongest_match_score = 0.0

    for match in matches[:5]:
        candidate_text = _match_text(match, source)
        match_terms = _normalize_terms([candidate_text, *(match.get("tags") or [])])
        lexical = _hybrid_lexical_overlap(base_terms, match_terms)
        semantic = semantic_similarity(" ".join(base_terms), candidate_text)
        temporal = _compute_time_proximity_score(entity_time, _match_time(match, source))
        entities = _entity_overlap_score(base_terms, match_terms)
        shared_term_count = len(set(base_terms) & set(match_terms))

        # Reject weak, generic matches early so URLhaus linkage is more precise.
        if shared_term_count < SETTINGS.retrieval.min_shared_terms and exact_cve_hits == 0 and entities == 0:
            continue
        if lexical < SETTINGS.retrieval.min_lexical_overlap and semantic < SETTINGS.retrieval.min_semantic_support and entities == 0:
            continue

        score = (
            lexical * cfg.lexical_weight
            + semantic * cfg.semantic_weight
            + temporal * cfg.temporal_weight
            + entities * cfg.entity_weight
        )

        if source == "urlhaus" and str(match.get("url_status", "")).lower() == "online":
            score += cfg.online_weight
            online_hits += 1

        normalized_terms = _normalize_threat_terms(match_terms)
        high_signal_term_hits = len(HIGH_IMPACT_TERMS.intersection(normalized_terms))
        if high_signal_term_hits:
            high_signal_hits += 1
            score += min(cfg.high_signal_weight + (0.05 * high_signal_term_hits), 0.45)

        if entities > 0:
            entity_hits += 1

        joined_terms = " ".join(match_terms)
        if any(cve_id in joined_terms for cve_id in cve_terms):
            exact_cve_hits += 1
            score += 0.55 if source == "urlhaus" else 0.45

        total_score += score
        strongest_match_score = max(strongest_match_score, score)
        lexical_scores.append(round(lexical, 4))
        semantic_scores.append(round(semantic, 4))
        temporal_scores.append(round(temporal, 4))
        shared_terms.extend(top_shared_terms(base_terms, match_terms, limit=6))

    cap = cfg.urlhaus_score_cap if source == "urlhaus" else cfg.dread_score_cap
    if not lexical_scores:
        return 0.0, [], _empty_match_stats()

    avg_lexical = round(sum(lexical_scores) / len(lexical_scores), 4)
    avg_semantic = round(sum(semantic_scores) / len(semantic_scores), 4)
    avg_temporal = round(sum(temporal_scores) / len(temporal_scores), 4)

    if exact_cve_hits:
        explanations.append(f"Exact CVE-style evidence appeared in {exact_cve_hits} correlated record(s).")
    if avg_lexical >= 0.14:
        explanations.append(f"Lexical overlap is meaningful (avg lexical={avg_lexical}).")
    if avg_semantic >= SETTINGS.semantic.similarity_floor:
        explanations.append(f"Semantic similarity is non-trivial (avg semantic={avg_semantic}).")
    if entity_hits:
        explanations.append(f"Named threat/product/CVE entities aligned in {entity_hits} record(s).")
    if high_signal_hits:
        explanations.append("High-signal exploit or malware terminology reinforced the correlation.")
    if online_hits:
        explanations.append(f"{online_hits} IOC record(s) remain online, increasing operational relevance.")

    stats = {
        "avg_overlap_ratio": avg_lexical,
        "avg_lexical_score": avg_lexical,
        "avg_semantic_score": avg_semantic,
        "avg_temporal_score": avg_temporal,
        "exact_cve_hits": exact_cve_hits,
        "online_hits": online_hits,
        "high_signal_hits": high_signal_hits,
        "entity_overlap_hits": entity_hits,
        "strongest_match_score": round(strongest_match_score, 4),
        "shared_terms": sorted(set(shared_terms))[:10],
        "hybrid_score_cap": cap,
    }
    return min(round(total_score, 4), cap), explanations, stats


def _match_text(match: Dict[str, Any], source: str) -> str:
    if source == "urlhaus":
        return " ".join(
            [
                str(match.get("url", "")),
                str(match.get("threat", "")),
                " ".join(str(tag) for tag in (match.get("tags") or [])),
                str(match.get("normalized_fields", {}).get("search_text", "")),
            ]
        )
    return " ".join(
        [
            str(match.get("title", "")),
            str(match.get("content", "")),
            str(match.get("category", "")),
            str(match.get("normalized_fields", {}).get("search_text", "")),
        ]
    )


def _match_time(match: Dict[str, Any], source: str) -> Optional[str]:
    if source == "urlhaus":
        return match.get("date_added")
    return match.get("created_at") or match.get("published")


def _hybrid_lexical_overlap(base_terms: Iterable[str], match_terms: Iterable[str]) -> float:
    base_list = list(base_terms)
    match_list = list(match_terms)
    return round((weighted_jaccard(base_list, match_list) * 0.65) + (token_jaccard(base_list, match_list) * 0.35), 4)


def _entity_overlap_score(base_terms: List[str], match_terms: List[str]) -> float:
    base_entities = {term for term in base_terms if term.startswith("cve-") or term in HIGH_IMPACT_TERMS or term.isdigit() is False and len(term) > 5}
    match_entities = {term for term in match_terms if term.startswith("cve-") or term in HIGH_IMPACT_TERMS or term.isdigit() is False and len(term) > 5}
    if not base_entities or not match_entities:
        return 0.0
    return round(len(base_entities & match_entities) / max(len(base_entities), 1), 4)


def _normalize_terms(values: Iterable[str]) -> List[str]:
    terms: List[str] = []
    for value in values:
        for token in tokenize(str(value)):
            token = token.lower().strip("._")
            if len(token) < 3 and not token.startswith("cve-"):
                continue
            if token in GENERIC_FILTER_TERMS and not token.startswith("cve-"):
                continue
            terms.append(token)
    return terms


def _normalize_threat_terms(terms: Iterable[str]) -> set[str]:
    normalized = set()
    for term in terms:
        key = term.lower().replace("-", "").replace("_", "")
        normalized.add(THREAT_NORMALIZATION.get(key, THREAT_NORMALIZATION.get(term.lower(), term.lower())))
    return normalized


def _compute_time_proximity_score(entity_time: Optional[str], candidate_time: Optional[str]) -> float:
    if not entity_time or not candidate_time:
        return 0.0
    try:
        entity_dt = _to_datetime(entity_time)
        candidate_dt = _to_datetime(candidate_time)
        delta_days = abs((entity_dt - candidate_dt).days)
        if delta_days <= 3:
            return 1.0
        if delta_days <= 14:
            return 0.7
        if delta_days <= 30:
            return 0.45
        if delta_days <= 90:
            return 0.2
        return 0.0
    except Exception:
        return 0.0


def _to_datetime(value: str) -> datetime:
    normalized = str(value).replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _empty_match_stats() -> Dict[str, Any]:
    return {
        "avg_overlap_ratio": 0.0,
        "avg_lexical_score": 0.0,
        "avg_semantic_score": 0.0,
        "avg_temporal_score": 0.0,
        "exact_cve_hits": 0,
        "online_hits": 0,
        "high_signal_hits": 0,
        "entity_overlap_hits": 0,
        "strongest_match_score": 0.0,
        "shared_terms": [],
    }

# Backward-compatible helper for older tests.
def correlate_keywords(source_keywords=None, candidate_texts=None, **kwargs):
    source_keywords = source_keywords or kwargs.get("base_keywords") or []
    candidate_texts = candidate_texts or kwargs.get("candidate_keywords") or []

    base_terms = _normalize_terms(source_keywords)
    cand_terms = _normalize_terms(candidate_texts)

    shared_terms = top_shared_terms(base_terms, cand_terms, limit=10)

    high_impact_terms = {
        "ransomware", "loader", "exploit", "rce", "remote", "code",
        "execution", "malware", "phishing", "cobaltstrike", "stealer"
    }
    has_high_impact_overlap = any(term in high_impact_terms for term in shared_terms)

    return {
        "overlap_count": len(shared_terms),
        "overlap_ratio": token_jaccard(base_terms, cand_terms),
        "weighted_overlap": weighted_jaccard(base_terms, cand_terms),
        "shared_terms": shared_terms,
        "has_high_impact_overlap": has_high_impact_overlap,
    }
