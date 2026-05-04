from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from config import get_settings
from analysis.nlp_features import (
    THREAT_PATTERNS,
    WEAK_TERMS,
    entity_overlap,
    extract_nlp_features,
    hybrid_semantic_score,
    normalize_token,
)
from analysis.semantic_similarity import tokenize, top_shared_terms, token_jaccard, weighted_jaccard

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
    "zeroday": "zero-day",
    "0day": "zero-day",
}

HIGH_IMPACT_TERMS = {
    "cobaltstrike", "ransomware", "botnet", "stealer", "loader", "dropper",
    "backdoor", "exploit", "rce", "zeroday", "zero-day", "0day", "webshell",
}

GENERIC_FILTER_TERMS = set(WEAK_TERMS)
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
    for match in matches[:8]:
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
    base_text = " ".join(base_terms)
    base_features = extract_nlp_features(base_text)

    accepted_scores: List[float] = []
    lexical_scores: List[float] = []
    semantic_scores: List[float] = []
    temporal_scores: List[float] = []
    entity_scores: List[float] = []
    shared_terms: List[str] = []
    reasons: List[str] = []

    exact_cve_hits = 0
    high_signal_hits = 0
    online_hits = 0
    entity_hits = 0
    rejected_count = 0
    strongest_match_score = 0.0

    for match in matches[:8]:
        candidate_text = _match_text(match, source)
        match_terms = _normalize_terms([candidate_text, *(match.get("tags") or [])])
        match_features = extract_nlp_features(candidate_text)
        lexical = _hybrid_lexical_overlap(base_terms, match_terms)
        semantic = hybrid_semantic_score(base_text, candidate_text, base_features, match_features)
        temporal = _compute_time_proximity_score(entity_time, _match_time(match, source))
        entity_info = entity_overlap(base_features, match_features)
        entity_score = float(entity_info.get("score", 0.0))
        shared_term_count = len(set(base_terms) & set(match_terms))

        joined_terms = " ".join(match_terms)
        exact_cve = any(cve_id in joined_terms for cve_id in {t for t in base_terms if CVE_RE.fullmatch(t)})
        high_signal_term_hits = len(_normalize_threat_terms(match_terms) & _normalize_threat_terms(base_terms + list(HIGH_IMPACT_TERMS)))

        accepted, reason = _accept_match(
            source=source,
            lexical=lexical,
            semantic=semantic,
            temporal=temporal,
            entity_score=entity_score,
            shared_term_count=shared_term_count,
            exact_cve=exact_cve,
            high_signal_term_hits=high_signal_term_hits,
        )
        if not accepted:
            rejected_count += 1
            continue

        score = (
            lexical * cfg.lexical_weight
            + semantic * cfg.semantic_weight
            + temporal * cfg.temporal_weight
            + entity_score * cfg.entity_weight
        )

        if source == "urlhaus" and str(match.get("url_status", "")).lower() == "online":
            score += cfg.online_weight
            online_hits += 1

        if high_signal_term_hits:
            score += min(cfg.high_signal_weight + (0.04 * high_signal_term_hits), 0.45)
            high_signal_hits += 1

        if exact_cve:
            score += 0.60 if source == "urlhaus" else 0.50
            exact_cve_hits += 1

        if entity_score > 0:
            entity_hits += 1

        accepted_scores.append(score)
        strongest_match_score = max(strongest_match_score, score)
        lexical_scores.append(round(lexical, 4))
        semantic_scores.append(round(semantic, 4))
        temporal_scores.append(round(temporal, 4))
        entity_scores.append(round(entity_score, 4))
        shared_terms.extend(top_shared_terms(base_terms, match_terms, limit=8))
        reasons.append(reason)

    cap = cfg.urlhaus_score_cap if source == "urlhaus" else cfg.dread_score_cap
    if not accepted_scores:
        return 0.0, [], _empty_match_stats(rejected_count=len(matches[:8]))

    # Diminishing returns: three weak similar posts should not outweigh one strong exact correlation.
    accepted_scores.sort(reverse=True)
    total_score = 0.0
    for idx, score in enumerate(accepted_scores):
        total_score += score * (0.72 ** idx)

    avg_lexical = _avg(lexical_scores)
    avg_semantic = _avg(semantic_scores)
    avg_temporal = _avg(temporal_scores)
    avg_entity = _avg(entity_scores)

    explanations = [f"Cross-source {source} correlation accepted ({len(accepted_scores)} of {len(matches[:8])} candidate record(s))."]
    if exact_cve_hits:
        explanations.append(f"Exact CVE identifier appeared in {exact_cve_hits} correlated record(s).")
    if avg_entity >= 0.18:
        explanations.append(f"Named entity alignment is meaningful (avg entity={avg_entity}).")
    if avg_lexical >= 0.12:
        explanations.append(f"Lexical overlap is meaningful (avg lexical={avg_lexical}).")
    if avg_semantic >= SETTINGS.semantic.similarity_floor:
        explanations.append(f"Semantic similarity is non-trivial (avg semantic={avg_semantic}).")
    if high_signal_hits:
        explanations.append("High-signal exploit, malware, or access-sale terminology reinforced the correlation.")
    if online_hits:
        explanations.append(f"{online_hits} IOC record(s) remain online, increasing operational relevance.")

    stats = {
        "avg_overlap_ratio": avg_lexical,
        "avg_lexical_score": avg_lexical,
        "avg_semantic_score": avg_semantic,
        "avg_temporal_score": avg_temporal,
        "avg_entity_score": avg_entity,
        "accepted_match_count": len(accepted_scores),
        "rejected_match_count": rejected_count,
        "exact_cve_hits": exact_cve_hits,
        "online_hits": online_hits,
        "high_signal_hits": high_signal_hits,
        "entity_overlap_hits": entity_hits,
        "strongest_match_score": round(strongest_match_score, 4),
        "shared_terms": sorted(set(shared_terms))[:12],
        "acceptance_reasons": sorted(set(reasons))[:8],
        "hybrid_score_cap": cap,
    }
    return min(round(total_score, 4), cap), explanations, stats


def _accept_match(
    *,
    source: str,
    lexical: float,
    semantic: float,
    temporal: float,
    entity_score: float,
    shared_term_count: int,
    exact_cve: bool,
    high_signal_term_hits: int,
) -> tuple[bool, str]:
    if exact_cve:
        return True, "exact_cve"
    if entity_score >= 0.30 and (semantic >= 0.10 or lexical >= 0.04):
        return True, "entity_alignment"
    if high_signal_term_hits >= 2 and (lexical >= 0.06 or semantic >= 0.18):
        return True, "high_signal_terms"
    if shared_term_count >= SETTINGS.retrieval.min_shared_terms and lexical >= SETTINGS.retrieval.min_lexical_overlap:
        return True, "lexical_overlap"
    if semantic >= max(SETTINGS.retrieval.min_semantic_support, 0.30) and temporal >= 0.2:
        return True, "semantic_temporal_support"
    return False, "weak_support"


def _match_text(match: Dict[str, Any], source: str) -> str:
    if source == "urlhaus":
        return " ".join([
            str(match.get("url", "")),
            str(match.get("threat", "")),
            " ".join(str(tag) for tag in (match.get("tags") or [])),
            str(match.get("normalized_fields", {}).get("search_text", "")),
        ])
    return " ".join([
        str(match.get("title", "")),
        str(match.get("content", "")),
        str(match.get("category", "")),
        str(match.get("normalized_fields", {}).get("search_text", "")),
    ])


def _match_time(match: Dict[str, Any], source: str) -> Optional[str]:
    if source == "urlhaus":
        return match.get("date_added")
    return match.get("created_at") or match.get("published")


def _hybrid_lexical_overlap(base_terms: Iterable[str], match_terms: Iterable[str]) -> float:
    base_list = list(base_terms)
    match_list = list(match_terms)
    if not base_list or not match_list:
        return 0.0
    return round((weighted_jaccard(base_list, match_list) * 0.60) + (token_jaccard(base_list, match_list) * 0.40), 4)


def _normalize_terms(values: Iterable[str]) -> List[str]:
    terms: List[str] = []
    for value in values:
        for token in tokenize(str(value)):
            token = normalize_token(token).strip("._")
            if len(token) < 3 and not token.startswith("cve-"):
                continue
            if token in GENERIC_FILTER_TERMS and not token.startswith("cve-"):
                continue
            terms.append(THREAT_NORMALIZATION.get(token, token))
    return terms


def _normalize_threat_terms(terms: Iterable[str]) -> set[str]:
    normalized = set()
    for term in terms:
        key = normalize_token(term).replace("-", "").replace("_", "")
        value = THREAT_NORMALIZATION.get(key, THREAT_NORMALIZATION.get(normalize_token(term), normalize_token(term)))
        normalized.add(value)
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


def _avg(values: List[float]) -> float:
    return round(sum(values) / len(values), 4) if values else 0.0


def _empty_match_stats(rejected_count: int = 0) -> Dict[str, Any]:
    return {
        "avg_overlap_ratio": 0.0,
        "avg_lexical_score": 0.0,
        "avg_semantic_score": 0.0,
        "avg_temporal_score": 0.0,
        "avg_entity_score": 0.0,
        "accepted_match_count": 0,
        "rejected_match_count": rejected_count,
        "exact_cve_hits": 0,
        "online_hits": 0,
        "high_signal_hits": 0,
        "entity_overlap_hits": 0,
        "strongest_match_score": 0.0,
        "shared_terms": [],
        "acceptance_reasons": [],
    }


def correlate_keywords(source_keywords=None, candidate_texts=None, **kwargs):
    source_keywords = source_keywords or kwargs.get("base_keywords") or []
    candidate_texts = candidate_texts or kwargs.get("candidate_keywords") or []

    base_terms = _normalize_terms(source_keywords)
    cand_terms = _normalize_terms(candidate_texts)
    shared_terms = top_shared_terms(base_terms, cand_terms, limit=10)
    high_impact = {normalize_token(t) for t in HIGH_IMPACT_TERMS | set(THREAT_PATTERNS)}

    return {
        "overlap_count": len(shared_terms),
        "overlap_ratio": token_jaccard(base_terms, cand_terms),
        "weighted_overlap": weighted_jaccard(base_terms, cand_terms),
        "shared_terms": shared_terms,
        "has_high_impact_overlap": any(term in high_impact for term in shared_terms),
    }
