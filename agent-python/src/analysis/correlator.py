from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from config import get_settings
from analysis.correlation_decisions import (
    CorrelationDecision,
    CorrelationDecisionStatus,
    build_correlation_candidate,
    correlation_decision_row,
    decide_correlation_candidate,
)
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

# URLhaus records are IOC artifacts. Generic URL/path tokens can accidentally
# align with CVE descriptions and should not make a candidate accepted evidence.
URL_ARTIFACT_NOISE_TERMS = {
    "api", "cdn", "cloud", "cloudflare", "com", "data", "dl", "download",
    "exe", "file", "files", "form", "github", "head", "heads", "html",
    "http", "https", "index", "index.php", "main", "mode", "php", "raw",
    "ref", "refs", "token", "url", "zip",
}

# Broad platform/CMS/vendor tokens are too low-specificity to prove that a
# malware URL is related to a CVE. They may still be useful in NLP/entity
# extraction elsewhere, but for URLhaus correlation they must not become
# meaningful shared terms by themselves.
URLHAUS_LOW_SPECIFICITY_SHARED_TERMS = {
    "windows", "microsoft", "linux", "wordpress", "apache", "nginx",
    "php", "java", "android", "server", "web", "plugin", "cms",
}

GENERIC_FILTER_TERMS = set(WEAK_TERMS) | URL_ARTIFACT_NOISE_TERMS | URLHAUS_LOW_SPECIFICITY_SHARED_TERMS
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
    return score, explanations, list(stats.get("accepted_dread_categories") or []), stats


def build_correlation_decisions(
    matches: List[Dict[str, Any]],
    base_keywords: Optional[List[str]] = None,
    entity_time: Optional[str] = None,
    *,
    source: str,
) -> List[CorrelationDecision]:
    base_terms = _normalize_terms(base_keywords or [])
    base_text = " ".join(base_terms)
    base_features = extract_nlp_features(base_text)
    decisions: List[CorrelationDecision] = []
    for match in matches[:8]:
        evaluated = _evaluate_match(
            match=match,
            source=source,
            base_terms=base_terms,
            base_text=base_text,
            base_features=base_features,
            entity_time=entity_time,
        )
        decisions.append(evaluated["decision"])
    return decisions


def build_correlation_decision_rows(
    matches: List[Dict[str, Any]],
    base_keywords: Optional[List[str]] = None,
    entity_time: Optional[str] = None,
    *,
    source: str,
) -> List[Dict[str, Any]]:
    base_terms = _normalize_terms(base_keywords or [])
    base_text = " ".join(base_terms)
    base_features = extract_nlp_features(base_text)
    rows: List[Dict[str, Any]] = []
    for match in matches[:8]:
        evaluated = _evaluate_match(
            match=match,
            source=source,
            base_terms=base_terms,
            base_text=base_text,
            base_features=base_features,
            entity_time=entity_time,
        )
        rows.append(correlation_decision_row(evaluated["candidate"], evaluated["decision"]))
    return rows


def _score_matches(
    matches: List[Dict[str, Any]],
    base_keywords: Optional[List[str]],
    entity_time: Optional[str],
    source: str,
) -> Tuple[float, List[str], Dict[str, Any]]:
    if not matches:
        return 0.0, [], _empty_match_stats(source=source)

    cfg = SETTINGS.scoring
    base_terms = _normalize_terms(base_keywords or [])
    base_text = " ".join(base_terms)
    base_features = extract_nlp_features(base_text)

    accepted_scores: List[float] = []
    accepted_matches: List[Dict[str, Any]] = []
    lexical_scores: List[float] = []
    semantic_scores: List[float] = []
    temporal_scores: List[float] = []
    entity_scores: List[float] = []
    shared_terms: List[str] = []
    reasons: List[str] = []
    candidate_dread_categories: List[str] = []
    accepted_dread_categories: List[str] = []

    exact_cve_hits = 0
    high_signal_hits = 0
    online_hits = 0
    entity_hits = 0
    raw_candidate_count = len(matches[:8])
    ignored_low_signal_count = 0
    signal_candidate_count = 0
    rejected_count = 0
    manual_review_count = 0
    strongest_match_score = 0.0
    status_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    accepted_reason_counts: Counter[str] = Counter()
    manual_review_reason_counts: Counter[str] = Counter()
    rejection_reason_counts: Counter[str] = Counter()
    ignored_reason_counts: Counter[str] = Counter()

    for match in matches[:8]:
        if source == "dread":
            candidate_dread_categories.extend(_dread_categories_for_match(match))
        evaluated = _evaluate_match(
            match=match,
            source=source,
            base_terms=base_terms,
            base_text=base_text,
            base_features=base_features,
            entity_time=entity_time,
        )
        lexical = evaluated["lexical"]
        semantic = evaluated["semantic"]
        temporal = evaluated["temporal"]
        entity_score = evaluated["entity_score"]
        meaningful_shared_terms = evaluated["meaningful_shared_terms"]
        exact_cve = evaluated["exact_cve"]
        high_signal_term_hits = evaluated["high_signal_term_hits"]
        decision = evaluated["decision"]
        reason = decision.primary_reason

        if _is_ignored_low_signal_candidate(evaluated):
            ignored_low_signal_count += 1
            ignored_reason_counts["low_signal_retrieval_noise"] += 1
            continue

        signal_candidate_count += 1
        status_counts[decision.status.value] += 1
        reason_counts[reason or "unspecified"] += 1
        if decision.status is not CorrelationDecisionStatus.ACCEPTED:
            if decision.status is CorrelationDecisionStatus.MANUAL_REVIEW:
                manual_review_count += 1
                manual_review_reason_counts[reason or "unspecified"] += 1
            else:
                rejected_count += 1
                rejection_reason_counts[reason or "unspecified"] += 1
            continue
        if source == "dread":
            accepted_dread_categories.extend(_dread_categories_for_match(match))
        accepted_reason_counts[reason or "unspecified"] += 1

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
        accepted_matches.append(_accepted_match_summary(match, source, score=score, reason=reason))
        strongest_match_score = max(strongest_match_score, score)
        lexical_scores.append(round(lexical, 4))
        semantic_scores.append(round(semantic, 4))
        temporal_scores.append(round(temporal, 4))
        entity_scores.append(round(entity_score, 4))
        shared_terms.extend(meaningful_shared_terms)
        reasons.append(reason)

    cap = cfg.urlhaus_score_cap if source == "urlhaus" else cfg.dread_score_cap
    if not accepted_scores:
        return 0.0, [], _empty_match_stats(
            raw_candidate_count=raw_candidate_count,
            ignored_low_signal_count=ignored_low_signal_count,
            signal_candidate_count=signal_candidate_count,
            rejected_count=rejected_count,
            manual_review_count=manual_review_count,
            source=source,
            candidate_dread_categories=candidate_dread_categories,
            status_counts=status_counts,
            reason_counts=reason_counts,
            accepted_reason_counts=accepted_reason_counts,
            manual_review_reason_counts=manual_review_reason_counts,
            rejection_reason_counts=rejection_reason_counts,
            ignored_reason_counts=ignored_reason_counts,
        )

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
        "raw_candidate_count": raw_candidate_count,
        "evaluated_candidate_count": raw_candidate_count - ignored_low_signal_count,
        "signal_candidate_count": signal_candidate_count,
        "ignored_low_signal_count": ignored_low_signal_count,
        "rejected_match_count": rejected_count,
        "manual_review_match_count": manual_review_count,
        "accepted_evidence_count": len(accepted_scores),
        "rejected_evidence_count": rejected_count,
        "manual_review_evidence_count": manual_review_count,
        "exact_cve_hits": exact_cve_hits,
        "online_hits": online_hits,
        "high_signal_hits": high_signal_hits,
        "entity_overlap_hits": entity_hits,
        "strongest_match_score": round(strongest_match_score, 4),
        "shared_terms": sorted(set(shared_terms))[:12],
        "acceptance_reasons": sorted(set(reasons))[:8],
        "accepted_matches": accepted_matches[:8],
        "status_distribution": _counter_dict(status_counts, ("accepted", "manual_review", "rejected")),
        "reason_code_distribution": _counter_dict(reason_counts),
        "accepted_reason_distribution": _counter_dict(accepted_reason_counts),
        "manual_review_reason_distribution": _counter_dict(manual_review_reason_counts),
        "rejection_reason_distribution": _counter_dict(rejection_reason_counts),
        "ignored_reason_distribution": _counter_dict(ignored_reason_counts),
        "candidate_count": raw_candidate_count,
        "hybrid_score_cap": cap,
        "evidence_source": source,
        "evidence_reliability": _source_reliability(source),
        "dread_evidence_present": source == "dread" and bool(matches[:8]),
        "dread_only_evidence": source == "dread",
        "corroborated_dread_evidence": False,
        "candidate_dread_categories": sorted(set(candidate_dread_categories))[:8],
        "observed_dread_categories": sorted(set(candidate_dread_categories))[:8],
        "accepted_dread_categories": sorted(set(accepted_dread_categories))[:8],
    }
    return min(round(total_score, 4), cap), explanations, stats


def _dread_categories_for_match(match: Dict[str, Any]) -> List[str]:
    categories: List[str] = []
    combined_text = f"{match.get('title', '')} {match.get('content', '')}".lower()
    for category, terms in DREAD_CLASSIFIERS.items():
        if any(term in combined_text for term in terms):
            categories.append(category)
    return categories


def _is_ignored_low_signal_candidate(evaluated: Dict[str, Any]) -> bool:
    """Return True for raw retrieval noise with no usable evidence signal."""
    return bool(
        not evaluated.get("exact_cve")
        and int(evaluated.get("high_signal_term_hits") or 0) == 0
        and len(evaluated.get("meaningful_shared_terms") or []) == 0
        and float(evaluated.get("lexical") or 0.0) == 0.0
        and float(evaluated.get("semantic") or 0.0) < SETTINGS.semantic.similarity_floor
        and float(evaluated.get("temporal") or 0.0) == 0.0
        and float(evaluated.get("entity_score") or 0.0) == 0.0
    )


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
    entity_matches: Optional[Dict[str, List[str]]] = None,
) -> tuple[bool, str]:
    candidate = build_correlation_candidate(
        source=source,
        source_identifier="source",
        target_identifier="target",
        relation_type=f"{source}_correlation",
        lexical=lexical,
        semantic=semantic,
        temporal=temporal,
        entity_score=entity_score,
        shared_term_count=shared_term_count,
        exact_cve=exact_cve,
        high_signal_term_hits=high_signal_term_hits,
        entity_matches=entity_matches or {},
    )
    decision = decide_correlation_candidate(
        candidate,
        min_shared_terms=SETTINGS.retrieval.min_shared_terms,
        min_lexical_overlap=SETTINGS.retrieval.min_lexical_overlap,
        min_semantic_support=SETTINGS.retrieval.min_semantic_support,
    )
    return decision.status is CorrelationDecisionStatus.ACCEPTED, decision.primary_reason


def _evaluate_match(
    *,
    match: Dict[str, Any],
    source: str,
    base_terms: List[str],
    base_text: str,
    base_features: Any,
    entity_time: Optional[str],
) -> Dict[str, Any]:
    candidate_text = _match_text(match, source)
    match_terms = _normalize_terms([candidate_text, *(match.get("tags") or [])])
    match_features = extract_nlp_features(candidate_text)
    lexical = _hybrid_lexical_overlap(base_terms, match_terms)
    semantic = hybrid_semantic_score(base_text, candidate_text, base_features, match_features)
    temporal = _compute_time_proximity_score(entity_time, _match_time(match, source))
    entity_info = entity_overlap(base_features, match_features)
    entity_score = float(entity_info.get("score", 0.0))
    shared_for_match = top_shared_terms(base_terms, match_terms, limit=8)
    meaningful_shared_terms = _meaningful_shared_terms(shared_for_match)
    shared_term_count = len(meaningful_shared_terms)

    joined_terms = " ".join(match_terms)
    exact_cve = any(cve_id in joined_terms for cve_id in {t for t in base_terms if CVE_RE.fullmatch(t)})
    base_high_signal_terms = _normalize_threat_terms(base_terms) & _normalize_threat_terms(HIGH_IMPACT_TERMS)
    candidate_high_signal_terms = _normalize_threat_terms(match_terms) & _normalize_threat_terms(HIGH_IMPACT_TERMS)
    high_signal_term_hits = len(base_high_signal_terms & candidate_high_signal_terms)
    candidate = build_correlation_candidate(
        source=source,
        source_identifier=_source_identifier(base_terms),
        target_identifier=_target_identifier(match, source),
        relation_type=f"{source}_correlation",
        lexical=lexical,
        semantic=semantic,
        temporal=temporal,
        entity_score=entity_score,
        shared_term_count=shared_term_count,
        exact_cve=exact_cve,
        high_signal_term_hits=high_signal_term_hits,
        entity_matches=entity_info.get("matches", {}),
        observed_at=_match_time(match, source),
        raw_reference=_raw_reference(match, source),
    )
    decision = decide_correlation_candidate(
        candidate,
        min_shared_terms=SETTINGS.retrieval.min_shared_terms,
        min_lexical_overlap=SETTINGS.retrieval.min_lexical_overlap,
        min_semantic_support=SETTINGS.retrieval.min_semantic_support,
    )
    return {
        "lexical": lexical,
        "semantic": semantic,
        "temporal": temporal,
        "entity_score": entity_score,
        "meaningful_shared_terms": meaningful_shared_terms,
        "exact_cve": exact_cve,
        "high_signal_term_hits": high_signal_term_hits,
        "candidate": candidate,
        "decision": decision,
    }


def _accepted_match_summary(match: Dict[str, Any], source: str, *, score: float, reason: str) -> Dict[str, Any]:
    """Return a JSON-safe, minimal view of an accepted correlation candidate.

    The risk engine and graph builder must only consume accepted evidence. Keeping
    this summary small prevents raw feed records or ObjectIds from leaking into
    the persisted analysis payload.
    """
    base = {
        "score": round(float(score), 4),
        "acceptance_reason": reason,
    }
    if source == "urlhaus":
        base.update({
            "url": match.get("url"),
            "threat": match.get("threat"),
            "tags": list(match.get("tags") or [])[:8],
            "url_status": match.get("url_status"),
            "date_added": match.get("date_added"),
        })
    else:
        base.update({
            "title": match.get("title"),
            "category": match.get("category"),
            "author": match.get("author"),
            "created_at": match.get("created_at") or match.get("published"),
        })
    return base


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


def _source_identifier(base_terms: List[str]) -> str:
    for term in base_terms:
        if CVE_RE.fullmatch(term):
            return term.upper()
    return " ".join(base_terms[:5]) or "unknown-source"


def _target_identifier(match: Dict[str, Any], source: str) -> str:
    if source == "urlhaus":
        return str(match.get("url") or match.get("urlhaus_id") or "unknown-urlhaus")
    return str(match.get("title") or match.get("_id") or match.get("url") or "unknown-dread")


def _raw_reference(match: Dict[str, Any], source: str) -> Optional[str]:
    if source == "urlhaus":
        value = match.get("url") or match.get("urlhaus_reference")
    else:
        value = match.get("url") or match.get("_id") or match.get("title")
    return str(value) if value not in (None, "") else None


def _meaningful_shared_terms(shared_terms: Iterable[str]) -> List[str]:
    meaningful: List[str] = []
    seen = set()
    for term in shared_terms:
        normalized = normalize_token(str(term)).strip("._-/")
        if not normalized or normalized in seen:
            continue
        if normalized in GENERIC_FILTER_TERMS and not CVE_RE.fullmatch(normalized):
            continue
        if len(normalized) < 4 and not CVE_RE.fullmatch(normalized):
            continue
        seen.add(normalized)
        meaningful.append(normalized)
    return meaningful


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


def _empty_match_stats(
    raw_candidate_count: int = 0,
    ignored_low_signal_count: int = 0,
    signal_candidate_count: int = 0,
    rejected_count: int = 0,
    manual_review_count: int = 0,
    source: str = "unknown",
    candidate_dread_categories: Optional[List[str]] = None,
    status_counts: Optional[Counter[str]] = None,
    reason_counts: Optional[Counter[str]] = None,
    accepted_reason_counts: Optional[Counter[str]] = None,
    manual_review_reason_counts: Optional[Counter[str]] = None,
    rejection_reason_counts: Optional[Counter[str]] = None,
    ignored_reason_counts: Optional[Counter[str]] = None,
) -> Dict[str, Any]:
    candidate_dread_categories = candidate_dread_categories or []
    status_counts = status_counts or Counter()
    reason_counts = reason_counts or Counter()
    accepted_reason_counts = accepted_reason_counts or Counter()
    manual_review_reason_counts = manual_review_reason_counts or Counter()
    rejection_reason_counts = rejection_reason_counts or Counter()
    ignored_reason_counts = ignored_reason_counts or Counter()
    raw_candidate_count = int(raw_candidate_count if raw_candidate_count else rejected_count + manual_review_count + ignored_low_signal_count)
    ignored_low_signal_count = int(ignored_low_signal_count)
    signal_candidate_count = int(signal_candidate_count if signal_candidate_count else rejected_count + manual_review_count)
    if not status_counts:
        status_counts.update({"manual_review": manual_review_count, "rejected": rejected_count})
    return {
        "avg_overlap_ratio": 0.0,
        "avg_lexical_score": 0.0,
        "avg_semantic_score": 0.0,
        "avg_temporal_score": 0.0,
        "avg_entity_score": 0.0,
        "accepted_match_count": 0,
        "raw_candidate_count": raw_candidate_count,
        "evaluated_candidate_count": max(raw_candidate_count - ignored_low_signal_count, 0),
        "signal_candidate_count": signal_candidate_count,
        "ignored_low_signal_count": ignored_low_signal_count,
        "rejected_match_count": rejected_count,
        "manual_review_match_count": manual_review_count,
        "accepted_evidence_count": 0,
        "rejected_evidence_count": rejected_count,
        "manual_review_evidence_count": manual_review_count,
        "exact_cve_hits": 0,
        "online_hits": 0,
        "high_signal_hits": 0,
        "entity_overlap_hits": 0,
        "strongest_match_score": 0.0,
        "shared_terms": [],
        "acceptance_reasons": [],
        "accepted_matches": [],
        "status_distribution": _counter_dict(status_counts, ("accepted", "manual_review", "rejected")),
        "reason_code_distribution": _counter_dict(reason_counts),
        "accepted_reason_distribution": _counter_dict(accepted_reason_counts),
        "manual_review_reason_distribution": _counter_dict(manual_review_reason_counts),
        "rejection_reason_distribution": _counter_dict(rejection_reason_counts),
        "ignored_reason_distribution": _counter_dict(ignored_reason_counts),
        "candidate_count": raw_candidate_count,
        "evidence_source": source,
        "evidence_reliability": _source_reliability(source),
        "dread_evidence_present": source == "dread" and signal_candidate_count > 0,
        "dread_only_evidence": source == "dread" and signal_candidate_count > 0,
        "corroborated_dread_evidence": False,
        "candidate_dread_categories": sorted(set(candidate_dread_categories))[:8],
        "observed_dread_categories": sorted(set(candidate_dread_categories))[:8],
        "accepted_dread_categories": [],
    }


def _source_reliability(source: str) -> float:
    if source == "urlhaus":
        return 0.84
    if source == "dread":
        return 0.38
    return 0.0


def _counter_dict(counter: Counter[str], keys: Iterable[str] = ()) -> Dict[str, int]:
    data = {key: int(counter.get(key, 0)) for key in keys}
    data.update({key: int(value) for key, value in sorted(counter.items()) if int(value) > 0})
    return data


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
