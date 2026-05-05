from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Sequence

from analysis.semantic_similarity import semantic_similarity, tokenize

CVE_RE = re.compile(r"\bcve-\d{4}-\d{4,7}\b", re.I)
VERSION_RE = re.compile(r"\b(?:v(?:ersion)?\s*)?(\d+(?:\.\d+){1,3})(?:\s*(?:through|to|-|<=|<)\s*\d+(?:\.\d+){1,3})?\b", re.I)
URL_RE = re.compile(r"https?://[^\s\]\)>'\"]+", re.I)
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
CWE_RE = re.compile(r"\bcwe-\d+\b", re.I)

VULN_PATTERNS = {
    "remote_code_execution": ["remote code execution", "rce", "execute arbitrary code", "code execution"],
    "privilege_escalation": ["privilege escalation", "elevation of privilege", "escalate privileges"],
    "authentication_bypass": ["authentication bypass", "auth bypass", "bypass authentication"],
    "sql_injection": ["sql injection", "sqli"],
    "xss": ["cross-site scripting", "xss"],
    "path_traversal": ["path traversal", "directory traversal"],
    "deserialization": ["deserialization", "deserialize"],
    "buffer_overflow": ["buffer overflow", "heap overflow", "stack overflow"],
    "information_disclosure": ["information disclosure", "sensitive information", "data exposure"],
    "denial_of_service": ["denial of service", "dos", "crash"],
}

IMPACT_PATTERNS = {
    "takeover": ["takeover", "full control", "compromise", "remote compromise"],
    "credential_theft": ["credential", "password", "token", "session", "cookie"],
    "data_leak": ["leak", "exfiltrate", "dump", "database", "records", "sensitive data"],
    "service_disruption": ["denial of service", "service disruption", "crash", "unavailable"],
    "initial_access": ["initial access", "foothold", "vpn", "rdp", "shell access"],
}

THREAT_PATTERNS = {
    "ransomware", "malware", "loader", "dropper", "stealer", "botnet", "backdoor",
    "cobaltstrike", "cobalt strike", "phishing", "exploit", "0day", "zero-day", "zeroday",
    "webshell", "shell", "rce", "credential", "access", "breach", "leak",
}

WEAK_TERMS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "have", "has",
    "may", "can", "also", "could", "would", "there", "their", "them", "been", "being",
    "after", "before", "about", "through", "where", "which", "via",
    "remote", "code", "execution", "vulnerability", "vulnerabilities", "attacker", "attackers",
    "allows", "allow", "issue", "component", "components", "product", "products", "software",
    "system", "systems", "version", "versions", "affected", "application", "service",
    "input", "output", "request", "response", "network", "user", "users", "crafted", "prior",
    "before", "after", "through", "using", "successful", "exploitation", "exploitability",
    # Common stopwords and generic security words that produced noisy CVE/IOC joins.
    "a", "an", "or", "of", "to", "in", "on", "by", "as", "is", "are", "was", "were",
    "de", "del", "la", "las", "el", "en", "y", "un", "una", "con", "que", "se",
    "security", "secure", "device", "devices", "server", "client", "feature", "condition",
    "cause", "result", "resulting", "valid", "validation", "management", "interface",
    "interfaces", "connection", "packets", "software", "http", "service", "access",
}

VENDOR_HINTS = {
    "microsoft", "windows", "office", "exchange", "sharepoint", "apache", "nginx", "linux",
    "ubuntu", "debian", "redhat", "openssl", "oracle", "cisco", "fortinet", "palo", "vmware",
    "wordpress", "drupal", "joomla", "chrome", "firefox", "android", "ios", "apple", "samsung",
}

@dataclass
class NLPFeatures:
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    products: List[str] = field(default_factory=list)
    versions: List[str] = field(default_factory=list)
    vuln_types: List[str] = field(default_factory=list)
    impacts: List[str] = field(default_factory=list)
    threat_terms: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    salient_phrases: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def all_terms(self) -> List[str]:
        merged: List[str] = []
        for group in [
            self.cve_ids, self.cwe_ids, self.products, self.versions, self.vuln_types,
            self.impacts, self.threat_terms, self.iocs, self.domains, self.keywords, self.salient_phrases,
        ]:
            merged.extend(group)
        return dedupe(merged)


def dedupe(values: Iterable[str], limit: int | None = None) -> List[str]:
    out: List[str] = []
    seen = set()
    for value in values:
        normalized = normalize_token(str(value))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        out.append(normalized)
        if limit is not None and len(out) >= limit:
            break
    return out


def normalize_token(value: str) -> str:
    value = (value or "").lower().strip().strip(".,;:()[]{}<>\"'")
    value = re.sub(r"\s+", " ", value)
    if value == "cobalt strike":
        return "cobaltstrike"
    return value


def extract_nlp_features(text: str, extra: str = "") -> NLPFeatures:
    raw = f"{text or ''} {extra or ''}".strip()
    lowered = raw.lower()
    tokens = list(tokenize(lowered))

    cve_ids = dedupe(CVE_RE.findall(lowered), limit=8)
    cwe_ids = dedupe(CWE_RE.findall(lowered), limit=8)
    urls = dedupe(URL_RE.findall(raw), limit=8)
    domains = dedupe(DOMAIN_RE.findall(raw), limit=8)
    versions = dedupe(VERSION_RE.findall(raw), limit=10)
    vuln_types = dedupe(_match_patterns(lowered, VULN_PATTERNS), limit=8)
    impacts = dedupe(_match_patterns(lowered, IMPACT_PATTERNS), limit=8)
    threat_terms = dedupe(_extract_threat_terms(lowered, tokens), limit=12)
    products = dedupe(_extract_product_candidates(raw, tokens), limit=12)
    salient_phrases = dedupe(_extract_salient_phrases(tokens), limit=10)
    keywords = dedupe(_rank_keywords(tokens, boost_terms=threat_terms + vuln_types + products + cve_ids + cwe_ids), limit=18)

    return NLPFeatures(
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        products=products,
        versions=versions,
        vuln_types=vuln_types,
        impacts=impacts,
        threat_terms=threat_terms,
        iocs=urls,
        domains=domains,
        keywords=keywords,
        salient_phrases=salient_phrases,
    )


def _match_patterns(text: str, patterns: Dict[str, Sequence[str]]) -> List[str]:
    hits: List[str] = []
    for label, phrases in patterns.items():
        if any(phrase in text for phrase in phrases):
            hits.append(label)
    return hits


def _extract_threat_terms(text: str, tokens: Sequence[str]) -> List[str]:
    hits = []
    token_set = {normalize_token(token) for token in tokens}
    for term in THREAT_PATTERNS:
        normalized = normalize_token(term)
        if " " in term:
            if term in text:
                hits.append(normalized)
        elif normalized in token_set:
            hits.append(normalized)
    return hits


def _extract_product_candidates(raw: str, tokens: Sequence[str]) -> List[str]:
    candidates: List[str] = []
    lowered_tokens = [normalize_token(t) for t in tokens]
    for token in lowered_tokens:
        if CVE_RE.fullmatch(token) or CWE_RE.fullmatch(token):
            continue
        if token in VENDOR_HINTS:
            candidates.append(token)
        elif any(ch.isdigit() for ch in token) and any(ch.isalpha() for ch in token) and token not in WEAK_TERMS:
            candidates.append(token)

    # Capture simple title-case product names from descriptions, e.g. "Example Product".
    for phrase in re.findall(r"\b([A-Z][A-Za-z0-9_\-]+(?:\s+[A-Z][A-Za-z0-9_\-]+){0,3})\b", raw or ""):
        norm = normalize_token(phrase)
        if len(norm) >= 4 and norm not in WEAK_TERMS and not CVE_RE.fullmatch(norm):
            candidates.append(norm)
    return candidates


def _extract_salient_phrases(tokens: Sequence[str]) -> List[str]:
    clean = [normalize_token(t) for t in tokens if len(t) >= 4 and normalize_token(t) not in WEAK_TERMS]
    bigrams = [f"{clean[i]} {clean[i+1]}" for i in range(len(clean) - 1)]
    trigrams = [f"{clean[i]} {clean[i+1]} {clean[i+2]}" for i in range(len(clean) - 2)]
    counts = Counter(bigrams + trigrams)
    return [phrase for phrase, _ in counts.most_common(10)]


def _rank_keywords(tokens: Sequence[str], boost_terms: Sequence[str]) -> List[str]:
    clean = [normalize_token(t) for t in tokens]
    clean = [t for t in clean if len(t) >= 3 and not t.isdigit() and t not in WEAK_TERMS]
    counts = Counter(clean)
    boost = {normalize_token(t) for t in boost_terms if t}
    scored = []
    for term, count in counts.items():
        score = math.log1p(count)
        if term in boost:
            score += 2.0
        if CVE_RE.fullmatch(term) or CWE_RE.fullmatch(term):
            score += 3.0
        if any(ch.isdigit() for ch in term):
            score += 0.5
        scored.append((term, score))
    return [term for term, _ in sorted(scored, key=lambda item: item[1], reverse=True)]


def semantic_text(features: NLPFeatures) -> str:
    return " ".join(features.all_terms)


def entity_overlap(left: NLPFeatures, right: NLPFeatures) -> Dict[str, Any]:
    groups = {
        "cve_ids": (left.cve_ids, right.cve_ids, 1.0),
        "cwe_ids": (left.cwe_ids, right.cwe_ids, 0.7),
        "products": (left.products, right.products, 0.75),
        "vuln_types": (left.vuln_types, right.vuln_types, 0.85),
        "impacts": (left.impacts, right.impacts, 0.55),
        "threat_terms": (left.threat_terms, right.threat_terms, 0.8),
        "domains": (left.domains, right.domains, 0.65),
    }
    score = 0.0
    matches: Dict[str, List[str]] = {}
    for name, (a, b, weight) in groups.items():
        shared = sorted(set(a) & set(b))
        if shared:
            matches[name] = shared
            score += min(len(shared) * weight, weight)
    return {"score": round(min(score / 3.0, 1.0), 4), "matches": matches}


def hybrid_semantic_score(left_text: str, right_text: str, left_features: NLPFeatures | None = None, right_features: NLPFeatures | None = None) -> float:
    base = semantic_similarity(left_text, right_text)
    if left_features and right_features:
        ent = float(entity_overlap(left_features, right_features)["score"])
        return round((base * 0.65) + (ent * 0.35), 4)
    return round(base, 4)
