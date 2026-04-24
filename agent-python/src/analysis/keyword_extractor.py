import re
from typing import List


STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "have", "has",
    "allow", "allows", "could", "would", "there", "their", "them", "been",
    "being", "after", "before", "about", "through", "remote", "local", "attack",
    "attacker", "attackers", "vulnerability", "vulnerabilities", "product",
    "products", "component", "components", "affected", "impact", "issue",
    "causes", "using", "used", "when", "where", "which", "via",
    "unauthenticated", "authenticated", "arbitrary", "code", "execution",
    "privilege", "escalation", "denial", "service", "overflow", "buffer",
    "improper", "input", "validation", "application", "software", "version",
    "versions", "may", "can", "also",
}

HIGH_SIGNAL_TERMS = {
    "rce", "exploit", "0day", "zero-day", "zeroday", "leak", "breach",
    "malware", "botnet", "cobaltstrike", "ransomware", "phishing",
    "credential", "access", "shell", "loader", "dropper", "backdoor",
}


def extract_keywords(text: str, extra: str = "") -> List[str]:
    combined = f"{text} {extra}".lower()
    cve_ids = re.findall(r"cve-\d{4}-\d{4,7}", combined, flags=re.IGNORECASE)

    tokens = re.findall(r"[a-zA-Z0-9\-_\.]{4,}", combined)
    cleaned: List[str] = []

    for token in tokens:
        token = token.strip("._- ").lower()
        if not token or token in STOPWORDS or token.isdigit():
            continue
        cleaned.append(token)

    boosted: List[str] = []
    for token in cleaned:
        if token in HIGH_SIGNAL_TERMS:
            boosted.append(token)
        elif any(ch.isdigit() for ch in token):
            boosted.append(token)
        elif token[0].isalpha():
            boosted.append(token)

    seen = set()
    result: List[str] = []
    for item in cve_ids + boosted:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result[:12]