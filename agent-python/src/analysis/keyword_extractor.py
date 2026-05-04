from __future__ import annotations

from typing import List

from analysis.nlp_features import extract_nlp_features


def extract_keywords(text: str, extra: str = "") -> List[str]:
    """Return high-signal, normalized search terms for cross-source retrieval.

    The old implementation was mostly token filtering. This version keeps the same
    public function but prioritizes CVE/CWE identifiers, products, vulnerability
    types, threat terms, and salient phrases from the lightweight NLP extractor.
    """
    features = extract_nlp_features(text, extra)
    ordered = (
        features.cve_ids
        + features.cwe_ids
        + features.products
        + features.vuln_types
        + features.threat_terms
        + features.impacts
        + features.keywords
        + features.salient_phrases
    )
    seen = set()
    result: List[str] = []
    for item in ordered:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
        if len(result) >= 12:
            break
    return result
