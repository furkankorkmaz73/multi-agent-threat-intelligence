from analysis.nlp_features import entity_overlap, extract_nlp_features, hybrid_semantic_score


def test_nlp_features_extracts_core_security_entities():
    text = "CVE-2026-1111 allows remote code execution in Example Product 1.2 and may lead to takeover."
    features = extract_nlp_features(text)

    assert "cve-2026-1111" in features.cve_ids
    assert "remote_code_execution" in features.vuln_types
    assert "takeover" in features.impacts
    assert "example product" in features.products


def test_entity_overlap_scores_shared_cve_and_vulnerability_type():
    left = extract_nlp_features("CVE-2026-1111 remote code execution in vpn gateway")
    right = extract_nlp_features("Exploit sale for CVE-2026-1111 RCE access")

    overlap = entity_overlap(left, right)

    assert overlap["score"] > 0
    assert "cve_ids" in overlap["matches"]


def test_hybrid_semantic_score_stays_bounded():
    left = extract_nlp_features("ransomware loader targets cve-2026-1111")
    right = extract_nlp_features("malware loader exploiting CVE-2026-1111")

    score = hybrid_semantic_score(" ".join(left.all_terms), " ".join(right.all_terms), left, right)

    assert 0.0 <= score <= 1.0
    assert score > 0.2
