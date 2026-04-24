from analysis.keyword_extractor import extract_keywords


def test_extract_keywords_finds_cve_and_signal_terms():
    text = """
    CVE-2024-12345 allows remote code execution in Example Product.
    Attackers may use a loader and malware for exploitation.
    """
    keywords = extract_keywords(text)

    assert "cve-2024-12345" in keywords
    assert "loader" in keywords
    assert "malware" in keywords


def test_extract_keywords_removes_common_stopwords():
    text = "the and for with this that product vulnerability may can also"
    keywords = extract_keywords(text)

    assert keywords == []


def test_extract_keywords_limits_result_count():
    text = " ".join([f"token{i}" for i in range(30)])
    keywords = extract_keywords(text)

    assert len(keywords) <= 12


def test_extract_keywords_uses_extra_field():
    keywords = extract_keywords("simple description", extra="CVE-2023-9999")

    assert "cve-2023-9999" in keywords