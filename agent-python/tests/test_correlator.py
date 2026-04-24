from analysis.correlator import correlate_keywords, score_dread_matches, score_urlhaus_matches


def test_correlate_keywords_detects_overlap():
    result = correlate_keywords(
        source_keywords=["cve-2024-1111", "ransomware", "loader"],
        candidate_texts=["This ransomware loader targets CVE-2024-1111 systems"],
    )

    assert result["overlap_count"] >= 2
    assert result["overlap_ratio"] > 0
    assert result["has_high_impact_overlap"] is True


def test_score_urlhaus_matches_returns_stats():
    matches = [
        {
            "url": "http://bad.example/download.exe",
            "threat": "malware",
            "tags": ["ransomware", "loader"],
            "url_status": "online",
            "date_added": "2026-04-20T10:00:00+00:00",
        }
    ]

    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["ransomware", "loader", "download.exe"],
        entity_time="2026-04-21T10:00:00+00:00",
    )

    assert score > 0
    assert len(explanations) > 0
    assert "avg_overlap_ratio" in stats
    assert stats["avg_overlap_ratio"] > 0


def test_score_dread_matches_returns_categories_and_stats():
    matches = [
        {
            "title": "0day exploit sale",
            "content": "Selling exploit for CVE-2026-1111 with rce access",
            "created_at": "2026-04-21T10:00:00+00:00",
        }
    ]

    score, explanations, categories, stats = score_dread_matches(
        matches,
        base_keywords=["cve-2026-1111", "exploit", "rce"],
        entity_time="2026-04-22T10:00:00+00:00",
    )

    assert score > 0
    assert "exploit_sale" in categories
    assert stats["exact_cve_hits"] >= 1
    assert stats["avg_overlap_ratio"] > 0