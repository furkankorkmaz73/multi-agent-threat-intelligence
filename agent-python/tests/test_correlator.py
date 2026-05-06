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
    assert stats["accepted_match_count"] == 1
    assert stats["accepted_matches"][0]["url"] == "http://bad.example/download.exe"


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

def test_weak_urlhaus_candidates_are_rejected():
    matches = [
        {
            "url": "https://refundonex.com/cloud/form_96986.pdf.ps1",
            "threat": "malware_download",
            "tags": ["ascii", "opendir", "powershell", "ps1"],
            "url_status": "offline",
            "date_added": "2026-05-04T10:00:00+00:00",
        }
    ]

    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=[
            "cve-2026-20100",
            "cisco secure firewall",
            "remote access ssl vpn",
            "denial_of_service",
            "service_disruption",
        ],
        entity_time="2026-03-04T10:00:00+00:00",
    )

    assert score == 0.0
    assert explanations == []
    assert stats["accepted_match_count"] == 0
    assert stats["rejected_match_count"] == 1
    assert stats["accepted_matches"] == []


def test_urlhaus_entity_alignment_without_meaningful_terms_is_rejected():
    matches = [
        {
            "url": "https://github.com/sunxholejabi/bc-game-crash-predictor/raw/refs/heads/main/CrashPredictor.Test/Markup/predictor-crash-game-bc-2.0.zip",
            "threat": "malware_download",
            "tags": ["SmartLoader", "zip"],
            "url_status": "offline",
            "date_added": "2026-05-04T10:00:00+00:00",
        }
    ]

    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["cve-2006-5295", "bc game crash predictor", "crash predictor", "game"],
        entity_time="2006-10-16T23:07:00+00:00",
    )

    assert score == 0.0
    assert explanations == []
    assert stats["accepted_match_count"] == 0
    assert stats["rejected_match_count"] == 1
    assert stats["accepted_matches"] == []
    assert stats["shared_terms"] == []
