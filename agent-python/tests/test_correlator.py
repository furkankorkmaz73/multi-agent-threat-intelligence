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


def test_score_urlhaus_exact_cve_match_remains_accepted():
    matches = [
        {
            "url": "https://malware.example/dropper/CVE-2026-1234.exe",
            "threat": "malware_download",
            "tags": ["loader"],
            "url_status": "offline",
            "date_added": "2026-04-20T10:00:00+00:00",
        }
    ]

    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["CVE-2026-1234", "example product"],
        entity_time="2026-04-21T10:00:00+00:00",
    )

    assert score > 0
    assert explanations
    assert stats["accepted_match_count"] == 1
    assert stats["accepted_evidence_count"] == 1
    assert stats["exact_cve_hits"] == 1
    assert stats["ignored_low_signal_count"] == 0


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
    assert "exploit_sale" in stats["accepted_dread_categories"]
    assert "exploit_sale" in stats["observed_dread_categories"]
    assert stats["exact_cve_hits"] >= 1
    assert stats["avg_overlap_ratio"] > 0
    assert stats["evidence_source"] == "dread"
    assert stats["evidence_reliability"] < 0.5
    assert stats["dread_evidence_present"] is True


def test_non_exact_dread_high_signal_is_diagnostic_not_accepted():
    matches = [
        {
            "title": "VPN exploit chatter",
            "content": "Selling rce exploit access for exposed VPN appliances.",
            "created_at": "2026-04-21T10:00:00+00:00",
        }
    ]

    score, explanations, categories, stats = score_dread_matches(
        matches,
        base_keywords=["example vpn", "rce", "exploit"],
        entity_time="2026-04-22T10:00:00+00:00",
    )

    assert score == 0.0
    assert explanations == []
    assert categories == []
    assert "exploit_sale" in stats["observed_dread_categories"]
    assert stats["accepted_dread_categories"] == []
    assert stats["accepted_match_count"] == 0
    assert stats["manual_review_match_count"] == 1
    assert stats["accepted_evidence_count"] == 0
    assert stats["manual_review_evidence_count"] == 1
    assert stats["dread_only_evidence"] is True

def test_zero_signal_urlhaus_candidates_are_ignored_not_rejected():
    matches = [
        {
            "url": "https://refundonex.com/cloud/form_96986.pdf.ps1",
            "threat": "malware_download",
            "tags": ["ascii", "opendir", "powershell", "ps1"],
            "url_status": "offline",
            "date_added": "",
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
    assert stats["raw_candidate_count"] == 1
    assert stats["ignored_low_signal_count"] == 1
    assert stats["evaluated_candidate_count"] == 0
    assert stats["signal_candidate_count"] == 0
    assert stats["rejected_match_count"] == 0
    assert stats["accepted_evidence_count"] == 0
    assert stats["rejected_evidence_count"] == 0
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
    assert stats["ignored_low_signal_count"] == 0
    assert stats["signal_candidate_count"] == 1
    assert stats["rejected_match_count"] == 1
    assert stats["accepted_matches"] == []
    assert stats["shared_terms"] == []


def test_urlhaus_generic_platform_shared_term_is_rejected():
    matches = [
        {
            "url": "https://ip-address-check-mo.vercel.app/api/settings/windows",
            "threat": "malware_download",
            "tags": ["ContagiousInterview", "DPRK", "Lazarus"],
            "url_status": "offline",
            "date_added": "",
        }
    ]

    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["cve-2005-0051", "microsoft windows", "remote code execution", "windows"],
        entity_time="2005-05-02T04:00:00+00:00",
    )

    assert score == 0.0
    assert explanations == []
    assert stats["accepted_match_count"] == 0
    assert stats["ignored_low_signal_count"] == 1
    assert stats["rejected_match_count"] == 0
    assert stats["shared_terms"] == []


def test_urlhaus_generic_cms_shared_term_is_rejected():
    matches = [
        {
            "url": "https://krikadoo.com/wordpress/update.ps1",
            "threat": "malware_download",
            "tags": ["PhantomStealer", "powershell", "ps1"],
            "url_status": "offline",
            "date_added": "",
        }
    ]

    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["cve-2006-2702", "wordpress", "plugin", "cross site scripting"],
        entity_time="2006-05-31T10:06:00+00:00",
    )

    assert score == 0.0
    assert explanations == []
    assert stats["accepted_match_count"] == 0
    assert stats["ignored_low_signal_count"] == 1
    assert stats["rejected_match_count"] == 0
    assert stats["shared_terms"] == []


def test_signal_bearing_urlhaus_candidate_can_be_rejected():
    matches = [
        {
            "url": "https://malware.example/payload.exe",
            "threat": "malware_download",
            "tags": ["payload"],
            "url_status": "offline",
            "date_added": "2026-05-04T10:00:00+00:00",
        }
    ]

    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["cve-2026-20101", "example vpn", "rce"],
        entity_time="2026-05-04T10:00:00+00:00",
    )

    assert score == 0.0
    assert explanations == []
    assert stats["ignored_low_signal_count"] == 0
    assert stats["signal_candidate_count"] == 1
    assert stats["rejected_match_count"] == 1
    assert stats["rejected_evidence_count"] == 1
