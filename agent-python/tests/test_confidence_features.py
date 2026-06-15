from analysis.features.confidence import (
    calculate_cve_confidence,
    calculate_rejected_cve_confidence,
    calculate_urlhaus_confidence,
)


def test_cve_strong_evidence_reaches_maximum_confidence_cap():
    result = calculate_cve_confidence(
        has_cvss=True,
        cvss_score=9.8,
        cvss_version="CVSS v3.1",
        description="A" * 220,
        age_days=2,
        urlhaus_match_count=4,
        dread_match_count=3,
        keyword_count=20,
        llm_fields_count=4,
        graph_score=2.0,
        nlp_entities={
            "products": ["vpn", "gateway", "firewall", "identity", "exchange", "router"],
            "vuln_types": ["remote_code_execution"],
            "impacts": ["initial_access"],
            "threat_terms": ["exploit"],
            "cve_ids": ["CVE-2026-0001"],
        },
        urlhaus_stats={
            "exact_cve_hits": 2,
            "high_signal_hits": 2,
            "entity_overlap_hits": 3,
            "shared_terms": ["rce", "vpn", "payload", "exploit"],
            "acceptance_reasons": ["exact_cve"],
            "avg_semantic_score": 0.9,
        },
        dread_stats={
            "exact_cve_hits": 1,
            "high_signal_hits": 1,
            "entity_overlap_hits": 2,
            "shared_terms": ["access", "ransomware"],
            "acceptance_reasons": ["high_signal"],
            "avg_semantic_score": 0.8,
        },
    )

    assert result.confidence == 0.95
    assert result.breakdown["final_confidence"] == 0.95
    assert result.breakdown["external_evidence_confidence"] == 0.38


def test_cve_weak_metadata_without_external_evidence_has_low_confidence():
    result = calculate_cve_confidence(
        has_cvss=True,
        cvss_score=4.2,
        cvss_version="CVSS v2.0",
        description="Weak issue summary.",
        age_days=500,
        urlhaus_match_count=0,
        dread_match_count=0,
        keyword_count=1,
        llm_fields_count=0,
        graph_score=0.0,
        nlp_entities={},
    )

    assert result.confidence == 0.203
    assert result.breakdown["metadata_confidence"] == 0.28
    assert result.breakdown["penalties"] == -0.2
    assert result.breakdown["signals"]["epss_available"] is False
    assert result.breakdown["signals"]["kev_status_known"] is False
    assert "epss_unavailable" in result.breakdown["coverage_limitations"]
    assert "kev_status_unknown" in result.breakdown["coverage_limitations"]


def test_cve_missing_evidence_uses_minimum_confidence_floor():
    result = calculate_cve_confidence(
        has_cvss=False,
        description="",
        age_days=None,
        urlhaus_match_count=0,
        dread_match_count=0,
        keyword_count=0,
        llm_fields_count=0,
        graph_score=0.0,
        nlp_entities={},
    )

    assert result.confidence == 0.05
    assert result.breakdown["final_confidence"] == 0.05
    assert result.breakdown["signals"]["has_cvss"] is False


def test_cve_conflicting_entity_alignment_evidence_is_penalized():
    result = calculate_cve_confidence(
        has_cvss=True,
        cvss_score=7.5,
        cvss_version="CVSS v3.1",
        description="Remote code execution vulnerability in Example Product.",
        age_days=45,
        urlhaus_match_count=1,
        dread_match_count=0,
        keyword_count=6,
        llm_fields_count=0,
        graph_score=1.0,
        nlp_entities={"products": ["example product"], "vuln_types": ["remote_code_execution"]},
        urlhaus_stats={
            "entity_overlap_hits": 1,
            "acceptance_reasons": ["entity_alignment"],
            "avg_semantic_score": 0.2,
        },
    )

    assert result.breakdown["signals"]["entity_alignment_only"] is True
    assert result.breakdown["external_evidence_confidence"] == 0.04
    assert result.breakdown["penalties"] == -0.03


def test_metadata_rich_cve_without_epss_kev_can_reach_moderate_confidence():
    result = calculate_cve_confidence(
        has_cvss=True,
        cvss_score=9.0,
        cvss_version="CVSS v3.1",
        description=(
            "A remote code execution vulnerability in Example VPN Gateway allows "
            "unauthenticated attackers to execute commands on exposed appliances. "
            "The record includes affected product and impact context."
        ),
        age_days=12,
        urlhaus_match_count=0,
        dread_match_count=0,
        keyword_count=12,
        llm_fields_count=0,
        graph_score=0.0,
        nlp_entities={
            "products": ["example vpn gateway"],
            "vuln_types": ["remote_code_execution"],
            "impacts": ["takeover"],
            "threat_terms": ["exploit"],
        },
        epss_available=False,
        kev_status_known=False,
    )

    assert 0.55 <= result.confidence < 0.8
    assert result.breakdown["assessment_confidence"] >= 0.55
    assert result.breakdown["data_completeness"] < 0.8
    assert result.breakdown["signals"]["accepted_external_evidence"] == 0
    assert "epss_unavailable" in result.breakdown["coverage_limitations"]
    assert "kev_status_unknown" in result.breakdown["coverage_limitations"]


def test_ignored_low_signal_candidates_do_not_add_confidence_penalty():
    base = calculate_cve_confidence(
        has_cvss=True,
        cvss_score=7.5,
        cvss_version="CVSS v3.1",
        description="A detailed vulnerability in Example Product allows service disruption.",
        age_days=40,
        urlhaus_match_count=0,
        dread_match_count=0,
        keyword_count=8,
        llm_fields_count=0,
        graph_score=0.0,
        nlp_entities={"products": ["example product"], "vuln_types": ["denial_of_service"]},
    )
    ignored = calculate_cve_confidence(
        has_cvss=True,
        cvss_score=7.5,
        cvss_version="CVSS v3.1",
        description="A detailed vulnerability in Example Product allows service disruption.",
        age_days=40,
        urlhaus_match_count=0,
        dread_match_count=0,
        keyword_count=8,
        llm_fields_count=0,
        graph_score=0.0,
        nlp_entities={"products": ["example product"], "vuln_types": ["denial_of_service"]},
        urlhaus_stats={"ignored_low_signal_count": 25},
    )

    assert ignored.confidence == base.confidence
    assert ignored.breakdown["penalties"] == base.breakdown["penalties"]
    assert ignored.breakdown["signals"]["ignored_low_signal_candidate_count"] == 25
    assert "ignored_low_signal_candidates_present" in ignored.breakdown["coverage_limitations"]


def test_rejected_cve_confidence_is_fixed_low_confidence():
    result = calculate_rejected_cve_confidence()

    assert result.confidence == 0.25
    assert result.breakdown["signals"] == {"validity_status": "invalid_or_rejected"}
    assert result.to_dict()["confidence"] == 0.25


def test_urlhaus_strong_ioc_reaches_maximum_confidence_cap():
    result = calculate_urlhaus_confidence(
        threat="malware_download",
        tags=["smartloader", "exe", "zip", "powershell", "ransomware", "loader"],
        status="online",
        date_added="2026-06-01T00:00:00+00:00",
        related_cves=5,
        related_dread=4,
        graph_summary={"structural_strength": 2.0},
        payload_signals={
            "script_payload": True,
            "binary_payload": True,
            "archive_payload": True,
            "living_off_land_delivery": True,
        },
        family_signals=["smartloader", "ransomware", "guloader"],
        age_calculator=lambda _value: 1,
    )

    assert result.confidence == 0.92
    assert result.breakdown["final_confidence"] == 0.92
    assert result.breakdown["payload_confidence"] == 0.14


def test_urlhaus_missing_ioc_metadata_uses_minimum_confidence_floor():
    result = calculate_urlhaus_confidence(
        threat="unknown",
        tags=[],
        status="",
        date_added="",
        related_cves=0,
        related_dread=0,
        graph_summary={},
        payload_signals={
            "script_payload": False,
            "binary_payload": False,
            "archive_payload": False,
            "living_off_land_delivery": False,
        },
        family_signals=[],
    )

    assert result.confidence == 0.25
    assert result.breakdown["penalties"] == -0.13
    assert result.breakdown["signals"]["date_added_present"] is False
