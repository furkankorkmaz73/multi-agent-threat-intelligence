from analysis.correlation_decisions import CorrelationDecisionStatus
from analysis.correlator import build_correlation_decision_rows, build_correlation_decisions, score_dread_matches, score_urlhaus_matches
from analysis.evidence_models import Evidence, EvidenceSource, EvidenceType, Provenance
from config import DreadConfig


def test_exact_cve_reference_is_accepted_with_provenance_serialization():
    decisions = build_correlation_decisions(
        [
            {
                "url": "https://malware.example/CVE-2026-4242/payload.exe",
                "threat": "malware_download",
                "tags": ["ransomware"],
                "url_status": "online",
                "date_added": "2026-05-02T00:00:00+00:00",
            }
        ],
        base_keywords=["cve-2026-4242", "remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )

    decision = decisions[0]
    serialized = decision.to_dict()
    assert decision.status is CorrelationDecisionStatus.ACCEPTED
    assert decision.primary_reason == "exact_cve"
    assert decision.evidence_gate_passed is True
    assert decision.evidence_gate_reason == "exact_cve"
    assert decision.accepted_evidence_count == 1
    assert decision.rejected_evidence_count == 0
    assert serialized["status"] == "accepted"
    assert serialized["source_identifier"] == "CVE-2026-4242"
    assert serialized["target_identifier"] == "https://malware.example/CVE-2026-4242/payload.exe"
    assert "urlhaus" in serialized["provenance_summary"]["sources"]
    assert any(item["evidence_type"] == "cve_reference" for item in serialized["evidence_references"])


def test_dread_high_signal_overlap_routes_to_manual_review_without_exact_cve():
    matches = [
        {
            "title": "RCE exploit sale",
            "content": "Selling exploit and ransomware loader access for exposed VPN appliances.",
            "category": "market",
            "created_at": "2026-05-02T00:00:00+00:00",
        }
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["remote code execution", "exploit", "ransomware", "vpn"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="dread",
    )

    assert decisions[0].status is CorrelationDecisionStatus.MANUAL_REVIEW
    assert decisions[0].primary_reason == "ambiguous_support"
    assert decisions[0].final_confidence <= 0.35
    assert decisions[0].evidence_gate_passed is False
    assert decisions[0].manual_review_evidence_count == 1
    assert decisions[0].accepted_evidence_count == 0
    assert decisions[0].dread_only_evidence is True
    assert decisions[0].confidence_cap_reason == "dread_manual_review_cap"


def test_dread_exact_cve_can_be_accepted_but_confidence_is_capped():
    decisions = build_correlation_decisions(
        [
            {
                "title": "CVE-2026-4242 exploit sale",
                "content": "Selling exploit for CVE-2026-4242 with rce loader access.",
                "category": "market",
                "created_at": "2026-05-02T00:00:00+00:00",
            }
        ],
        base_keywords=["cve-2026-4242", "remote code execution", "exploit"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="dread",
    )

    decision = decisions[0]
    assert decision.status is CorrelationDecisionStatus.ACCEPTED
    assert decision.primary_reason == "exact_cve"
    assert decision.final_confidence <= 0.62
    assert decision.evidence_reliability < 0.7
    assert decision.corroborated_dread_evidence is True
    assert decision.confidence_cap_reason == "dread_source_reliability_cap"


def test_weak_dread_candidate_does_not_increase_score_or_confidence():
    matches = [
        {
            "title": "Admin discussion",
            "content": "Generic access discussion without CVE, exploit, malware, or product-specific detail.",
            "category": "forum",
            "created_at": "2026-05-02T00:00:00+00:00",
        }
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["cve-2026-4242", "example vpn remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="dread",
    )
    score, explanations, _, stats = score_dread_matches(
        matches,
        base_keywords=["cve-2026-4242", "example vpn remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
    )

    assert decisions[0].status is CorrelationDecisionStatus.REJECTED
    assert decisions[0].final_confidence <= 0.15
    assert decisions[0].evidence_gate_passed is False
    assert decisions[0].rejection_reason == "weak_support"
    assert decisions[0].false_positive_control is True
    assert score == 0.0
    assert explanations == []
    assert stats["accepted_match_count"] == 0
    assert stats["dread_evidence_present"] is True


def test_generic_keyword_only_urlhaus_candidate_is_rejected():
    decisions = build_correlation_decisions(
        [
            {
                "url": "https://ip-address-check-mo.vercel.app/api/settings/windows",
                "threat": "malware_download",
                "tags": ["ContagiousInterview", "DPRK", "Lazarus"],
                "url_status": "offline",
                "date_added": "",
            }
        ],
        base_keywords=["cve-2005-0051", "microsoft windows", "remote code execution", "windows"],
        entity_time="2005-05-02T04:00:00+00:00",
        source="urlhaus",
    )

    assert decisions[0].status is CorrelationDecisionStatus.REJECTED
    assert decisions[0].primary_reason == "weak_support"
    assert decisions[0].evidence_gate_passed is False
    assert decisions[0].accepted_evidence_count == 0


def test_keyword_only_urlhaus_high_signal_candidate_is_rejected():
    matches = [
        {
            "url": "https://noise.example/exploit-rce-loader",
            "threat": "malware_download",
            "tags": ["exploit", "rce", "loader"],
            "url_status": "offline",
            "date_added": "2026-05-02T00:00:00+00:00",
        }
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["cve-2026-4242", "remote code execution", "exploit", "rce"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )
    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["cve-2026-4242", "remote code execution", "exploit", "rce"],
        entity_time="2026-05-01T00:00:00+00:00",
    )

    assert decisions[0].status is CorrelationDecisionStatus.REJECTED
    assert decisions[0].evidence_gate_passed is False
    assert decisions[0].false_positive_control is True
    assert score == 0.0
    assert explanations == []
    assert stats["accepted_match_count"] == 0
    assert stats["accepted_evidence_count"] == 0


def test_stale_urlhaus_high_signal_candidate_is_rejected_without_temporal_support():
    matches = [
        {
            "url": "https://old.example/vpn-rce-loader",
            "threat": "malware_download",
            "tags": ["exploit", "rce", "vpn", "loader"],
            "url_status": "offline",
            "date_added": "2018-01-01T00:00:00+00:00",
        }
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["cve-2026-4242", "example vpn", "rce", "exploit", "loader"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )
    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["cve-2026-4242", "example vpn", "rce", "exploit", "loader"],
        entity_time="2026-05-01T00:00:00+00:00",
    )

    assert decisions[0].status is not CorrelationDecisionStatus.ACCEPTED
    assert decisions[0].final_confidence <= 0.45
    assert score == 0.0
    assert explanations == []
    assert stats["accepted_evidence_count"] == 0


def test_unrelated_product_overlap_urlhaus_candidate_is_rejected():
    matches = [
        {
            "url": "https://updates.example/example-vpn-admin-theme",
            "threat": "malware_download",
            "tags": ["example", "vpn", "admin"],
            "url_status": "offline",
            "date_added": "2026-05-02T00:00:00+00:00",
        }
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["cve-2026-4242", "example vpn gateway authentication bypass"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )

    assert decisions[0].status is CorrelationDecisionStatus.REJECTED
    assert decisions[0].rejected_evidence_count == 1
    assert decisions[0].accepted_evidence_count == 0
    assert decisions[0].false_positive_control is True


def test_generic_keyword_only_dread_candidate_is_not_accepted():
    decisions = build_correlation_decisions(
        [
            {
                "title": "Windows server thread",
                "content": "Discussion mentions windows server administration and access but no CVE or exploit details.",
                "category": "forum",
                "created_at": "2026-05-02T00:00:00+00:00",
            }
        ],
        base_keywords=["cve-2026-4242", "microsoft windows server", "remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="dread",
    )

    assert decisions[0].status in {CorrelationDecisionStatus.REJECTED, CorrelationDecisionStatus.MANUAL_REVIEW}


def test_weak_entity_alignment_routes_to_manual_review_without_accepted_counts():
    matches = [
        {
            "url": "https://weak.example/vpn/loader",
            "threat": "malware_download",
            "tags": ["loader"],
            "url_status": "offline",
            "date_added": "2026-05-02T00:00:00+00:00",
        }
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["example vpn gateway", "initial access"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )
    score, explanations, stats = score_urlhaus_matches(
        matches,
        base_keywords=["example vpn gateway", "initial access"],
        entity_time="2026-05-01T00:00:00+00:00",
    )

    assert decisions[0].status in {CorrelationDecisionStatus.REJECTED, CorrelationDecisionStatus.MANUAL_REVIEW}
    assert score == 0.0
    assert explanations == []
    assert stats["accepted_match_count"] == 0
    assert stats["rejected_match_count"] == 1
    assert stats["accepted_evidence_count"] == 0
    assert stats["manual_review_evidence_count"] in {0, 1}


def test_conflicting_evidence_does_not_count_as_accepted():
    matches = [
        {
            "url": "https://old.example/unrelated/payload.exe",
            "threat": "malware_download",
            "tags": ["exe"],
            "url_status": "offline",
            "date_added": "2010-01-01T00:00:00+00:00",
        }
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["example vpn remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )
    _, _, stats = score_urlhaus_matches(
        matches,
        base_keywords=["example vpn remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
    )

    assert decisions[0].status in {CorrelationDecisionStatus.REJECTED, CorrelationDecisionStatus.MANUAL_REVIEW}
    assert stats["accepted_match_count"] == 0


def test_evidence_confidence_is_bounded_and_serialized():
    evidence = Evidence(
        source=EvidenceSource.URLHAUS,
        evidence_type=EvidenceType.IOC,
        subject_identifier="CVE-2026-1",
        related_object_identifier="https://example.test/payload.exe",
        observed_at="2026-05-01T00:00:00+00:00",
        confidence=2.5,
        provenance=Provenance(source=EvidenceSource.URLHAUS, method="unit-test", metadata={"feed": "urlhaus"}),
        reason="bounded",
        raw_reference="https://example.test/payload.exe",
    )

    serialized = evidence.to_dict()
    assert evidence.confidence == 1.0
    assert serialized["confidence"] == 1.0
    assert serialized["provenance"]["metadata"] == {"feed": "urlhaus"}


def test_decision_order_is_deterministic():
    matches = [
        {"url": "https://b.example/CVE-2026-2222/payload.exe", "threat": "malware_download", "tags": [], "date_added": ""},
        {"url": "https://a.example/CVE-2026-1111/payload.exe", "threat": "malware_download", "tags": [], "date_added": ""},
    ]

    decisions = build_correlation_decisions(
        matches,
        base_keywords=["cve-2026-2222", "cve-2026-1111"],
        source="urlhaus",
    )

    assert [decision.target_identifier for decision in decisions] == [
        "https://b.example/CVE-2026-2222/payload.exe",
        "https://a.example/CVE-2026-1111/payload.exe",
    ]


def test_correlation_decision_rows_include_component_scores():
    rows = build_correlation_decision_rows(
        [
            {
                "url": "https://malware.example/CVE-2026-4242/payload.exe",
                "threat": "malware_download",
                "tags": ["ransomware"],
                "url_status": "online",
                "date_added": "2026-05-02T00:00:00+00:00",
            }
        ],
        base_keywords=["cve-2026-4242", "remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )

    row = rows[0]
    assert row["decision"] == "accepted"
    assert row["primary_reason"] == "exact_cve"
    assert {"source_identifier", "target_identifier", "lexical_score", "semantic_score", "final_confidence"} <= set(row)
    assert {"evidence_source", "evidence_reliability", "confidence_cap_reason"} <= set(row)
    assert {"evidence_gate_passed", "evidence_gate_reason", "accepted_evidence_count", "false_positive_control"} <= set(row)


def test_dread_is_default_off_when_environment_is_unset(monkeypatch):
    monkeypatch.delenv("DREAD_ENABLED", raising=False)
    monkeypatch.delenv("DREAD_ONION_URL", raising=False)

    cfg = DreadConfig()

    assert cfg.enabled is False
    assert cfg.onion_url is None
