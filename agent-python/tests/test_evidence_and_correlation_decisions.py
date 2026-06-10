from analysis.correlation_decisions import CorrelationDecisionStatus
from analysis.correlator import build_correlation_decisions, score_urlhaus_matches
from analysis.evidence_models import Evidence, EvidenceSource, EvidenceType, Provenance


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
    assert serialized["status"] == "accepted"
    assert serialized["source_identifier"] == "CVE-2026-4242"
    assert serialized["target_identifier"] == "https://malware.example/CVE-2026-4242/payload.exe"
    assert "urlhaus" in serialized["provenance_summary"]["sources"]
    assert any(item["evidence_type"] == "cve_reference" for item in serialized["evidence_references"])


def test_high_signal_overlap_is_accepted_without_changing_public_stats():
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

    assert decisions[0].status is CorrelationDecisionStatus.ACCEPTED
    assert decisions[0].primary_reason in {"entity_alignment", "high_signal_terms", "lexical_overlap"}


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
