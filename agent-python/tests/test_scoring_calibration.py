from analysis.risk_engine import RiskEngine


def _cve(cvss: float, description: str, published: str = "2025-01-01T00:00:00+00:00"):
    return {
        "_id": "CVE-2026-9999",
        "published": published,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": cvss}}]},
    }


class EmptyDB:
    def find_related_urlhaus(self, keywords, limit=25):
        return []

    def find_related_dread(self, keywords, limit=25):
        return []


class ExactEvidenceDB(EmptyDB):
    def find_related_urlhaus(self, keywords, limit=25):
        return [
            {
                "url": "https://evil.example/CVE-2026-9999/payload.exe",
                "threat": "malware_download",
                "tags": ["ransomware", "exploit", "rce"],
                "url_status": "online",
                "date_added": "2026-05-02T00:00:00+00:00",
            }
        ]


class IgnoredUrlhausDB(EmptyDB):
    def find_related_urlhaus(self, keywords, limit=25):
        return [
            {
                "url": "https://cdn.example.invalid/download/file.bin",
                "threat": "malware_download",
                "tags": ["ascii", "opendir"],
                "url_status": "offline",
                "date_added": "",
            }
        ]


def test_high_cvss_without_external_evidence_is_not_low():
    result = RiskEngine().evaluate_cve(
        _cve(9.8, "Unspecified vulnerability in Example Product."),
        db=EmptyDB(),
    )

    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert result["risk_score"] >= 6.5
    assert result["confidence"] < 0.75
    assert result["feature_breakdown"]["active_threat_score"] == 0
    assert result["feature_breakdown"]["severity_signal"] > 0.9
    assert result["feature_breakdown"]["epss_available"] is False
    assert result["feature_breakdown"]["kev_status_known"] is False


def test_old_high_cvss_without_external_evidence_is_still_prioritized():
    result = RiskEngine().evaluate_cve(
        _cve(
            9.8,
            "Remote code execution vulnerability in Example VPN appliance may allow takeover.",
            published="2018-01-01T00:00:00+00:00",
        ),
        db=EmptyDB(),
    )

    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert result["risk_score"] >= 6.5
    assert result["feature_breakdown"]["age_penalty"] <= 1.0


def test_high_cvss_with_accepted_external_evidence_has_high_confidence():
    result = RiskEngine().evaluate_cve(
        _cve(9.8, "Unspecified vulnerability in Example Product."),
        db=ExactEvidenceDB(),
    )

    assert result["risk_level"] in {"HIGH", "CRITICAL"}
    assert result["confidence"] >= 0.8
    assert result["evidence"]["related_urlhaus_count"] == 1
    assert result["feature_breakdown"]["active_threat_score"] > 0
    assert result["feature_breakdown"]["age_penalty"] < result["feature_breakdown"]["raw_age_penalty"]


def test_low_cvss_without_evidence_stays_low():
    result = RiskEngine().evaluate_cve(
        _cve(3.0, "Information disclosure in a local utility."),
        db=EmptyDB(),
    )

    assert result["risk_level"] == "LOW"
    assert result["risk_score"] < 4.0


def test_invalid_cve_record_has_low_risk_confidence():
    result = RiskEngine().evaluate_cve(
        {
            "_id": "CVE-2026-REJECTED",
            "published": "2026-01-01T00:00:00+00:00",
            "descriptions": [{"lang": "en", "value": "Rejected reason: this candidate was issued in error."}],
            "metrics": {},
        },
        db=EmptyDB(),
    )

    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "LOW"
    assert result["confidence"] <= 0.35
    assert result["evidence"]["validity_status"] == "invalid_or_rejected"


def test_zero_cvss_without_external_evidence_has_low_confidence():
    result = RiskEngine().evaluate_cve(
        _cve(0.0, "Unspecified vulnerability in a legacy component."),
        db=EmptyDB(),
    )

    assert result["evidence"]["cvss_score"] == 0.0
    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["confidence"] <= 0.42


def test_medium_cvss_with_kev_and_high_epss_can_rank_above_high_cvss_without_external_signals():
    high_no_external = RiskEngine().evaluate_cve(
        _cve(9.8, "Unspecified vulnerability in Example Product."),
        db=EmptyDB(),
    )
    medium_with_external = RiskEngine().evaluate_cve(
        _cve(6.5, "Authentication bypass in Example VPN Gateway allows initial access."),
        db=EmptyDB(),
        external_signals={"epss_probability": 0.94, "kev_listed": True},
    )

    assert medium_with_external["risk_score"] > high_no_external["risk_score"]
    assert medium_with_external["feature_breakdown"]["epss_signal"] == 0.94
    assert medium_with_external["feature_breakdown"]["kev_signal"] == 1.0


def test_missing_epss_and_kev_do_not_crash_or_zero_risk():
    result = RiskEngine().evaluate_cve(
        _cve(9.0, "Remote code execution vulnerability in Example Product."),
        db=EmptyDB(),
        external_signals={},
    )

    assert result["risk_score"] > 0
    assert result["feature_breakdown"]["epss_signal"] == 0.0
    assert result["feature_breakdown"]["kev_signal"] == 0.0
    assert 0.0 <= result["risk_score"] <= 10.0


def test_cve_analysis_uses_nested_enrichment_fields():
    payload = _cve(6.5, "Authentication bypass in Example VPN Gateway allows initial access.")
    payload["enrichment"] = {
        "epss": {"available": True, "probability": 0.94, "percentile": 0.99, "date": "2026-06-18", "source": "FIRST"},
        "kev": {"status_known": True, "listed": True, "source": "CISA", "date_checked": "2026-06-18"},
    }

    result = RiskEngine().evaluate_cve(payload, db=EmptyDB())

    assert result["evidence"]["epss_probability"] == 0.94
    assert result["evidence"]["epss_available"] is True
    assert result["evidence"]["kev_status_known"] is True
    assert result["evidence"]["kev_listed"] is True
    assert result["feature_breakdown"]["epss_signal"] == 0.94
    assert result["feature_breakdown"]["kev_signal"] == 1.0


def test_loaded_kev_catalog_absent_cve_sets_known_not_listed_in_analysis():
    payload = _cve(7.5, "A detailed vulnerability in Example Product allows service disruption.")
    payload["enrichment"] = {
        "epss": {"available": False, "source": "FIRST"},
        "kev": {"status_known": True, "listed": False, "source": "CISA", "date_checked": "2026-06-18"},
    }

    result = RiskEngine().evaluate_cve(payload, db=EmptyDB())

    assert result["evidence"]["epss_available"] is False
    assert result["evidence"]["kev_status_known"] is True
    assert result["evidence"]["kev_listed"] is False
    assert result["feature_breakdown"]["epss_signal"] == 0.0
    assert result["feature_breakdown"]["kev_signal"] == 0.0
    assert "kev_status_unknown" not in result["confidence_breakdown"]["coverage_limitations"]


def test_low_epss_enrichment_does_not_force_critical():
    payload = _cve(7.5, "A detailed vulnerability in Example Product allows service disruption.")
    payload["enrichment"] = {
        "epss": {"available": True, "probability": 0.01, "percentile": 0.20, "source": "FIRST"},
        "kev": {"status_known": True, "listed": False, "source": "CISA", "date_checked": "2026-06-18"},
    }

    result = RiskEngine().evaluate_cve(payload, db=EmptyDB())

    assert result["feature_breakdown"]["epss_signal"] == 0.01
    assert result["risk_level"] != "CRITICAL"
    assert result["risk_score"] < 8.5


def test_high_epss_enrichment_increases_epss_signal_and_risk():
    base = _cve(7.5, "A detailed vulnerability in Example Product allows service disruption.")
    enriched = _cve(7.5, "A detailed vulnerability in Example Product allows service disruption.")
    enriched["enrichment"] = {
        "epss": {"available": True, "probability": 0.90, "percentile": 0.98, "source": "FIRST"},
        "kev": {"status_known": True, "listed": False, "source": "CISA", "date_checked": "2026-06-18"},
    }

    baseline = RiskEngine().evaluate_cve(base, db=EmptyDB())
    with_epss = RiskEngine().evaluate_cve(enriched, db=EmptyDB())

    assert baseline["feature_breakdown"]["epss_signal"] == 0.0
    assert with_epss["feature_breakdown"]["epss_signal"] == 0.9
    assert with_epss["risk_score"] > baseline["risk_score"]


def test_kev_listed_enrichment_increases_kev_signal_and_risk():
    base = _cve(7.5, "A detailed vulnerability in Example Product allows service disruption.")
    enriched = _cve(7.5, "A detailed vulnerability in Example Product allows service disruption.")
    enriched["enrichment"] = {
        "epss": {"available": False, "source": "FIRST"},
        "kev": {"status_known": True, "listed": True, "source": "CISA", "date_checked": "2026-06-18"},
    }

    baseline = RiskEngine().evaluate_cve(base, db=EmptyDB())
    with_kev = RiskEngine().evaluate_cve(enriched, db=EmptyDB())

    assert baseline["feature_breakdown"]["kev_signal"] == 0.0
    assert with_kev["feature_breakdown"]["kev_signal"] == 1.0
    assert with_kev["risk_score"] > baseline["risk_score"]


def test_intrinsic_criticality_floor_lifts_recent_cvss10_high_context_without_external_evidence():
    result = RiskEngine().evaluate_cve(
        _cve(
            10.0,
            (
                "Remote code execution vulnerability in Example VPN Gateway allows "
                "unauthenticated attackers to execute arbitrary commands and take over "
                "exposed appliances. Exploit terminology is present in the CVE context."
            ),
            published="2026-06-10T00:00:00+00:00",
        ),
        db=EmptyDB(),
        external_signals={},
    )

    assert result["risk_score"] >= 8.0
    assert result["risk_score"] <= 8.2
    assert result["feature_breakdown"]["score_before_intrinsic_floor"] < result["risk_score"]
    assert result["feature_breakdown"]["intrinsic_criticality_floor_applied"] is True
    assert result["feature_breakdown"]["intrinsic_criticality_floor_value"] == 8.1
    assert result["feature_breakdown"]["correlation_signal"] == 0.0
    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["evidence"]["related_dread_count"] == 0
    assert result["confidence"] < 0.8
    assert result["confidence_breakdown"]["signals"]["confidence_cap_reason"] == "coverage_limited_without_external_support"
    assert "no_accepted_external_evidence" in result["confidence_breakdown"]["coverage_limitations"]


def test_intrinsic_criticality_floor_does_not_apply_to_medium_cvss():
    result = RiskEngine().evaluate_cve(
        _cve(
            6.5,
            (
                "Remote code execution vulnerability in Example VPN Gateway allows "
                "attackers to execute arbitrary commands on exposed appliances."
            ),
            published="2026-06-10T00:00:00+00:00",
        ),
        db=EmptyDB(),
    )

    assert result["feature_breakdown"]["intrinsic_criticality_floor_applied"] is False
    assert result["risk_score"] == result["feature_breakdown"]["score_before_intrinsic_floor"]


def test_ignored_urlhaus_candidates_do_not_influence_intrinsic_floor():
    payload = _cve(
        10.0,
        (
            "Remote code execution vulnerability in Example VPN Gateway allows "
            "unauthenticated attackers to execute arbitrary commands and take over "
            "exposed appliances. Exploit terminology is present in the CVE context."
        ),
        published="2026-06-10T00:00:00+00:00",
    )

    baseline = RiskEngine().evaluate_cve(payload, db=EmptyDB())
    with_ignored = RiskEngine().evaluate_cve(payload, db=IgnoredUrlhausDB())

    assert with_ignored["risk_score"] == baseline["risk_score"]
    assert with_ignored["confidence"] == baseline["confidence"]
    assert with_ignored["feature_breakdown"]["intrinsic_criticality_floor_applied"] is True
    assert with_ignored["feature_breakdown"]["correlation_signal"] == 0.0
    assert with_ignored["evidence"]["urlhaus_match_stats"]["ignored_low_signal_count"] == 1
