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
