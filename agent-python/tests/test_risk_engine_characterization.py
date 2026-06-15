import analysis.risk_engine as risk_engine_module
from analysis.risk_engine import RiskEngine


def _install_fixed_age_clock(monkeypatch):
    age_by_date = {
        "2026-06-01": 10,
        "2026-02-10": 120,
        "2015-01-01": 4000,
        "2026-06-08": 2,
        "2025-05-06": 400,
    }

    def fixed_age_days(value):
        if value is None:
            return None
        text = str(value)
        for date_prefix, age_days in age_by_date.items():
            if date_prefix in text:
                return age_days
        return None

    monkeypatch.setattr(risk_engine_module, "calculate_age_days", fixed_age_days)


def _cve_payload(cve_id, cvss=None, description="", published="2026-06-01T00:00:00+00:00"):
    payload = {
        "_id": cve_id,
        "published": published,
        "descriptions": [{"lang": "en", "value": description}],
    }
    if cvss is not None:
        payload["metrics"] = {"cvss_metric_v31": [{"cvss_data": {"base_score": cvss}}]}
    return payload


class EmptyCveDB:
    def find_related_urlhaus(self, keywords, limit=25):
        return []

    def find_related_dread(self, keywords, limit=25):
        return []


class StrongCveEvidenceDB(EmptyCveDB):
    def find_related_urlhaus(self, keywords, limit=25):
        return [
            {
                "url": "https://malware.example/CVE-2026-9001/payload.exe",
                "threat": "malware_download",
                "tags": ["ransomware", "exploit", "rce"],
                "url_status": "online",
                "date_added": "2026-06-08T00:00:00+00:00",
            }
        ]

    def find_related_dread(self, keywords, limit=25):
        return [
            {
                "title": "Exploit sale for CVE-2026-9001",
                "content": "Selling RCE exploit and initial access for CVE-2026-9001",
                "category": "market",
                "author": "seller",
                "created_at": "2026-06-08T00:00:00+00:00",
            }
        ]


class LimitedCveEvidenceDB(EmptyCveDB):
    def find_related_dread(self, keywords, limit=25):
        return [
            {
                "title": "VPN access discussion",
                "content": "Initial access and exploit chatter involving Example VPN gateway",
                "category": "forum",
                "author": "analyst",
                "created_at": "2026-02-11T00:00:00+00:00",
            }
        ]


class EmptyIocDB:
    def find_related_cves(self, keywords, limit=25):
        return []

    def find_related_dread(self, keywords, limit=25):
        return []


class CorrelatedIocDB(EmptyIocDB):
    def find_related_cves(self, keywords, limit=25):
        return [{"_id": "CVE-2026-9001"}, {"_id": "CVE-2026-9002"}]

    def find_related_dread(self, keywords, limit=25):
        return [{"title": "loader campaign", "content": "malware loader infrastructure"}]


def test_cve_high_severity_with_strong_external_evidence_is_locked(monkeypatch):
    _install_fixed_age_clock(monkeypatch)

    result = RiskEngine().evaluate_cve(
        _cve_payload(
            "CVE-2026-9001",
            9.8,
            "Remote code execution vulnerability in Example VPN gateway allows unauthenticated "
            "attackers to execute commands, deploy ransomware, and gain initial access.",
        ),
        db=StrongCveEvidenceDB(),
        llm_info={
            "products": ["Example VPN"],
            "versions": ["1.0"],
            "vuln_type": "remote code execution",
            "impact": "initial access",
        },
    )

    assert result["risk_score"] == 8.59
    assert result["confidence"] == 0.95
    assert result["risk_level"] == "CRITICAL"
    assert result["evidence"]["related_urlhaus_count"] == 1
    assert result["evidence"]["related_dread_count"] == 1
    assert result["evidence"]["urlhaus_match_stats"]["accepted_match_count"] == 1
    assert result["evidence"]["dread_match_stats"]["accepted_match_count"] == 1
    assert result["confidence_breakdown"]["signals"]["accepted_external_evidence"] == 2
    assert result["confidence_breakdown"]["signals"]["exact_hits"] == 2
    assert result["feature_breakdown"]["base_cvss_component"] == 7.06
    assert result["feature_breakdown"]["recentness_bonus"] == 0.8
    assert result["feature_breakdown"]["urlhaus_correlation_bonus"] == 1.51
    assert result["feature_breakdown"]["dread_correlation_bonus"] == 0.92
    assert result["feature_breakdown"]["nlp_context_bonus"] == 1.2
    assert result["feature_breakdown"]["llm_context_bonus"] == 0.3
    assert result["feature_breakdown"]["graph_bonus"] == 0.19
    assert result["feature_breakdown"]["risk_score_from_signals"] == 8.59


def test_cve_medium_severity_with_limited_evidence_is_locked(monkeypatch):
    _install_fixed_age_clock(monkeypatch)

    result = RiskEngine().evaluate_cve(
        _cve_payload(
            "CVE-2026-9002",
            6.5,
            "Authentication bypass vulnerability in Example VPN gateway may allow initial access "
            "to administrative functions.",
            published="2026-02-10T00:00:00+00:00",
        ),
        db=LimitedCveEvidenceDB(),
    )

    assert result["risk_score"] == 5.25
    assert result["confidence"] == 0.525
    assert result["risk_level"] == "MEDIUM"
    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["evidence"]["related_dread_count"] == 0
    assert result["evidence"]["dread_match_stats"]["accepted_match_count"] == 0
    assert result["confidence_breakdown"]["signals"]["accepted_external_evidence"] == 0
    assert result["feature_breakdown"]["base_cvss_component"] == 4.68
    assert result["feature_breakdown"]["dread_correlation_bonus"] == 0.0
    assert result["feature_breakdown"]["age_penalty"] == 0.15
    assert result["feature_breakdown"]["raw_age_penalty"] == 0.15
    assert result["feature_breakdown"]["nlp_context_bonus"] == 1.2
    assert result["feature_breakdown"]["graph_bonus"] == 0.0


def test_old_cve_age_penalty_behavior_is_locked(monkeypatch):
    _install_fixed_age_clock(monkeypatch)

    result = RiskEngine().evaluate_cve(
        _cve_payload(
            "CVE-2026-9003",
            8.8,
            "Remote code execution vulnerability in Legacy Router allows attackers to execute arbitrary code.",
            published="2015-01-01T00:00:00+00:00",
        ),
        db=EmptyCveDB(),
    )

    assert result["risk_score"] == 6.44
    assert result["confidence"] == 0.407
    assert result["risk_level"] == "MEDIUM"
    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["evidence"]["related_dread_count"] == 0
    assert result["feature_breakdown"]["base_cvss_component"] == 6.34
    assert result["feature_breakdown"]["age_penalty"] == 1.0
    assert result["feature_breakdown"]["raw_age_penalty"] == 1.0
    assert result["feature_breakdown"]["temporal_score"] == -1.0
    assert result["feature_breakdown"]["nlp_context_bonus"] == 0.87
    assert result["confidence_breakdown"]["penalties"] == -0.195


def test_cve_missing_optional_fields_behavior_is_locked(monkeypatch):
    _install_fixed_age_clock(monkeypatch)

    result = RiskEngine().evaluate_cve(
        {"_id": "CVE-2026-9004", "descriptions": []},
        db=EmptyCveDB(),
    )

    assert result["risk_score"] == 1.5
    assert result["confidence"] == 0.05
    assert result["risk_level"] == "LOW"
    assert result["evidence"]["cvss_score"] == 0.0
    assert result["evidence"]["age_days"] is None
    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["evidence"]["related_dread_count"] == 0
    assert result["feature_breakdown"]["base_cvss_component"] == 1.5
    assert result["feature_breakdown"]["recentness_bonus"] == 0.0
    assert result["feature_breakdown"]["age_penalty"] == 0.0
    assert result["feature_breakdown"]["nlp_context_bonus"] == 0.0
    assert result["confidence_breakdown"]["signals"]["has_cvss"] is False
    assert result["confidence_breakdown"]["penalties"] == -0.365


def test_online_malware_ioc_with_payload_evidence_is_locked(monkeypatch):
    _install_fixed_age_clock(monkeypatch)

    result = RiskEngine().evaluate_urlhaus(
        {
            "urlhaus_id": "UH-9001",
            "url": "http://bad.example/update/payload.exe",
            "threat": "malware_download",
            "tags": ["SmartLoader", "exe", "zip"],
            "url_status": "online",
            "date_added": "2026-06-08T00:00:00+00:00",
        },
        db=CorrelatedIocDB(),
    )

    assert result["risk_score"] == 7.34
    assert result["confidence"] == 0.901
    assert result["risk_level"] == "HIGH"
    assert result["evidence"]["related_cve_count"] == 2
    assert result["evidence"]["related_dread_count"] == 1
    assert result["evidence"]["payload_signals"]["binary_payload"] is True
    assert result["evidence"]["payload_signals"]["archive_payload"] is True
    assert result["evidence"]["malware_family_signals"] == ["smartloader"]
    assert result["feature_breakdown"]["base_feed_component"] == 1.4
    assert result["feature_breakdown"]["threat_type_score"] == 0.9
    assert result["feature_breakdown"]["status_score"] == 1.25
    assert result["feature_breakdown"]["payload_score"] == 1.0
    assert result["feature_breakdown"]["malware_family_score"] == 0.9
    assert result["feature_breakdown"]["freshness_score"] == 0.7
    assert result["feature_breakdown"]["cross_source_score"] == 0.16
    assert result["feature_breakdown"]["graph_bonus"] == 0.33
    assert result["confidence_breakdown"]["cross_source_confidence"] == 0.1


def test_stale_offline_ioc_behavior_is_locked(monkeypatch):
    _install_fixed_age_clock(monkeypatch)

    result = RiskEngine().evaluate_urlhaus(
        {
            "urlhaus_id": "UH-9002",
            "url": "https://old.example/archive/payload.zip",
            "threat": "malware_download",
            "tags": ["zip"],
            "url_status": "offline",
            "date_added": "2025-05-06T00:00:00+00:00",
        },
        db=EmptyIocDB(),
    )

    assert result["risk_score"] == 3.48
    assert result["confidence"] == 0.512
    assert result["risk_level"] == "LOW"
    assert result["evidence"]["related_cve_count"] == 0
    assert result["evidence"]["related_dread_count"] == 0
    assert result["evidence"]["payload_signals"]["archive_payload"] is True
    assert result["feature_breakdown"]["status_score"] == 0.15
    assert result["feature_breakdown"]["payload_score"] == 0.35
    assert result["feature_breakdown"]["delivery_pattern_score"] == 0.35
    assert result["feature_breakdown"]["freshness_score"] == 0.0
    assert result["feature_breakdown"]["graph_bonus"] == 0.33
    assert result["confidence_breakdown"]["penalties"] == -0.04


def test_sparse_ioc_low_confidence_behavior_is_locked(monkeypatch):
    _install_fixed_age_clock(monkeypatch)

    result = RiskEngine().evaluate_urlhaus(
        {
            "urlhaus_id": "UH-9003",
            "url": "https://example.test/landing",
            "threat": "unknown",
            "tags": [],
            "url_status": "",
        },
        db=EmptyIocDB(),
    )

    assert result["risk_score"] == 2.18
    assert result["confidence"] == 0.25
    assert result["risk_level"] == "LOW"
    assert result["evidence"]["related_cve_count"] == 0
    assert result["evidence"]["related_dread_count"] == 0
    assert result["evidence"]["payload_signals"] == {
        "script_payload": False,
        "binary_payload": False,
        "archive_payload": False,
        "living_off_land_delivery": False,
    }
    assert result["feature_breakdown"]["base_feed_component"] == 1.4
    assert result["feature_breakdown"]["threat_type_score"] == 0.45
    assert result["feature_breakdown"]["status_score"] == 0.0
    assert result["feature_breakdown"]["payload_score"] == 0.0
    assert result["feature_breakdown"]["cross_source_score"] == 0.0
    assert result["feature_breakdown"]["graph_bonus"] == 0.33
    assert result["confidence_breakdown"]["penalties"] == -0.13
