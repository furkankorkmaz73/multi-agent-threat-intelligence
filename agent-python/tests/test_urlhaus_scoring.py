from analysis.risk_engine import RiskEngine


class EmptyDB:
    def find_related_cves(self, keywords, limit=10):
        return []

    def find_related_dread(self, keywords, limit=10):
        return []


class CorrelatedDB(EmptyDB):
    def find_related_cves(self, keywords, limit=10):
        return [{"_id": "CVE-2026-1111"}, {"_id": "CVE-2026-2222"}]

    def find_related_dread(self, keywords, limit=10):
        return [{"title": "loader campaign", "content": "malware infrastructure"}]


def test_online_loader_ioc_is_medium_or_higher_with_breakdown():
    engine = RiskEngine()
    result = engine.evaluate_urlhaus(
        {
            "url": "http://bad.example/update/payload.exe",
            "threat": "malware_download",
            "tags": ["SmartLoader", "zip"],
            "url_status": "online",
            "date_added": "2026-04-21T10:00:00+00:00",
        },
        db=EmptyDB(),
    )

    assert result["risk_score"] >= 4.0
    assert result["risk_level"] in {"MEDIUM", "HIGH", "CRITICAL"}
    assert result["confidence_breakdown"]["feed_confidence"] > 0
    assert result["confidence_breakdown"]["payload_confidence"] > 0
    assert result["confidence_breakdown"]["family_confidence"] > 0
    assert result["evidence"]["payload_signals"]["binary_payload"] is True


def test_offline_generic_ioc_stays_low_or_lower_medium():
    engine = RiskEngine()
    result = engine.evaluate_urlhaus(
        {
            "url": "https://example.test/neutral/path.index",
            "threat": "malware_download",
            "tags": [],
            "url_status": "offline",
            "date_added": "",
        },
        db=EmptyDB(),
    )

    assert result["risk_score"] < 4.0
    assert result["risk_level"] == "LOW"
    assert result["confidence"] < 0.6
    assert result["confidence_breakdown"]["penalties"] < 0


def test_botnet_script_ioc_receives_payload_and_family_signals():
    engine = RiskEngine()
    result = engine.evaluate_urlhaus(
        {
            "url": "http://1.2.3.4/bin.sh",
            "threat": "malware_download",
            "tags": ["elf", "mirai", "ua-wget"],
            "url_status": "offline",
        },
        db=EmptyDB(),
    )

    breakdown = result["feature_breakdown"]
    assert breakdown["payload_score"] > 0
    assert breakdown["malware_family_score"] > 0
    assert breakdown["delivery_pattern_score"] > 0
    assert result["confidence_breakdown"]["family_confidence"] > 0


def test_cross_source_support_is_conservative_but_visible():
    engine = RiskEngine()
    result = engine.evaluate_urlhaus(
        {
            "url": "http://bad.example/payload.exe",
            "threat": "malware_download",
            "tags": ["GuLoader", "exe"],
            "url_status": "online",
            "date_added": "2026-04-21T10:00:00+00:00",
        },
        db=CorrelatedDB(),
    )

    assert 0 < result["feature_breakdown"]["cross_source_score"] <= 0.5
    assert result["confidence_breakdown"]["cross_source_confidence"] > 0
    assert result["evidence"]["related_cve_count"] == 2
    assert result["evidence"]["related_dread_count"] == 1
