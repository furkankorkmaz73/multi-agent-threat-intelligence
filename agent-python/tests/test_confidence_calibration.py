from analysis.risk_engine import RiskEngine


class EmptyDB:
    def find_related_urlhaus(self, keywords, limit=25):
        return []

    def find_related_dread(self, keywords, limit=25):
        return []


class ExactEvidenceDB(EmptyDB):
    def find_related_urlhaus(self, keywords, limit=25):
        return [
            {
                "url": "https://malware.example/CVE-2026-4242/payload.exe",
                "threat": "malware_download",
                "tags": ["ransomware", "exploit", "rce"],
                "url_status": "online",
                "date_added": "2026-05-02T00:00:00+00:00",
            }
        ]


def _cve(cvss: float, description: str, published: str = "2026-01-01T00:00:00+00:00"):
    return {
        "_id": "CVE-2026-4242",
        "published": published,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": cvss}}]},
    }


def test_confidence_breakdown_is_returned_for_cve_analysis():
    result = RiskEngine().evaluate_cve(
        _cve(9.8, "Remote code execution in Example VPN appliance allows takeover."),
        db=EmptyDB(),
    )

    breakdown = result["confidence_breakdown"]
    assert breakdown["final_confidence"] == result["confidence"]
    assert breakdown["metadata_confidence"] > 0
    assert breakdown["entity_confidence"] > 0
    assert breakdown["external_evidence_confidence"] == 0
    assert breakdown["signals"]["has_cvss"] is True


def test_richer_entity_context_has_higher_confidence_than_weak_text():
    weak = RiskEngine().evaluate_cve(
        _cve(9.8, "Unspecified vulnerability."),
        db=EmptyDB(),
    )
    rich = RiskEngine().evaluate_cve(
        _cve(
            9.8,
            "Remote code execution vulnerability in Example VPN gateway allows unauthenticated attackers "
            "to execute commands, steal credentials, and gain initial access to the appliance.",
        ),
        db=EmptyDB(),
    )

    assert rich["confidence"] > weak["confidence"]
    assert rich["confidence_breakdown"]["entity_confidence"] > weak["confidence_breakdown"]["entity_confidence"]


def test_exact_external_evidence_raises_external_confidence_component():
    result = RiskEngine().evaluate_cve(
        _cve(9.8, "Remote code execution vulnerability in Example Product."),
        db=ExactEvidenceDB(),
    )

    assert result["confidence"] >= 0.8
    assert result["confidence_breakdown"]["external_evidence_confidence"] > 0
    assert result["confidence_breakdown"]["signals"]["accepted_external_evidence"] == 1
    assert result["evidence"]["related_urlhaus_count"] == 1


def test_missing_cvss_without_external_evidence_has_low_confidence_breakdown():
    result = RiskEngine().evaluate_cve(
        _cve(0.0, "Unspecified vulnerability in a legacy component."),
        db=EmptyDB(),
    )

    assert result["confidence"] <= 0.35
    assert result["confidence_breakdown"]["signals"]["has_cvss"] is False
    assert result["confidence_breakdown"]["external_evidence_confidence"] == 0
    assert result["confidence_breakdown"]["penalties"] < 0


class GenericEntityAlignmentDB(EmptyDB):
    def find_related_urlhaus(self, keywords, limit=25):
        return [
            {
                "url": "https://ip-address-check-mo.vercel.app/api/settings/windows",
                "threat": "malware_download",
                "tags": ["ContagiousInterview", "DPRK", "Lazarus"],
                "url_status": "offline",
                "date_added": "",
            }
        ]


def test_generic_urlhaus_entity_alignment_does_not_raise_confidence():
    result = RiskEngine().evaluate_cve(
        _cve(
            7.5,
            "Remote code execution vulnerability in Microsoft Windows allows attackers to execute code.",
            published="2005-05-02T04:00:00+00:00",
        ),
        db=GenericEntityAlignmentDB(),
    )

    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["confidence_breakdown"]["external_evidence_confidence"] == 0
    assert result["confidence_breakdown"]["signals"]["accepted_external_evidence"] == 0
    assert result["confidence"] < 0.7


class WeakDreadOnlyDB(EmptyDB):
    def find_related_dread(self, keywords, limit=25):
        return [
            {
                "title": "VPN admin chatter",
                "content": "Generic VPN admin portal discussion without exact CVE or exploit proof.",
                "category": "forum",
                "created_at": "2026-01-02T00:00:00+00:00",
            }
        ]


def test_dread_only_weak_evidence_does_not_produce_high_confidence():
    result = RiskEngine().evaluate_cve(
        _cve(7.5, "Authentication bypass in Example VPN Gateway may allow initial access."),
        db=WeakDreadOnlyDB(),
    )

    assert result["evidence"]["related_urlhaus_count"] == 0
    assert result["confidence"] < 0.7
    assert result["confidence_breakdown"]["signals"]["dread_only"] in {False, True}
