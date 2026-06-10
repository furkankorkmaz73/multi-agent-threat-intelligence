from analysis.applicability import ApplicabilityStatus, VulnerableProduct, resolve_product_applicability
from analysis.assets import Asset, AssetCriticality, CompensatingControl, InstalledProduct, NetworkExposure, PatchState
from analysis.operational_risk import OperationalRiskService


def _analysis(score=8.0, confidence=0.9):
    return {"entity_id": "CVE-2026-9001", "risk_score": score, "confidence": confidence}


def _asset(
    *,
    product=None,
    criticality=AssetCriticality.MEDIUM,
    exposure=NetworkExposure.INTERNAL,
    patch_state=PatchState.UNKNOWN,
    controls=(),
):
    return Asset(
        asset_id="asset-1",
        name="vpn-01",
        environment="prod",
        owner_team="platform",
        criticality=criticality,
        exposure=exposure,
        installed_products=(product or InstalledProduct(name="Example VPN Gateway", vendor="Example Corp", version="4.2"),),
        patch_state=patch_state,
        compensating_controls=tuple(controls),
        tags=("edge",),
    )


def test_exact_cpe_like_match_is_applicable():
    asset = _asset(
        product=InstalledProduct(
            name="Example VPN Gateway",
            vendor="Example Corp",
            version="4.2",
            identifiers=("cpe:2.3:a:example:vpn_gateway:4.2:*:*:*:*:*:*:*",),
        )
    )
    vulnerable = VulnerableProduct(
        name="Example VPN Gateway",
        vendor="Example Corp",
        versions=("4.2",),
        identifiers=("cpe:2.3:a:example:vpn_gateway:4.2:*:*:*:*:*:*:*",),
        evidence_references=({"source": "cve", "field": "configurations"},),
    )

    result = resolve_product_applicability(asset, (vulnerable,))

    assert result.status == ApplicabilityStatus.APPLICABLE
    assert result.confidence == 0.97
    assert result.matched_product_identifiers == ("cpe:2.3:a:example:vpn_gateway:4.2:*:*:*:*:*:*:*",)
    assert result.to_dict()["evidence_references"] == [{"source": "cve", "field": "configurations"}]


def test_vendor_product_normalized_match_is_applicable():
    asset = _asset(product=InstalledProduct(name="Example VPN Gateway", vendor="Example Corp", version="4.2"))
    vulnerable = VulnerableProduct(name="example vpn gateway", vendor="example corp", versions=("4.2",))

    result = resolve_product_applicability(asset, (vulnerable,))

    assert result.status == ApplicabilityStatus.APPLICABLE
    assert result.confidence == 0.82
    assert result.reasons == ("vendor_product_match", "version_match")


def test_generic_substring_overlap_is_rejected():
    asset = _asset(product=InstalledProduct(name="Server Backup Pro", vendor="Example Corp", version="1.0"))
    vulnerable = VulnerableProduct(name="server", vendor="Different Vendor", versions=("1.0",))

    result = resolve_product_applicability(asset, (vulnerable,))

    assert result.status == ApplicabilityStatus.NOT_APPLICABLE
    assert result.reasons == ("generic_or_substring_overlap_rejected",)


def test_missing_asset_version_is_uncertain():
    asset = _asset(product=InstalledProduct(name="Example VPN Gateway", vendor="Example Corp"))
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = resolve_product_applicability(asset, (vulnerable,))

    assert result.status == ApplicabilityStatus.UNCERTAIN
    assert result.confidence == 0.58
    assert "asset_version_missing" in result.reasons


def test_explicitly_patched_asset_reduces_operational_risk():
    asset = _asset(patch_state=PatchState.PATCHED)
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = OperationalRiskService().assess(_analysis(score=7.0), (vulnerable,), asset)

    assert result.final_operational_risk_score == 5.0
    assert result.component_breakdown["patch_state_contribution"] == -2.0
    assert result.final_risk_level == "MEDIUM"


def test_exposed_critical_asset_increases_operational_risk():
    asset = _asset(criticality=AssetCriticality.CRITICAL, exposure=NetworkExposure.INTERNET, patch_state=PatchState.UNPATCHED)
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = OperationalRiskService().assess(_analysis(score=6.2), (vulnerable,), asset)

    assert result.final_operational_risk_score == 9.8
    assert result.final_risk_level == "CRITICAL"
    assert result.criticality_contribution == 1.4
    assert result.exposure_contribution == 1.2


def test_low_criticality_internal_asset_keeps_operational_risk_lower():
    asset = _asset(criticality=AssetCriticality.LOW, exposure=NetworkExposure.INTERNAL, patch_state=PatchState.PATCHED)
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = OperationalRiskService().assess(_analysis(score=5.0), (vulnerable,), asset)

    assert result.final_operational_risk_score == 2.6
    assert result.final_risk_level == "LOW"


def test_compensating_controls_reduce_but_do_not_erase_severe_applicable_risk():
    asset = _asset(
        criticality=AssetCriticality.HIGH,
        exposure=NetworkExposure.INTERNET,
        patch_state=PatchState.UNPATCHED,
        controls=(
            CompensatingControl(name="WAF virtual patch", control_type="waf", effectiveness=1.0),
            CompensatingControl(name="Segmentation", control_type="network", effectiveness=1.0),
            CompensatingControl(name="EDR block", control_type="edr", effectiveness=1.0),
            CompensatingControl(name="Inactive control", control_type="manual", effectiveness=1.0, active=False),
        ),
    )
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = OperationalRiskService().assess(_analysis(score=9.0), (vulnerable,), asset)

    assert result.compensating_control_reduction == 2.4
    assert result.final_operational_risk_score == 9.6
    assert result.final_risk_level == "CRITICAL"
    assert len(result.component_breakdown["active_compensating_controls"]) == 3


def test_non_applicable_asset_is_non_actionable_zero_risk():
    asset = _asset(product=InstalledProduct(name="Unrelated Mail Server", vendor="Other Corp", version="9.0"))
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = OperationalRiskService().assess(_analysis(score=9.5), (vulnerable,), asset)

    assert result.applicability.status == ApplicabilityStatus.NOT_APPLICABLE
    assert result.final_operational_risk_score == 0.0
    assert result.final_risk_level == "LOW"
    assert "non-actionable" in result.explanation


def test_uncertain_applicability_caps_score_and_confidence():
    asset = _asset(product=InstalledProduct(name="Example VPN Gateway", vendor="Example Corp"))
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = OperationalRiskService().assess(_analysis(score=9.5, confidence=0.95), (vulnerable,), asset)

    assert result.applicability.status == ApplicabilityStatus.UNCERTAIN
    assert result.final_operational_risk_score == 5.0
    assert result.confidence == 0.55


def test_operational_risk_serialization_is_bounded_and_deterministic():
    asset = _asset(criticality=AssetCriticality.CRITICAL, exposure=NetworkExposure.INTERNET, patch_state=PatchState.UNPATCHED)
    vulnerable = VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.2",))

    result = OperationalRiskService().assess(_analysis(score=99, confidence=2), (vulnerable,), asset)
    serialized = result.to_dict()

    assert serialized == result.to_dict()
    assert serialized["source_risk_score"] == 10.0
    assert serialized["final_operational_risk_score"] == 10.0
    assert serialized["confidence"] == 0.82
    assert serialized["applicability"]["status"] == "applicable"
