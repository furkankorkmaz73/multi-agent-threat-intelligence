from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Mapping, Optional

from analysis.applicability import ApplicabilityStatus, ProductApplicability, VulnerableProduct, resolve_product_applicability
from analysis.assets import Asset, AssetCriticality, NetworkExposure, PatchState
from analysis.scoring import level_from_score


def _clamp(value: Any, low: float = 0.0, high: float = 1.0, default: float = 0.0) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = default
    return max(low, min(numeric, high))


def _score(value: Any) -> float:
    return round(_clamp(value, 0.0, 10.0), 2)


@dataclass(frozen=True)
class OperationalRiskConfig:
    criticality_contributions: Mapping[AssetCriticality, float] = field(
        default_factory=lambda: {
            AssetCriticality.LOW: -0.4,
            AssetCriticality.MEDIUM: 0.0,
            AssetCriticality.HIGH: 0.8,
            AssetCriticality.CRITICAL: 1.4,
        }
    )
    exposure_contributions: Mapping[NetworkExposure, float] = field(
        default_factory=lambda: {
            NetworkExposure.INTERNAL: 0.0,
            NetworkExposure.PARTNER: 0.35,
            NetworkExposure.EXTERNAL: 0.8,
            NetworkExposure.INTERNET: 1.2,
        }
    )
    patch_state_contributions: Mapping[PatchState, float] = field(
        default_factory=lambda: {
            PatchState.PATCHED: -2.0,
            PatchState.UNPATCHED: 1.0,
            PatchState.PARTIALLY_PATCHED: 0.45,
            PatchState.UNKNOWN: 0.35,
        }
    )
    max_control_reduction: float = 2.5
    severe_applicable_floor: float = 6.5
    severe_source_threshold: float = 8.0
    uncertain_score_multiplier: float = 0.6
    uncertain_score_cap: float = 5.0
    uncertain_confidence_cap: float = 0.55
    not_applicable_confidence_cap: float = 0.8


@dataclass(frozen=True)
class OperationalRiskResult:
    asset_id: str
    source_identifier: str
    source_risk_score: float
    applicability: ProductApplicability
    criticality_contribution: float
    exposure_contribution: float
    patch_state_contribution: float
    compensating_control_reduction: float
    final_operational_risk_score: float
    final_risk_level: str
    confidence: float
    explanation: str
    component_breakdown: Mapping[str, Any]

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_risk_score", _score(self.source_risk_score))
        object.__setattr__(self, "criticality_contribution", round(float(self.criticality_contribution), 2))
        object.__setattr__(self, "exposure_contribution", round(float(self.exposure_contribution), 2))
        object.__setattr__(self, "patch_state_contribution", round(float(self.patch_state_contribution), 2))
        object.__setattr__(self, "compensating_control_reduction", round(_clamp(self.compensating_control_reduction, 0.0, 10.0), 2))
        object.__setattr__(self, "final_operational_risk_score", _score(self.final_operational_risk_score))
        object.__setattr__(self, "confidence", round(_clamp(self.confidence), 4))
        object.__setattr__(self, "component_breakdown", dict(self.component_breakdown))

    def to_dict(self) -> Dict[str, Any]:
        operational_delta = round(self.final_operational_risk_score - self.source_risk_score, 2)
        asset_applicable = self.applicability.status == ApplicabilityStatus.APPLICABLE
        return {
            "asset_id": self.asset_id,
            "source_identifier": self.source_identifier,
            "source_risk_score": self.source_risk_score,
            "generic_cve_risk_score": self.source_risk_score,
            "applicability": self.applicability.to_dict(),
            "criticality_contribution": self.criticality_contribution,
            "exposure_contribution": self.exposure_contribution,
            "patch_state_contribution": self.patch_state_contribution,
            "compensating_control_reduction": self.compensating_control_reduction,
            "final_operational_risk_score": self.final_operational_risk_score,
            "operational_risk_score": self.final_operational_risk_score,
            "operational_risk_delta": operational_delta,
            "asset_applicable": asset_applicable,
            "asset_match_reason": list(self.applicability.reasons),
            "final_risk_level": self.final_risk_level,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "component_breakdown": dict(self.component_breakdown),
        }


class OperationalRiskService:
    def __init__(self, config: Optional[OperationalRiskConfig] = None) -> None:
        self.config = config or OperationalRiskConfig()

    def assess(
        self,
        cve_analysis_result: Mapping[str, Any],
        vulnerable_products: Iterable[VulnerableProduct],
        asset: Asset,
    ) -> OperationalRiskResult:
        source_score = _score(cve_analysis_result.get("risk_score", 0.0))
        source_confidence = _clamp(cve_analysis_result.get("confidence", 0.0))
        source_identifier = str(cve_analysis_result.get("entity_id") or cve_analysis_result.get("cve_id") or cve_analysis_result.get("_id") or "unknown-cve")
        applicability = resolve_product_applicability(asset, vulnerable_products)

        criticality = round(float(self.config.criticality_contributions.get(asset.criticality, 0.0)), 2)
        exposure = round(float(self.config.exposure_contributions.get(asset.exposure, 0.0)), 2)
        patch_state = round(float(self.config.patch_state_contributions.get(asset.patch_state, 0.0)), 2)
        control_reduction = self._control_reduction(asset)

        if applicability.status == ApplicabilityStatus.NOT_APPLICABLE:
            final_score = 0.0
            confidence = min(source_confidence, applicability.confidence, self.config.not_applicable_confidence_cap)
            explanation = "Vulnerability is not applicable to the asset inventory; operational risk is non-actionable."
        else:
            base = source_score
            if applicability.status == ApplicabilityStatus.UNCERTAIN:
                base *= self.config.uncertain_score_multiplier
            raw_score = base + criticality + exposure + patch_state - control_reduction
            if applicability.status == ApplicabilityStatus.UNCERTAIN:
                final_score = min(_score(raw_score), self.config.uncertain_score_cap)
                confidence = min(source_confidence, applicability.confidence, self.config.uncertain_confidence_cap)
                explanation = "Applicability is uncertain, so operational score and confidence are capped."
            else:
                final_score = _score(raw_score)
                if source_score >= self.config.severe_source_threshold:
                    final_score = max(final_score, self.config.severe_applicable_floor)
                confidence = min(source_confidence, applicability.confidence)
                explanation = "Applicable vulnerability adjusted by asset criticality, exposure, patch state, and controls."

        final_score = _score(final_score)
        confidence = round(_clamp(confidence), 4)
        operational_delta = round(final_score - source_score, 2)
        asset_applicable = applicability.status == ApplicabilityStatus.APPLICABLE
        breakdown = {
            "source_risk_score": source_score,
            "generic_cve_risk_score": source_score,
            "applicability_status": applicability.status.value,
            "applicability_confidence": round(float(applicability.confidence), 4),
            "asset_applicable": asset_applicable,
            "asset_match_reason": list(applicability.reasons),
            "criticality": asset.criticality.value,
            "criticality_contribution": criticality,
            "asset_criticality_factor": criticality,
            "exposure": asset.exposure.value,
            "exposure_contribution": exposure,
            "network_exposure_factor": exposure,
            "patch_state": asset.patch_state.value,
            "patch_state_contribution": patch_state,
            "patch_state_factor": patch_state,
            "compensating_control_reduction": control_reduction,
            "compensating_control_factor": -control_reduction,
            "active_compensating_controls": [control.to_dict() for control in asset.compensating_controls if control.active],
            "bounded_final_score": final_score,
            "operational_risk_score": final_score,
            "operational_risk_delta": operational_delta,
        }
        return OperationalRiskResult(
            asset_id=asset.asset_id,
            source_identifier=source_identifier,
            source_risk_score=source_score,
            applicability=applicability,
            criticality_contribution=criticality,
            exposure_contribution=exposure,
            patch_state_contribution=patch_state,
            compensating_control_reduction=control_reduction,
            final_operational_risk_score=final_score,
            final_risk_level=level_from_score(final_score),
            confidence=confidence,
            explanation=explanation,
            component_breakdown=breakdown,
        )

    def _control_reduction(self, asset: Asset) -> float:
        active_controls = [control for control in asset.compensating_controls if control.active]
        raw_reduction = sum(control.effectiveness * 0.8 for control in active_controls)
        return round(min(raw_reduction, self.config.max_control_reduction), 2)
