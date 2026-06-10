from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Mapping, Optional

from analysis.assets import Asset, InstalledProduct


GENERIC_PRODUCT_TERMS = {
    "app",
    "application",
    "client",
    "component",
    "device",
    "gateway",
    "library",
    "manager",
    "module",
    "plugin",
    "product",
    "server",
    "service",
    "software",
    "system",
    "tool",
    "web",
}


class ApplicabilityStatus(str, Enum):
    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class VulnerableProduct:
    name: str
    vendor: Optional[str] = None
    versions: tuple[str, ...] = field(default_factory=tuple)
    identifiers: tuple[str, ...] = field(default_factory=tuple)
    evidence_references: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name or "").strip())
        object.__setattr__(self, "vendor", _clean_optional(self.vendor))
        object.__setattr__(self, "versions", tuple(str(value).strip() for value in _as_tuple(self.versions) if str(value).strip()))
        object.__setattr__(self, "identifiers", tuple(str(value).strip() for value in _as_tuple(self.identifiers) if str(value).strip()))
        object.__setattr__(self, "evidence_references", tuple(dict(value) for value in _as_tuple(self.evidence_references)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "vendor": self.vendor,
            "versions": list(self.versions),
            "identifiers": list(self.identifiers),
            "evidence_references": [dict(item) for item in self.evidence_references],
        }


@dataclass(frozen=True)
class ProductApplicability:
    status: ApplicabilityStatus
    confidence: float
    matched_product_identifiers: tuple[str, ...] = field(default_factory=tuple)
    reasons: tuple[str, ...] = field(default_factory=tuple)
    asset_product: Optional[InstalledProduct] = None
    vulnerable_product: Optional[VulnerableProduct] = None
    evidence_references: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", _clamp(self.confidence))
        object.__setattr__(
            self,
            "matched_product_identifiers",
            tuple(str(value).strip() for value in _as_tuple(self.matched_product_identifiers) if str(value).strip()),
        )
        object.__setattr__(self, "reasons", tuple(str(value).strip() for value in _as_tuple(self.reasons) if str(value).strip()))
        object.__setattr__(self, "evidence_references", tuple(dict(value) for value in _as_tuple(self.evidence_references)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "confidence": round(float(self.confidence), 4),
            "matched_product_identifiers": list(self.matched_product_identifiers),
            "reasons": list(self.reasons),
            "asset_product": self.asset_product.to_dict() if self.asset_product else None,
            "vulnerable_product": self.vulnerable_product.to_dict() if self.vulnerable_product else None,
            "evidence_references": [dict(item) for item in self.evidence_references],
        }


def resolve_product_applicability(asset: Asset, vulnerable_products: Iterable[VulnerableProduct]) -> ProductApplicability:
    products = tuple(vulnerable_products or ())
    if not products:
        return ProductApplicability(
            status=ApplicabilityStatus.UNCERTAIN,
            confidence=0.2,
            reasons=("no_vulnerable_product_metadata",),
        )
    if not asset.installed_products:
        return ProductApplicability(
            status=ApplicabilityStatus.UNCERTAIN,
            confidence=0.2,
            reasons=("asset_has_no_installed_product_inventory",),
        )

    candidates: list[ProductApplicability] = []
    for vulnerable_product in products:
        for installed_product in asset.installed_products:
            candidates.append(_compare_products(installed_product, vulnerable_product))

    ordered = sorted(candidates, key=_applicability_sort_key, reverse=True)
    best = ordered[0] if ordered else None
    if best is None:
        return ProductApplicability(status=ApplicabilityStatus.UNCERTAIN, confidence=0.2, reasons=("no_comparable_products",))
    return best


def _compare_products(installed: InstalledProduct, vulnerable: VulnerableProduct) -> ProductApplicability:
    identifier_match = _identifier_intersection(installed, vulnerable)
    if identifier_match:
        return _with_version_decision(
            installed,
            vulnerable,
            matched_identifiers=identifier_match,
            base_confidence=0.97,
            match_reason="exact_identifier_match",
        )

    name_match = _normalized_name_match(installed, vulnerable)
    vendor_match = _normalized(installed.vendor) and _normalized(installed.vendor) == _normalized(vulnerable.vendor)
    if name_match and vendor_match:
        return _with_version_decision(
            installed,
            vulnerable,
            matched_identifiers=(installed.name,),
            base_confidence=0.82,
            match_reason="vendor_product_match",
        )

    if name_match and not vulnerable.vendor:
        return _with_version_decision(
            installed,
            vulnerable,
            matched_identifiers=(installed.name,),
            base_confidence=0.72,
            match_reason="product_name_match_without_vendor",
        )

    if _weak_overlap(installed.name, vulnerable.name):
        return ProductApplicability(
            status=ApplicabilityStatus.NOT_APPLICABLE,
            confidence=0.64,
            matched_product_identifiers=(),
            reasons=("generic_or_substring_overlap_rejected",),
            asset_product=installed,
            vulnerable_product=vulnerable,
            evidence_references=vulnerable.evidence_references,
        )

    return ProductApplicability(
        status=ApplicabilityStatus.NOT_APPLICABLE,
        confidence=0.7,
        reasons=("no_product_match",),
        asset_product=installed,
        vulnerable_product=vulnerable,
        evidence_references=vulnerable.evidence_references,
    )


def _with_version_decision(
    installed: InstalledProduct,
    vulnerable: VulnerableProduct,
    *,
    matched_identifiers: tuple[str, ...],
    base_confidence: float,
    match_reason: str,
) -> ProductApplicability:
    if not vulnerable.versions:
        return ProductApplicability(
            status=ApplicabilityStatus.APPLICABLE,
            confidence=base_confidence - 0.12,
            matched_product_identifiers=matched_identifiers,
            reasons=(match_reason, "no_vulnerable_version_constraint"),
            asset_product=installed,
            vulnerable_product=vulnerable,
            evidence_references=vulnerable.evidence_references,
        )

    if not installed.version:
        return ProductApplicability(
            status=ApplicabilityStatus.UNCERTAIN,
            confidence=min(base_confidence, 0.58),
            matched_product_identifiers=matched_identifiers,
            reasons=(match_reason, "asset_version_missing"),
            asset_product=installed,
            vulnerable_product=vulnerable,
            evidence_references=vulnerable.evidence_references,
        )

    if _version_matches(installed.version, vulnerable.versions):
        return ProductApplicability(
            status=ApplicabilityStatus.APPLICABLE,
            confidence=base_confidence,
            matched_product_identifiers=matched_identifiers,
            reasons=(match_reason, "version_match"),
            asset_product=installed,
            vulnerable_product=vulnerable,
            evidence_references=vulnerable.evidence_references,
        )

    return ProductApplicability(
        status=ApplicabilityStatus.NOT_APPLICABLE,
        confidence=0.88,
        matched_product_identifiers=matched_identifiers,
        reasons=(match_reason, "version_mismatch"),
        asset_product=installed,
        vulnerable_product=vulnerable,
        evidence_references=vulnerable.evidence_references,
    )


def _identifier_intersection(installed: InstalledProduct, vulnerable: VulnerableProduct) -> tuple[str, ...]:
    installed_ids = {_normalized_identifier(value) for value in installed.identifiers}
    vulnerable_ids = {_normalized_identifier(value) for value in vulnerable.identifiers}
    matched = sorted(value for value in installed_ids.intersection(vulnerable_ids) if value)
    return tuple(matched)


def _normalized_name_match(installed: InstalledProduct, vulnerable: VulnerableProduct) -> bool:
    installed_name = _normalized_product_name(installed.name)
    vulnerable_name = _normalized_product_name(vulnerable.name)
    if not installed_name or not vulnerable_name:
        return False
    return installed_name == vulnerable_name


def _weak_overlap(left: str, right: str) -> bool:
    left_tokens = set(_tokens(left))
    right_tokens = set(_tokens(right))
    overlap = left_tokens.intersection(right_tokens)
    return bool(overlap) and all(token in GENERIC_PRODUCT_TERMS for token in overlap)


def _version_matches(installed_version: str, vulnerable_versions: Iterable[str]) -> bool:
    installed = _normalized_version(installed_version)
    return installed in {_normalized_version(value) for value in vulnerable_versions}


def _normalized_product_name(value: Optional[str]) -> str:
    tokens = [token for token in _tokens(value) if token not in GENERIC_PRODUCT_TERMS]
    return " ".join(tokens)


def _tokens(value: Optional[str]) -> tuple[str, ...]:
    normalized = _normalized(value)
    if not normalized:
        return ()
    return tuple(token for token in normalized.split(" ") if token)


def _normalized_identifier(value: str) -> str:
    return re.sub(r"\s+", "", str(value or "").strip().lower())


def _normalized(value: Optional[str]) -> str:
    text = str(value or "").lower().strip()
    text = re.sub(r"[^a-z0-9.+_-]+", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _normalized_version(value: str) -> str:
    return str(value or "").strip().lower().lstrip("v")


def _applicability_sort_key(result: ProductApplicability) -> tuple[int, float, int]:
    status_rank = {
        ApplicabilityStatus.APPLICABLE: 3,
        ApplicabilityStatus.UNCERTAIN: 2,
        ApplicabilityStatus.NOT_APPLICABLE: 1,
    }[result.status]
    return status_rank, result.confidence, len(result.matched_product_identifiers)


def _as_tuple(values: Iterable[Any] | None) -> tuple[Any, ...]:
    if values is None:
        return ()
    return tuple(values)


def _clean_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clamp(value: Any, low: float = 0.0, high: float = 1.0) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = low
    return max(low, min(numeric, high))
