from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, Optional


def _as_tuple(values: Iterable[Any] | None) -> tuple[Any, ...]:
    if values is None:
        return ()
    return tuple(values)


def _clamp(value: Any, low: float = 0.0, high: float = 1.0) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = low
    return max(low, min(numeric, high))


class AssetCriticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NetworkExposure(str, Enum):
    INTERNAL = "internal"
    PARTNER = "partner"
    EXTERNAL = "external"
    INTERNET = "internet"


class PatchState(str, Enum):
    PATCHED = "patched"
    UNPATCHED = "unpatched"
    PARTIALLY_PATCHED = "partially_patched"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InstalledProduct:
    name: str
    vendor: Optional[str] = None
    version: Optional[str] = None
    identifiers: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name or "").strip())
        object.__setattr__(self, "vendor", _clean_optional(self.vendor))
        object.__setattr__(self, "version", _clean_optional(self.version))
        object.__setattr__(self, "identifiers", tuple(str(value).strip() for value in _as_tuple(self.identifiers) if str(value).strip()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "vendor": self.vendor,
            "version": self.version,
            "identifiers": list(self.identifiers),
        }


@dataclass(frozen=True)
class CompensatingControl:
    name: str
    control_type: str
    effectiveness: float
    active: bool = True
    references: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "name", str(self.name or "").strip())
        object.__setattr__(self, "control_type", str(self.control_type or "").strip())
        object.__setattr__(self, "effectiveness", _clamp(self.effectiveness))
        object.__setattr__(self, "references", tuple(str(value).strip() for value in _as_tuple(self.references) if str(value).strip()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "control_type": self.control_type,
            "effectiveness": self.effectiveness,
            "active": bool(self.active),
            "references": list(self.references),
        }


@dataclass(frozen=True)
class Asset:
    asset_id: str
    name: str
    environment: Optional[str] = None
    owner_team: Optional[str] = None
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    exposure: NetworkExposure = NetworkExposure.INTERNAL
    installed_products: tuple[InstalledProduct, ...] = field(default_factory=tuple)
    patch_state: PatchState = PatchState.UNKNOWN
    compensating_controls: tuple[CompensatingControl, ...] = field(default_factory=tuple)
    tags: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        object.__setattr__(self, "asset_id", str(self.asset_id or "").strip())
        object.__setattr__(self, "name", str(self.name or "").strip())
        object.__setattr__(self, "environment", _clean_optional(self.environment))
        object.__setattr__(self, "owner_team", _clean_optional(self.owner_team))
        object.__setattr__(self, "installed_products", tuple(self.installed_products or ()))
        object.__setattr__(self, "compensating_controls", tuple(self.compensating_controls or ()))
        object.__setattr__(self, "tags", tuple(str(value).strip() for value in _as_tuple(self.tags) if str(value).strip()))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "environment": self.environment,
            "owner_team": self.owner_team,
            "criticality": self.criticality.value,
            "exposure": self.exposure.value,
            "installed_products": [item.to_dict() for item in self.installed_products],
            "patch_state": self.patch_state.value,
            "compensating_controls": [item.to_dict() for item in self.compensating_controls],
            "tags": list(self.tags),
        }


def _clean_optional(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
