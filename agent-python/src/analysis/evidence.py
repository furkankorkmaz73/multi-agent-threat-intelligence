from __future__ import annotations

from typing import Any, Dict, List, Optional, Protocol


class RelatedEvidenceProvider(Protocol):
    def find_related_urlhaus(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        ...

    def find_related_dread(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        ...

    def find_related_cves(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        ...


class NullRelatedEvidenceProvider:
    def find_related_urlhaus(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return []

    def find_related_dread(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return []

    def find_related_cves(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return []


class RelatedEvidenceAdapter:
    def __init__(self, provider: Any) -> None:
        self.provider = provider

    def find_related_urlhaus(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._call("find_related_urlhaus", keywords, limit)

    def find_related_dread(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._call("find_related_dread", keywords, limit)

    def find_related_cves(self, keywords: List[str], limit: int = 20) -> List[Dict[str, Any]]:
        return self._call("find_related_cves", keywords, limit)

    def _call(self, method_name: str, keywords: List[str], limit: int) -> List[Dict[str, Any]]:
        method = getattr(self.provider, method_name, None)
        if method is None:
            return []
        result = method(keywords, limit=limit)
        return list(result or [])


def coerce_related_evidence_provider(provider: Optional[Any]) -> RelatedEvidenceProvider:
    if provider is None:
        return NullRelatedEvidenceProvider()
    return RelatedEvidenceAdapter(provider)
