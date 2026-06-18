from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from enrichment.epss import EpssCatalog
from enrichment.kev import KevCatalog


@dataclass
class EnrichmentSummary:
    total_cves_scanned: int = 0
    epss_matched: int = 0
    epss_missing: int = 0
    kev_listed: int = 0
    kev_not_listed: int = 0
    kev_unknown: int = 0
    updated: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "total_cves_scanned": self.total_cves_scanned,
            "epss_matched": self.epss_matched,
            "epss_missing": self.epss_missing,
            "kev_listed": self.kev_listed,
            "kev_not_listed": self.kev_not_listed,
            "kev_unknown": self.kev_unknown,
            "updated": self.updated,
        }


def build_cve_enrichment(
    cve_id: Any,
    *,
    epss_catalog: EpssCatalog,
    kev_catalog: KevCatalog,
    date_checked: str | None = None,
) -> dict[str, Any]:
    return {
        "epss": epss_catalog.lookup(cve_id),
        "kev": kev_catalog.lookup(cve_id, date_checked=date_checked),
    }


def build_enrichment_update(
    cve_id: Any,
    *,
    epss_catalog: EpssCatalog,
    kev_catalog: KevCatalog,
    date_checked: str | None = None,
) -> dict[str, Any]:
    enrichment = build_cve_enrichment(
        cve_id,
        epss_catalog=epss_catalog,
        kev_catalog=kev_catalog,
        date_checked=date_checked,
    )
    return {
        "$set": {
            "enrichment.epss": enrichment["epss"],
            "enrichment.kev": enrichment["kev"],
        }
    }


def update_summary(summary: EnrichmentSummary, enrichment: Mapping[str, Any]) -> None:
    summary.total_cves_scanned += 1
    epss = enrichment.get("epss") if isinstance(enrichment, Mapping) else {}
    kev = enrichment.get("kev") if isinstance(enrichment, Mapping) else {}
    if isinstance(epss, Mapping) and epss.get("available") is True:
        summary.epss_matched += 1
    else:
        summary.epss_missing += 1

    if isinstance(kev, Mapping) and kev.get("status_known") is True:
        if kev.get("listed") is True:
            summary.kev_listed += 1
        else:
            summary.kev_not_listed += 1
    else:
        summary.kev_unknown += 1
