from enrichment.cve_enrichment import EnrichmentSummary, build_cve_enrichment, build_enrichment_update, update_summary
from enrichment.epss import EpssCatalog, EpssEntry
from enrichment.kev import KevCatalog, KevEntry


def test_cve_enrichment_builds_mongo_payload_for_epss_and_non_listed_kev():
    epss_catalog = EpssCatalog(
        entries={
            "CVE-2026-1111": EpssEntry(
                cve_id="CVE-2026-1111",
                probability=0.00561,
                percentile=0.42218,
                date="2026-06-18",
            )
        },
        source_date="2026-06-18",
    )
    kev_catalog = KevCatalog(entries={}, available=True, date_checked="2026-06-18")

    enrichment = build_cve_enrichment("CVE-2026-1111", epss_catalog=epss_catalog, kev_catalog=kev_catalog)

    assert enrichment == {
        "epss": {
            "available": True,
            "probability": 0.00561,
            "percentile": 0.42218,
            "date": "2026-06-18",
            "source": "FIRST",
        },
        "kev": {
            "status_known": True,
            "listed": False,
            "source": "CISA",
            "date_checked": "2026-06-18",
        },
    }


def test_cve_enrichment_includes_kev_metadata_when_listed():
    epss_catalog = EpssCatalog(entries={}, source_date="2026-06-18")
    kev_catalog = KevCatalog(
        entries={
            "CVE-2026-1111": KevEntry(
                cve_id="CVE-2026-1111",
                vendor_project="Example Vendor",
                product="Example Product",
                vulnerability_name="Example Vulnerability",
                date_added="2026-06-18",
                due_date="2026-06-25",
                known_ransomware_campaign_use="Known",
                required_action="Patch",
                notes="Note",
            )
        },
        date_checked="2026-06-18",
    )

    enrichment = build_cve_enrichment("CVE-2026-1111", epss_catalog=epss_catalog, kev_catalog=kev_catalog)

    assert enrichment["epss"] == {"available": False, "source": "FIRST", "date": "2026-06-18"}
    assert enrichment["kev"]["listed"] is True
    assert enrichment["kev"]["vendor_project"] == "Example Vendor"
    assert enrichment["kev"]["required_action"] == "Patch"


def test_cve_enrichment_keeps_kev_unknown_when_catalog_unavailable():
    epss_catalog = EpssCatalog(entries={}, source_date="2026-06-18")
    kev_catalog = KevCatalog(entries={}, available=False, date_checked="2026-06-18")

    enrichment = build_cve_enrichment("CVE-2026-1111", epss_catalog=epss_catalog, kev_catalog=kev_catalog)

    assert enrichment["kev"] == {
        "status_known": False,
        "listed": False,
        "source": "CISA",
        "date_checked": "2026-06-18",
    }


def test_cve_enrichment_update_only_sets_enrichment_fields():
    epss_catalog = EpssCatalog(entries={})
    kev_catalog = KevCatalog(entries={}, available=True, date_checked="2026-06-18")

    update = build_enrichment_update("CVE-2026-1111", epss_catalog=epss_catalog, kev_catalog=kev_catalog)

    assert set(update) == {"$set"}
    assert set(update["$set"]) == {"enrichment.epss", "enrichment.kev"}


def test_cve_enrichment_summary_counts_all_statuses():
    summary = EnrichmentSummary()
    update_summary(summary, {"epss": {"available": True}, "kev": {"status_known": True, "listed": True}})
    update_summary(summary, {"epss": {"available": False}, "kev": {"status_known": True, "listed": False}})
    update_summary(summary, {"epss": {"available": False}, "kev": {"status_known": False, "listed": False}})

    assert summary.to_dict() == {
        "total_cves_scanned": 3,
        "epss_matched": 1,
        "epss_missing": 2,
        "kev_listed": 1,
        "kev_not_listed": 1,
        "kev_unknown": 1,
        "updated": 0,
    }
