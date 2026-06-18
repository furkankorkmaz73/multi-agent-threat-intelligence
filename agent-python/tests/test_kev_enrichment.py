import json
from datetime import datetime, timezone

from enrichment.kev import CISA_KEV_URL, KevCatalog, load_kev_catalog, parse_kev_csv, parse_kev_json


def _kev_payload():
    return {
        "title": "CISA Catalog of Known Exploited Vulnerabilities",
        "catalogVersion": "2026.06.18",
        "dateReleased": "2026-06-18T00:00:00Z",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-1111",
                "vendorProject": "Example Vendor",
                "product": "Example Product",
                "vulnerabilityName": "Example Product Remote Code Execution",
                "dateAdded": "2026-06-18",
                "dueDate": "2026-06-25",
                "knownRansomwareCampaignUse": "Known",
                "requiredAction": "Apply mitigations.",
                "notes": "https://example.invalid/advisory",
            }
        ],
    }


def test_kev_parser_handles_listed_cve_json():
    result = parse_kev_json(_kev_payload())
    entry = result.entries["CVE-2026-1111"]

    assert result.valid_rows == 1
    assert result.catalog_version == "2026.06.18"
    assert entry.vendor_project == "Example Vendor"
    assert entry.required_action == "Apply mitigations."
    assert entry.to_enrichment(date_checked="2026-06-18") == {
        "status_known": True,
        "listed": True,
        "source": "CISA",
        "date_checked": "2026-06-18",
        "vendor_project": "Example Vendor",
        "product": "Example Product",
        "vulnerability_name": "Example Product Remote Code Execution",
        "date_added": "2026-06-18",
        "due_date": "2026-06-25",
        "known_ransomware_campaign_use": "Known",
        "required_action": "Apply mitigations.",
        "notes": "https://example.invalid/advisory",
    }


def test_kev_catalog_loaded_absent_cve_is_known_not_listed():
    result = parse_kev_json(_kev_payload())
    catalog = KevCatalog(entries=result.entries, available=True, date_checked="2026-06-18")

    assert catalog.lookup("CVE-2026-1111")["listed"] is True
    assert catalog.lookup("CVE-2026-9999") == {
        "status_known": True,
        "listed": False,
        "source": "CISA",
        "date_checked": "2026-06-18",
    }


def test_kev_catalog_unavailable_keeps_status_unknown():
    catalog = KevCatalog(entries={}, available=False, date_checked="2026-06-18")

    assert catalog.lookup("CVE-2026-9999") == {
        "status_known": False,
        "listed": False,
        "source": "CISA",
        "date_checked": "2026-06-18",
    }


def test_kev_parser_handles_csv_sample():
    result = parse_kev_csv(
        "\n".join(
            [
                "cveID,vendorProject,product,vulnerabilityName,dateAdded,dueDate,knownRansomwareCampaignUse,requiredAction,notes",
                "CVE-2026-1111,Example Vendor,Example Product,Example Vulnerability,2026-06-18,2026-06-25,Unknown,Patch,Note",
            ]
        )
    )

    assert result.valid_rows == 1
    assert result.entries["CVE-2026-1111"].known_ransomware_campaign_use == "Unknown"


def test_kev_catalog_refresh_caches_json(tmp_path):
    calls = []

    def fetcher(url, timeout):
        calls.append((url, timeout))
        return json.dumps(_kev_payload())

    catalog = load_kev_catalog(
        cache_dir=tmp_path,
        refresh=True,
        fetcher=fetcher,
        now=lambda: datetime(2026, 6, 18, tzinfo=timezone.utc),
    )
    cached = load_kev_catalog(cache_dir=tmp_path, offline=True, fetcher=lambda *_args: (_ for _ in ()).throw(AssertionError("network used")))

    assert calls == [(CISA_KEV_URL, 30.0)]
    assert catalog.available is True
    assert cached.cache_hit is True
    assert cached.lookup("CVE-2026-1111")["listed"] is True


def test_kev_catalog_offline_can_load_cached_csv(tmp_path):
    (tmp_path / "cisa_kev.csv").write_text(
        "\n".join(
            [
                "cveID,vendorProject,product,vulnerabilityName,dateAdded,dueDate,knownRansomwareCampaignUse,requiredAction,notes",
                "CVE-2026-1111,Example Vendor,Example Product,Example Vulnerability,2026-06-18,2026-06-25,Unknown,Patch,Note",
            ]
        ),
        encoding="utf-8",
    )

    catalog = load_kev_catalog(cache_dir=tmp_path, offline=True, now=lambda: datetime(2026, 6, 18, tzinfo=timezone.utc))

    assert catalog.available is True
    assert catalog.cache_hit is True
    assert catalog.lookup("CVE-2026-1111")["listed"] is True


def test_kev_catalog_offline_missing_cache_is_unavailable(tmp_path):
    catalog = load_kev_catalog(cache_dir=tmp_path, offline=True)

    assert catalog.available is False
    assert catalog.lookup("CVE-2026-1111")["status_known"] is False
