from __future__ import annotations

from typing import Any, Dict, List

from analysis.applicability import VulnerableProduct
from analysis.assets import Asset, AssetCriticality, CompensatingControl, InstalledProduct, NetworkExposure, PatchState


def fixture_cves() -> List[Dict[str, Any]]:
    return [
        {
            "_id": "CVE-2026-9001",
            "published": "2026-06-08T00:00:00+00:00",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Remote code execution vulnerability in Example VPN Gateway 4.2 allows unauthenticated attackers to execute commands and deploy ransomware.",
                }
            ],
            "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 9.8}}]},
        },
        {
            "_id": "CVE-2026-9002",
            "published": "2026-02-10T00:00:00+00:00",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "Authentication bypass in Example VPN Gateway may allow initial access to administrative functions.",
                }
            ],
            "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 6.5}}]},
        },
        {
            "_id": "CVE-2015-0001",
            "published": "2015-01-01T00:00:00+00:00",
            "descriptions": [{"lang": "en", "value": "Legacy Backup Server information disclosure vulnerability in obsolete deployments."}],
            "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": 4.0}}]},
        },
    ]


def fixture_urlhaus() -> List[Dict[str, Any]]:
    return [
        {
            "_id": "UH-9001",
            "urlhaus_id": "UH-9001",
            "url": "https://malware.example/CVE-2026-9001/payload.exe",
            "threat": "malware_download",
            "tags": ["ransomware", "exploit", "rce", "CVE-2026-9001"],
            "url_status": "online",
            "date_added": "2026-06-09T00:00:00+00:00",
        },
        {
            "_id": "UH-9002",
            "urlhaus_id": "UH-9002",
            "url": "https://cdn.example/vpn-admin-check",
            "threat": "phishing",
            "tags": ["vpn", "access"],
            "url_status": "online",
            "date_added": "2026-02-11T00:00:00+00:00",
        },
        {
            "_id": "UH-9003",
            "urlhaus_id": "UH-9003",
            "url": "https://old.example/archive.bin",
            "threat": "malware_download",
            "tags": ["legacy", "backup"],
            "url_status": "offline",
            "date_added": "2015-02-01T00:00:00+00:00",
        },
    ]


def fixture_dread() -> List[Dict[str, Any]]:
    return [
        {
            "_id": "DR-9001",
            "title": "Exploit sale for CVE-2026-9001",
            "content": "Selling RCE exploit and initial access for CVE-2026-9001 Example VPN Gateway ransomware deployment.",
            "category": "exploit_sale",
            "author": "seller",
            "created_at": "2026-06-09T00:00:00+00:00",
        },
        {
            "_id": "DR-9002",
            "title": "VPN admin access discussion",
            "content": "Weak VPN admin portals and initial access brokers mention Example VPN but no exact CVE.",
            "category": "forum",
            "author": "analyst",
            "created_at": "2026-02-11T00:00:00+00:00",
        },
    ]


def fixture_assets() -> List[Asset]:
    return [
        Asset(
            asset_id="asset-vpn-prod",
            name="vpn-prod-01",
            environment="prod",
            owner_team="platform",
            criticality=AssetCriticality.CRITICAL,
            exposure=NetworkExposure.INTERNET,
            installed_products=(
                InstalledProduct(
                    name="Example VPN Gateway",
                    vendor="Example Corp",
                    version="4.2",
                    identifiers=("cpe:2.3:a:example:vpn_gateway:4.2:*:*:*:*:*:*:*",),
                ),
            ),
            patch_state=PatchState.UNPATCHED,
            compensating_controls=(CompensatingControl(name="WAF virtual patch", control_type="waf", effectiveness=0.5),),
            tags=("edge", "vpn"),
        ),
        Asset(
            asset_id="asset-backup-internal",
            name="backup-01",
            environment="prod",
            owner_team="it",
            criticality=AssetCriticality.LOW,
            exposure=NetworkExposure.INTERNAL,
            installed_products=(InstalledProduct(name="Unrelated Mail Server", vendor="Other Corp", version="9.0"),),
            patch_state=PatchState.PATCHED,
            tags=("internal",),
        ),
    ]


def fixture_vulnerable_products() -> Dict[str, List[VulnerableProduct]]:
    return {
        "CVE-2026-9001": [
            VulnerableProduct(
                name="Example VPN Gateway",
                vendor="Example Corp",
                versions=("4.2",),
                identifiers=("cpe:2.3:a:example:vpn_gateway:4.2:*:*:*:*:*:*:*",),
                evidence_references=({"source": "fixture", "field": "cpe"},),
            )
        ],
        "CVE-2026-9002": [
            VulnerableProduct(name="Example VPN Gateway", vendor="Example Corp", versions=("4.1", "4.2"), evidence_references=({"source": "fixture", "field": "product"},))
        ],
        "CVE-2015-0001": [
            VulnerableProduct(name="Legacy Backup Server", vendor="LegacySoft", versions=("1.0",), evidence_references=({"source": "fixture", "field": "product"},))
        ],
    }


def fixture_kev_json() -> Dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-9001",
                "vendorProject": "Example Corp",
                "product": "Example VPN Gateway",
                "vulnerabilityName": "Example VPN Gateway RCE",
                "dateAdded": "2026-06-10",
                "knownRansomwareCampaignUse": "Known",
                "dueDate": "2026-06-24",
            }
        ]
    }


def fixture_epss_csv() -> str:
    return "\n".join(
        [
            "cve,epss,percentile",
            "CVE-2026-9001,0.94,0.99",
            "CVE-2026-9002,0.42,0.75",
            "CVE-2015-0001,0.02,0.10",
        ]
    )
