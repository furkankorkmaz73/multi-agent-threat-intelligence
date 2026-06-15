from __future__ import annotations

from typing import Any, Dict, List

from analysis.applicability import VulnerableProduct
from analysis.assets import Asset, AssetCriticality, CompensatingControl, InstalledProduct, NetworkExposure, PatchState
from analysis.scoring_signals import calculate_risk_score_from_normalized_signals, normalize_cvss


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
    kev_ids = {
        "CVE-2026-9001": ("Example Corp", "Example VPN Gateway", "Example VPN Gateway RCE"),
        "CVE-2026-9002": ("Example Corp", "Example VPN Gateway", "Example VPN Gateway auth bypass"),
        "CVE-2026-9008": ("IdentitySoft", "Identity Portal", "Identity Portal token forgery"),
        "CVE-2026-9010": ("LegacyNet", "Edge Gateway", "Legacy gateway exploitation"),
        "CVE-2026-9014": ("CloudWorks", "Admin Console", "Cloud admin access bypass"),
        "CVE-2026-9021": ("MailStack", "Mail Gateway", "Mail gateway command injection"),
        "CVE-2026-9022": ("DeviceCo", "IoT Console", "IoT console exploited access"),
    }
    return {
        "vulnerabilities": [
            {
                "cveID": cve_id,
                "vendorProject": vendor,
                "product": product,
                "vulnerabilityName": name,
                "dateAdded": "2026-06-10",
                "knownRansomwareCampaignUse": "Known",
                "dueDate": "2026-06-24",
            }
            for cve_id, (vendor, product, name) in sorted(kev_ids.items())
        ]
    }


def fixture_epss_csv() -> str:
    rows = ["cve,epss,percentile"]
    rows.extend(f"{row['cve_id']},{row['epss_score']:.2f},{row['epss_percentile']:.2f}" for row in fixture_evaluation_model_results())
    return "\n".join(rows)


def fixture_evaluation_model_results() -> List[Dict[str, Any]]:
    """Deterministic thesis evaluation set.

    These rows are a controlled benchmark fixture, not live threat-intelligence
    data. They intentionally mix severity, EPSS, KEV, correlation, recency, and
    confidence cases so ranking and ablation tables have observable behavior.
    """
    specs = [
        ("CVE-2026-9001", 9.8, 0.94, 0.99, 0.95, True, 0.80, 0.69, 0.32, 1.00, 1, 1, "exact CVE match plus URLhaus and Dread corroboration"),
        ("CVE-2026-9002", 6.5, 0.91, 0.98, 0.78, True, 0.45, 0.00, 0.00, 1.00, 0, 0, "medium CVSS but high EPSS and KEV-listed"),
        ("CVE-2026-9003", 5.5, 0.30, 0.55, 0.74, False, 0.80, 0.46, 0.20, 0.70, 1, 0, "medium severity with accepted URLhaus IOC evidence"),
        ("CVE-2026-9004", 9.8, 0.02, 0.08, 0.46, False, 0.05, 0.00, 0.00, 0.40, 0, 0, "high CVSS stale record with little external support"),
        ("CVE-2026-9005", 7.2, 0.62, 0.88, 0.84, False, 1.00, 0.74, 0.50, 0.90, 1, 0, "recent moderate CVE with strong accepted correlation"),
        ("CVE-2026-9006", 7.0, 0.25, 0.40, 0.46, False, 0.45, 0.00, 0.00, 0.65, 0, 0, "Dread-only weak signal routed to manual review"),
        ("CVE-2026-9007", 9.9, 0.01, 0.05, 0.43, False, 0.30, 0.00, 0.00, 0.35, 0, 0, "high CVSS with low EPSS and no accepted evidence"),
        ("CVE-2026-9008", 6.0, 0.88, 0.97, 0.81, True, 0.80, 0.18, 0.10, 0.80, 0, 0, "medium severity KEV case with high EPSS"),
        ("CVE-2026-9009", 4.2, 0.55, 0.82, 0.73, False, 1.00, 0.52, 0.25, 0.55, 1, 0, "low CVSS but accepted URLhaus evidence"),
        ("CVE-2026-9010", 8.8, 0.76, 0.93, 0.86, True, 0.05, 0.35, 0.20, 0.75, 1, 0, "older high-severity KEV case with active IOC support"),
        ("CVE-2026-9011", 9.5, 0.03, 0.12, 0.42, False, 0.30, 0.00, 0.00, 0.40, 0, 0, "high CVSS but low confidence and weak external evidence"),
        ("CVE-2026-9012", 6.8, 0.70, 0.90, 0.82, False, 1.00, 0.62, 0.45, 0.80, 1, 0, "moderate recent CVE with accepted correlation and graph context"),
        ("CVE-2026-9013", 5.0, 0.04, 0.15, 0.38, False, 0.30, 0.00, 0.00, 0.25, 0, 0, "medium severity control with low exploitation signal"),
        ("CVE-2026-9014", 7.0, 0.72, 0.91, 0.84, True, 0.45, 0.20, 0.10, 0.70, 0, 0, "KEV-listed operationally relevant admin console issue"),
        ("CVE-2026-9015", 5.8, 0.15, 0.30, 0.76, False, 0.80, 0.58, 0.35, 0.60, 1, 0, "exact URLhaus CVE reference despite lower EPSS"),
        ("CVE-2026-9016", 8.5, 0.10, 0.28, 0.44, False, 0.30, 0.00, 0.00, 0.35, 0, 0, "generic keyword-only candidate rejected"),
        ("CVE-2026-9017", 6.2, 0.40, 0.68, 0.52, False, 0.45, 0.00, 0.00, 0.55, 0, 0, "ambiguous Dread evidence kept for manual review"),
        ("CVE-2026-9018", 4.5, 0.05, 0.18, 0.34, False, 0.45, 0.00, 0.00, 0.20, 0, 0, "weak Dread signal rejected"),
        ("CVE-2026-9019", 5.5, 0.93, 0.99, 0.64, False, 0.80, 0.00, 0.00, 0.45, 0, 0, "high EPSS non-KEV without corroborating IOC evidence"),
        ("CVE-2026-9020", 9.0, 0.85, 0.96, 0.72, False, 0.45, 0.00, 0.00, 0.60, 0, 0, "high CVSS and EPSS but not KEV-listed"),
        ("CVE-2026-9021", 6.1, 0.33, 0.58, 0.75, True, 0.45, 0.12, 0.20, 0.60, 0, 0, "KEV-listed medium severity with modest EPSS"),
        ("CVE-2026-9022", 3.9, 0.90, 0.98, 0.80, True, 1.00, 0.10, 0.10, 0.40, 0, 0, "low CVSS but KEV and high EPSS"),
        ("CVE-2026-9023", 7.0, 0.50, 0.80, 0.83, False, 1.00, 0.70, 0.60, 0.75, 1, 0, "recent moderate issue with strong URLhaus and graph support"),
        ("CVE-2026-9024", 7.8, 0.02, 0.10, 0.40, False, 0.05, 0.00, 0.00, 0.35, 0, 0, "stale non-KEV control with no active evidence"),
    ]
    return [
        _evaluation_row(
            cve_id=cve_id,
            cvss_score=cvss,
            epss_score=epss,
            epss_percentile=percentile,
            confidence=confidence,
            is_kev=is_kev,
            recency_signal=recency,
            correlation_signal=correlation,
            graph_signal=graph,
            nlp_context_signal=nlp,
            related_urlhaus_count=urlhaus,
            related_dread_count=dread,
            rationale=rationale,
        )
        for cve_id, cvss, epss, percentile, confidence, is_kev, recency, correlation, graph, nlp, urlhaus, dread, rationale in specs
    ]


def _evaluation_row(
    *,
    cve_id: str,
    cvss_score: float,
    epss_score: float,
    epss_percentile: float,
    confidence: float,
    is_kev: bool,
    recency_signal: float,
    correlation_signal: float,
    graph_signal: float,
    nlp_context_signal: float,
    related_urlhaus_count: int,
    related_dread_count: int,
    rationale: str,
) -> Dict[str, Any]:
    signals = {
        "severity_signal": normalize_cvss(cvss_score),
        "epss_signal": epss_score,
        "kev_signal": 1.0 if is_kev else 0.0,
        "recency_signal": recency_signal,
        "correlation_signal": correlation_signal,
        "graph_signal": graph_signal,
        "nlp_context_signal": nlp_context_signal,
    }
    signal_breakdown = calculate_risk_score_from_normalized_signals(signals)
    risk_score = signal_breakdown["risk_score_from_signals"]
    return {
        "cve_id": cve_id,
        "risk_score": risk_score,
        "confidence": confidence,
        "cvss_score": cvss_score,
        "epss_score": epss_score,
        "epss_percentile": epss_percentile,
        "is_kev": is_kev,
        "evidence": {
            "cvss_score": cvss_score,
            "related_urlhaus_count": related_urlhaus_count,
            "related_dread_count": related_dread_count,
            "fixture_rationale": rationale,
        },
        "feature_breakdown": {
            **signal_breakdown,
            "final_score": risk_score,
            "raw_score_before_clamp": risk_score,
            "recentness_bonus": round(recency_signal, 3),
            "age_penalty": round(1.0 - recency_signal, 3),
            "urlhaus_correlation_bonus": round(correlation_signal * 2.0 if related_urlhaus_count else 0.0, 3),
            "dread_correlation_bonus": round(correlation_signal * 1.2 if related_dread_count else 0.0, 3),
            "graph_bonus": round(graph_signal * 0.6, 3),
            "fixture_rationale": rationale,
            "related_urlhaus_count": related_urlhaus_count,
            "related_dread_count": related_dread_count,
        },
    }
