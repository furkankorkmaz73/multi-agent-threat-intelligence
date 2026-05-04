"""Minimal API smoke test for a running local service.

Usage:
    python scripts/smoke_api.py [base_url]

Example:
    python scripts/smoke_api.py http://127.0.0.1:8000
"""
from __future__ import annotations

import json
import sys
from urllib.error import URLError
from urllib.request import Request, urlopen

BASE_URL = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://127.0.0.1:8000"


def request(path: str, method: str = "GET", payload: dict | None = None) -> dict:
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(f"{BASE_URL}{path}", data=data, headers=headers, method=method)
    with urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> int:
    try:
        health = request("/health")
        sources = request("/sources")
        analysis = request(
            "/analyze/cve",
            method="POST",
            payload={
                "_id": "CVE-SMOKE-0001",
                "published": "2026-01-01T00:00:00Z",
                "descriptions": [{"value": "remote code execution in exposed vpn appliance"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
            },
        )
    except URLError as exc:
        print(f"Smoke test failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({"health": health, "sources": sources, "analysis_level": analysis.get("risk_level"), "analysis_score": analysis.get("risk_score")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
