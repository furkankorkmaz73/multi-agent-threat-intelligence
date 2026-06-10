import json
from datetime import datetime, timezone

import pytest

from agents import llm_helper
from evaluation.model_export import run_model_export
from evaluation.nvd_cves import load_nvd_cves, parse_nvd_cve_records
from evaluation.real_data import DataUnavailableError


FIXED_NOW = "2026-06-10T00:00:00+00:00"


def _nvd_fixture(include_malformed=False):
    rows = [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:00.000",
                "lastModified": "2024-11-07T21:15:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints, allowing remote code execution.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
            }
        },
        {
            "cve": {
                "id": "CVE-2020-0796",
                "published": "2020-03-12T17:15:00.000",
                "lastModified": "2024-11-21T20:15:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A remote code execution vulnerability exists in Microsoft Server Message Block 3.1.1 handling of crafted requests.",
                    }
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "cvssData": {
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }
                    ]
                },
            }
        },
    ]
    if include_malformed:
        rows.append({"cve": {"id": "CVE-2023-0001", "descriptions": []}})
    return {"vulnerabilities": rows}


def _kev_json():
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
            }
        ]
    }


def _epss_csv():
    return "\n".join(
        [
            "cve,epss,percentile",
            "CVE-2021-44228,0.97,0.999",
            "CVE-2020-0796,0.11,0.610",
        ]
    )


def _write_inputs(tmp_path, *, include_malformed=False):
    cve_path = tmp_path / "nvd.json"
    kev_path = tmp_path / "kev.json"
    epss_path = tmp_path / "epss.csv"
    cve_path.write_text(json.dumps(_nvd_fixture(include_malformed=include_malformed)), encoding="utf-8")
    kev_path.write_text(json.dumps(_kev_json()), encoding="utf-8")
    epss_path.write_text(_epss_csv(), encoding="utf-8")
    return cve_path, kev_path, epss_path


def test_cached_cve_data_loading_records_provenance(tmp_path):
    calls = []

    def fetcher(url, timeout):
        calls.append((url, timeout))
        return json.dumps(_nvd_fixture())

    result = load_nvd_cves(
        cve_ids=["CVE-2021-44228", "CVE-2020-0796"],
        cache_dir=tmp_path,
        refresh=True,
        fetcher=fetcher,
        now=lambda: datetime(2026, 6, 10, tzinfo=timezone.utc),
    )
    cached = load_nvd_cves(cve_ids=["CVE-2021-44228"], cache_dir=tmp_path, offline=True)

    assert len(calls) == 2
    assert result.provenance.downloaded_at == FIXED_NOW
    assert result.records["CVE-2021-44228"]["metrics"]["cvss_metric_v31"][0]["cvss_data"]["base_score"] == 10.0
    assert cached.provenance.cache_hit is True
    assert cached.provenance.loaded_cves == ["CVE-2021-44228"]


def test_missing_cves_and_malformed_nvd_records_are_visible(tmp_path):
    cve_path, _kev_path, _epss_path = _write_inputs(tmp_path, include_malformed=True)

    result = load_nvd_cves(
        cve_ids=["CVE-2021-44228", "CVE-2023-34362"],
        cache_dir=tmp_path / "cache",
        local_path=cve_path,
        offline=True,
    )
    records, stats, malformed = parse_nvd_cve_records(cve_path.read_text(encoding="utf-8"))

    assert result.provenance.missing_cves == ["CVE-2023-34362"]
    assert result.malformed_records[0]["reason"] == "missing_required_cve_fields"
    assert records["CVE-2020-0796"]["_id"] == "CVE-2020-0796"
    assert stats["missing_required_rows"] == 1
    assert malformed


def test_offline_cve_loading_requires_cache(tmp_path):
    with pytest.raises(DataUnavailableError):
        load_nvd_cves(cve_ids=["CVE-2021-44228"], cache_dir=tmp_path, offline=True)


def test_model_export_is_deterministic_and_uses_llm_disabled_fallback(tmp_path):
    cve_path, _kev_path, _epss_path = _write_inputs(tmp_path)
    original_client = llm_helper.client
    llm_helper.client = object()
    try:
        first = run_model_export(
            cve_source_path=cve_path,
            output_dir=tmp_path / "first",
            cache_dir=tmp_path / "cache-a",
            offline=True,
            generated_at=FIXED_NOW,
            reference_time=FIXED_NOW,
        )
        second = run_model_export(
            cve_source_path=cve_path,
            output_dir=tmp_path / "second",
            cache_dir=tmp_path / "cache-b",
            offline=True,
            generated_at=FIXED_NOW,
            reference_time=FIXED_NOW,
        )
    finally:
        llm_helper.client = original_client

    first_payload = json.loads((tmp_path / "first" / "model_results.json").read_text(encoding="utf-8"))
    second_payload = json.loads((tmp_path / "second" / "model_results.json").read_text(encoding="utf-8"))
    assert first["coverage"]["model_result_count"] == 2
    assert first_payload == second_payload
    assert first_payload["records"][0]["evidence"]["llm_products"] == []
    assert {"cve_id", "risk_score", "confidence", "cvss_score", "feature_breakdown"} <= set(first_payload["records"][0])


def test_partial_analysis_failure_is_reported(tmp_path, monkeypatch):
    cve_path, _kev_path, _epss_path = _write_inputs(tmp_path)

    class FailingDiagnostic:
        def analyze(self, source, data, db=None):
            if data["_id"] == "CVE-2020-0796":
                raise RuntimeError("boom")
            return {
                "entity_id": data["_id"],
                "risk_score": 8.0,
                "risk_level": "HIGH",
                "confidence": 0.8,
                "evidence": {"cvss_score": 10.0},
                "feature_breakdown": {},
                "graph_summary": {},
                "orchestration_trace": [],
                "execution_plan": [],
            }

    monkeypatch.setattr("evaluation.model_export.DiagnosticAgent", FailingDiagnostic)
    report = run_model_export(cve_source_path=cve_path, output_dir=tmp_path / "out", cache_dir=tmp_path / "cache", offline=True, generated_at=FIXED_NOW)

    failures = json.loads((tmp_path / "out" / "analysis_failures.json").read_text(encoding="utf-8"))["failures"]
    assert report["coverage"]["model_result_count"] == 1
    assert any(item["cve_id"] == "CVE-2020-0796" and item["status"] == "analysis_failed" for item in failures)


def test_chained_benchmark_artifacts_are_generated_from_model_export(tmp_path):
    cve_path, kev_path, epss_path = _write_inputs(tmp_path)

    report = run_model_export(
        cve_source_path=cve_path,
        output_dir=tmp_path / "export",
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
        run_benchmark=True,
        benchmark_output_dir=tmp_path / "benchmark",
        kev_path=kev_path,
        epss_path=epss_path,
    )

    assert (tmp_path / "benchmark" / "benchmark_summary.json").exists()
    assert (tmp_path / "benchmark" / "benchmark_records.csv").exists()
    assert (tmp_path / "benchmark" / "baseline_metrics.csv").exists()
    assert report["benchmark"]["coverage"]["model_result_count"] == 2
    assert "CVE-2023-34362" in report["benchmark"]["coverage"]["missing_model_results"]
