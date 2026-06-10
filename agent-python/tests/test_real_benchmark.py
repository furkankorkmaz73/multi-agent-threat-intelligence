import gzip
import json
from datetime import datetime, timezone

import pytest

from evaluation.real_benchmark import CURATED_BENCHMARK, run_real_benchmark, validate_benchmark_definition
from evaluation.real_data import DataFormatError, DataUnavailableError, EPSS_SOURCE, KEV_SOURCE, load_cached_dataset


FIXED_NOW = datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc)


def _kev_json():
    return {
        "vulnerabilities": [
            {
                "cveID": "CVE-2021-44228",
                "vendorProject": "Apache",
                "product": "Log4j",
                "vulnerabilityName": "Log4Shell",
                "dateAdded": "2021-12-10",
                "knownRansomwareCampaignUse": "Known",
                "dueDate": "2021-12-24",
            },
            {
                "cveID": "CVE-2023-34362",
                "vendorProject": "Progress",
                "product": "MOVEit Transfer",
                "vulnerabilityName": "MOVEit SQL Injection",
                "dateAdded": "2023-06-02",
            },
        ]
    }


def _epss_csv():
    return "\n".join(
        [
            "cve,epss,percentile",
            "CVE-2021-44228,0.97,0.999",
            "CVE-2023-34362,0.95,0.998",
            "CVE-2023-23752,0.86,0.990",
            "CVE-2020-0796,0.11,0.610",
        ]
    )


def _model_results():
    return [
        {
            "cve_id": "CVE-2021-44228",
            "risk_score": 9.7,
            "confidence": 0.91,
            "cvss_score": 10.0,
            "evidence": {"related_urlhaus_count": 2, "related_dread_count": 1},
            "feature_breakdown": {"graph_bonus": 0.4},
        },
        {
            "cve_id": "CVE-2023-23752",
            "risk_score": 6.2,
            "confidence": 0.74,
            "cvss_score": 5.3,
            "evidence": {"related_urlhaus_count": 1},
        },
        {
            "cve_id": "CVE-2020-0796",
            "risk_score": 5.6,
            "confidence": 0.63,
            "cvss_score": 10.0,
            "evidence": {},
        },
    ]


def test_cached_download_reuse_and_provenance(tmp_path):
    calls = []

    def fetcher(url, timeout):
        calls.append((url, timeout))
        return json.dumps(_kev_json())

    first = load_cached_dataset(KEV_SOURCE, tmp_path, refresh=True, fetcher=fetcher, timeout_seconds=4.0, now=lambda: FIXED_NOW)
    second = load_cached_dataset(KEV_SOURCE, tmp_path, offline=True, fetcher=lambda *_args: (_ for _ in ()).throw(AssertionError("network used")))

    assert len(calls) == 1
    assert first.provenance.cache_hit is False
    assert second.provenance.cache_hit is True
    assert second.provenance.downloaded_at == FIXED_NOW.isoformat()
    assert first.provenance.content_hash == second.provenance.content_hash
    assert second.provenance.parser_stats["valid_rows"] == 2


def test_offline_mode_requires_cached_dataset(tmp_path):
    with pytest.raises(DataUnavailableError):
        load_cached_dataset(KEV_SOURCE, tmp_path, offline=True)


def test_malformed_download_fails_clearly(tmp_path):
    with pytest.raises(DataFormatError):
        load_cached_dataset(KEV_SOURCE, tmp_path, refresh=True, fetcher=lambda *_args: "{\"vulnerabilities\": []}", now=lambda: FIXED_NOW)


def test_gzip_epss_download_is_decompressed_and_hashed(tmp_path):
    compressed = gzip.compress(_epss_csv().encode("utf-8"))
    result = load_cached_dataset(EPSS_SOURCE, tmp_path, refresh=True, fetcher=lambda *_args: compressed, now=lambda: FIXED_NOW)

    assert result.parse_result.valid_rows == 4
    assert (tmp_path / "first_epss.csv").read_text(encoding="utf-8").startswith("cve,epss,percentile")
    assert result.provenance.content_hash


def test_benchmark_definition_is_valid_and_reviewable():
    summary = validate_benchmark_definition(CURATED_BENCHMARK)

    assert summary["version"] == "real-cve-benchmark-v1"
    assert summary["record_count"] >= 10
    assert summary["buckets"]["known_exploited_kev"] >= 3


def test_real_benchmark_generates_artifacts_and_reports_missing_model_results(tmp_path):
    kev_path = tmp_path / "kev.json"
    epss_path = tmp_path / "epss.csv"
    model_path = tmp_path / "model_results.json"
    output_dir = tmp_path / "artifacts"
    kev_path.write_text(json.dumps(_kev_json()), encoding="utf-8")
    epss_path.write_text(_epss_csv(), encoding="utf-8")
    model_path.write_text(json.dumps({"records": _model_results()}), encoding="utf-8")

    report = run_real_benchmark(
        model_results_path=model_path,
        output_dir=output_dir,
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW.isoformat(),
        kev_path=kev_path,
        epss_path=epss_path,
    )

    assert report["generated_at"] == FIXED_NOW.isoformat()
    assert report["coverage"]["model_result_count"] == 3
    assert "CVE-2023-34362" in report["coverage"]["missing_model_results"]
    assert report["coverage"]["kev_count"] == 2
    assert report["coverage"]["epss_available_count"] == 4
    assert report["model_results"]["missing_model_results"] == report["coverage"]["missing_model_results"]
    assert (output_dir / "benchmark_summary.json").exists()
    assert (output_dir / "benchmark_records.csv").read_text(encoding="utf-8").startswith("cve_id,bucket,")
    assert "model_risk,precision_at_1" in (output_dir / "baseline_metrics.csv").read_text(encoding="utf-8")


def test_real_benchmark_output_is_deterministic_for_fixed_inputs(tmp_path):
    kev_path = tmp_path / "kev.json"
    epss_path = tmp_path / "epss.csv"
    model_path = tmp_path / "model_results.json"
    kev_path.write_text(json.dumps(_kev_json()), encoding="utf-8")
    epss_path.write_text(_epss_csv(), encoding="utf-8")
    model_path.write_text(json.dumps(_model_results()), encoding="utf-8")

    first = run_real_benchmark(
        model_results_path=model_path,
        output_dir=tmp_path / "first",
        cache_dir=tmp_path / "cache-a",
        generated_at=FIXED_NOW.isoformat(),
        kev_path=kev_path,
        epss_path=epss_path,
    )
    second = run_real_benchmark(
        model_results_path=model_path,
        output_dir=tmp_path / "second",
        cache_dir=tmp_path / "cache-b",
        generated_at=FIXED_NOW.isoformat(),
        kev_path=kev_path,
        epss_path=epss_path,
    )

    assert first == second
    assert (tmp_path / "first" / "benchmark_summary.json").read_text(encoding="utf-8") == (
        tmp_path / "second" / "benchmark_summary.json"
    ).read_text(encoding="utf-8")
