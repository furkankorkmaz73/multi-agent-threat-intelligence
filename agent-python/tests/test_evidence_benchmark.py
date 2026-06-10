import json

from analysis.correlator import build_correlation_decisions
from analysis.correlation_decisions import CorrelationDecisionStatus
from evaluation.evidence_benchmark import run_evidence_benchmark
from evaluation.evidence_inputs import (
    FileRelatedEvidenceProvider,
    load_dread_records,
    load_urlhaus_records,
    parse_dread_export,
    parse_urlhaus_json,
)
from evaluation.model_export import run_model_export


FIXED_NOW = "2026-06-10T00:00:00+00:00"


def _nvd_record(cve_id, description, published="2026-05-01T00:00:00.000", cvss=9.8):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": published,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": cvss, "baseSeverity": "CRITICAL"}}]},
        }
    }


def _nvd_fixture():
    return {
        "vulnerabilities": [
            _nvd_record("CVE-2026-4242", "Example VPN gateway remote code execution exploited by ransomware loader."),
            _nvd_record("CVE-2026-4343", "Microsoft Windows component information disclosure with generic platform wording.", cvss=5.5),
        ]
    }


def _urlhaus_fixture():
    return {
        "2026-05-02": [
            {
                "id": "UH-1",
                "date_added": "2026-05-02T00:00:00+00:00",
                "url": "https://malware.example/CVE-2026-4242/payload.exe",
                "url_status": "online",
                "threat": "malware_download",
                "tags": ["ransomware", "loader"],
                "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
                "reporter": "abuse_ch",
            },
            {
                "id": "UH-2",
                "date_added": "2026-05-02T00:00:00+00:00",
                "url": "https://generic.example/api/windows",
                "url_status": "offline",
                "threat": "malware_download",
                "tags": ["exe"],
            },
            {
                "id": "UH-dup",
                "date_added": "2026-05-02T00:00:00+00:00",
                "url": "https://generic.example/api/windows",
                "url_status": "offline",
                "threat": "malware_download",
                "tags": ["exe"],
            },
            {"id": "bad"},
        ]
    }


def _dread_jsonl():
    return "\n".join(
        [
            json.dumps(
                {
                    "title": "VPN loader discussion",
                    "content": "Initial access loader for Example VPN gateway.",
                    "author": "actor",
                    "category": "access_sale",
                    "url": "dread://post/1",
                    "created_at": "2026-05-02T00:00:00+00:00",
                }
            ),
            "{not-json",
        ]
    )


def _write_files(tmp_path):
    nvd_path = tmp_path / "nvd.json"
    benchmark_path = tmp_path / "definition.json"
    urlhaus_path = tmp_path / "urlhaus.json"
    dread_path = tmp_path / "dread.jsonl"
    nvd_path.write_text(json.dumps(_nvd_fixture()), encoding="utf-8")
    benchmark_path.write_text(
        json.dumps(
            {
                "version": "test",
                "records": [
                    {"cve_id": "CVE-2026-4242", "bucket": "kev_positive"},
                    {"cve_id": "CVE-2026-4343", "bucket": "medium_severity_control"},
                ],
            }
        ),
        encoding="utf-8",
    )
    urlhaus_path.write_text(json.dumps(_urlhaus_fixture()), encoding="utf-8")
    dread_path.write_text(_dread_jsonl(), encoding="utf-8")
    return nvd_path, benchmark_path, urlhaus_path, dread_path


def test_urlhaus_cache_and_local_loading_handles_duplicates_and_malformed(tmp_path):
    path = tmp_path / "urlhaus.json"
    path.write_text(json.dumps(_urlhaus_fixture()), encoding="utf-8")

    local = load_urlhaus_records(path=path, cache_dir=tmp_path, offline=True)
    cached = load_urlhaus_records(cache_dir=tmp_path, refresh=True, fetcher=lambda _url, _timeout: json.dumps(_urlhaus_fixture()))

    assert local.provenance["row_count"] == 2
    assert local.provenance["parser_stats"]["duplicate_rows"] == 1
    assert local.provenance["parser_stats"]["missing_required_rows"] == 1
    assert cached.provenance["cache_hit"] is False
    assert (tmp_path / "urlhaus_json_recent.json").exists()


def test_dread_jsonl_parser_reports_malformed_rows(tmp_path):
    path = tmp_path / "dread.jsonl"
    path.write_text(_dread_jsonl(), encoding="utf-8")

    result = load_dread_records(path)
    parsed, stats, malformed = parse_dread_export(_dread_jsonl())

    assert result.provenance["row_count"] == 1
    assert parsed[0]["category"] == "access_sale"
    assert stats["malformed_rows"] == 1
    assert malformed[0]["reason"] == "invalid_json_line"


def test_file_related_evidence_provider_queries_are_deterministic():
    urlhaus_records, _stats, _malformed = parse_urlhaus_json(_urlhaus_fixture())
    provider = FileRelatedEvidenceProvider(urlhaus_records=urlhaus_records)

    matches = provider.find_related_urlhaus(["cve-2026-4242", "windows"], limit=2)

    assert [match["urlhaus_id"] for match in matches] == ["UH-1", "UH-2"]
    assert provider.find_related_dread(["vpn"]) == []


def test_correlation_decision_status_coverage_from_loaded_evidence():
    accepted = build_correlation_decisions(
        [
            {
                "url": "https://malware.example/CVE-2026-4242/payload.exe",
                "threat": "malware_download",
                "tags": ["ransomware"],
                "url_status": "online",
                "date_added": "2026-05-02T00:00:00+00:00",
            }
        ],
        base_keywords=["cve-2026-4242", "remote code execution"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )[0]
    manual = build_correlation_decisions(
        [
            {
                "url": "https://weak.example/vpn/loader",
                "threat": "malware_download",
                "tags": ["loader"],
                "url_status": "offline",
                "date_added": "2026-05-02T00:00:00+00:00",
            }
        ],
        base_keywords=["example vpn gateway", "initial access"],
        entity_time="2026-05-01T00:00:00+00:00",
        source="urlhaus",
    )[0]
    rejected = build_correlation_decisions(
        [
            {
                "url": "https://generic.example/api/windows",
                "threat": "malware_download",
                "tags": ["exe"],
                "url_status": "offline",
            }
        ],
        base_keywords=["microsoft windows information disclosure"],
        source="urlhaus",
    )[0]

    assert accepted.status is CorrelationDecisionStatus.ACCEPTED
    assert manual.status in {CorrelationDecisionStatus.MANUAL_REVIEW, CorrelationDecisionStatus.REJECTED}
    assert rejected.status is CorrelationDecisionStatus.REJECTED
    assert accepted.to_dict()["status"] == "accepted"


def test_cve_only_model_export_remains_compatible(tmp_path):
    nvd_path, benchmark_path, _urlhaus_path, _dread_path = _write_files(tmp_path)

    report = run_model_export(
        cve_source_path=nvd_path,
        benchmark_definition_path=benchmark_path,
        output_dir=tmp_path / "export",
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )

    payload = json.loads((tmp_path / "export" / "model_results.json").read_text(encoding="utf-8"))
    assert report["coverage"]["model_result_count"] == 2
    assert report["evidence_inputs"] == {}
    assert all(row["evidence"]["candidate_urlhaus_count"] == 0 for row in payload["records"])


def test_evidence_enabled_export_and_paired_artifacts_are_deterministic(tmp_path):
    nvd_path, benchmark_path, urlhaus_path, dread_path = _write_files(tmp_path)
    baseline = run_model_export(
        cve_source_path=nvd_path,
        benchmark_definition_path=benchmark_path,
        output_dir=tmp_path / "baseline",
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )

    first = run_evidence_benchmark(
        benchmark_definition_path=benchmark_path,
        nvd_path=nvd_path,
        baseline_model_results_path=baseline["paths"]["model_results_json"],
        urlhaus_path=urlhaus_path,
        dread_path=dread_path,
        output_dir=tmp_path / "first",
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )
    second = run_evidence_benchmark(
        benchmark_definition_path=benchmark_path,
        nvd_path=nvd_path,
        baseline_model_results_path=baseline["paths"]["model_results_json"],
        urlhaus_path=urlhaus_path,
        dread_path=dread_path,
        output_dir=tmp_path / "second",
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )

    assert first["coverage"]["urlhaus"]["row_count"] == 2
    assert first["coverage"]["dread"]["row_count"] == 1
    assert first["correlation_metrics"]["totals"]["accepted"] >= 1
    assert first["correlation_metrics"]["totals"]["rejected"] >= 1
    assert first["correlation_metrics"]["totals"]["manual_review"] >= 0
    assert first["paired_records"][0]["evidence_related_urlhaus_count"] >= 1
    assert first["paired_records"][0]["risk_score_delta"] >= 0
    assert (tmp_path / "first" / "paired_model_results.csv").exists()
    assert (tmp_path / "first" / "correlation_decisions.json").exists()
    assert first["paired_records"] == second["paired_records"]
    assert first["correlation_metrics"] == second["correlation_metrics"]


def test_missing_dread_input_is_reported_without_fabrication(tmp_path):
    nvd_path, benchmark_path, urlhaus_path, _dread_path = _write_files(tmp_path)
    baseline = run_model_export(
        cve_source_path=nvd_path,
        benchmark_definition_path=benchmark_path,
        output_dir=tmp_path / "baseline",
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )

    report = run_evidence_benchmark(
        benchmark_definition_path=benchmark_path,
        nvd_path=nvd_path,
        baseline_model_results_path=baseline["paths"]["model_results_json"],
        urlhaus_path=urlhaus_path,
        output_dir=tmp_path / "out",
        cache_dir=tmp_path / "cache",
        offline=True,
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )

    assert report["coverage"]["dread"]["available"] is False
    assert report["coverage"]["dread"]["row_count"] == 0
