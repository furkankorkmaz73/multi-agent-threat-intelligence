import json
from types import SimpleNamespace

from evaluation.correlation_benchmark import (
    GroundTruthLabel,
    _confusion_metrics,
    _select_controls,
    build_correlation_benchmark_definition,
    extract_cve_references_from_urlhaus,
    run_correlation_benchmark,
)
from evaluation.evidence_inputs import FileRelatedEvidenceProvider


FIXED_NOW = "2026-06-10T00:00:00+00:00"


def _nvd_record(cve_id, description, published="2025-01-02T00:00:00.000", cvss=9.8):
    return {
        "_id": cve_id,
        "id": cve_id,
        "published": published,
        "last_modified": published,
        "descriptions": [{"lang": "en", "value": description}],
        "metrics": {"cvss_metric_v31": [{"cvss_data": {"base_score": cvss, "base_severity": "HIGH"}}]},
        "processed": False,
        "source_metadata": {"source": "nvd", "source_ref": cve_id},
    }


def _urlhaus_records():
    return [
        {
            "urlhaus_id": "UH-1",
            "date_added": "2025-01-03T00:00:00+00:00",
            "url": "https://payload.example/CVE-2025-1111/dropper.exe",
            "url_status": "online",
            "threat": "malware_download",
            "tags": ["exploit"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
        },
        {
            "urlhaus_id": "UH-2",
            "date_added": "2025-01-03T00:00:00+00:00",
            "url": "https://payload.example/loader",
            "url_status": "offline",
            "threat": "malware_download",
            "tags": ["CVE-2025-2222", "loader"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/2/",
        },
        {
            "urlhaus_id": "UH-3",
            "date_added": "2025-01-04T00:00:00+00:00",
            "url": "https://generic.example/windows-loader",
            "url_status": "offline",
            "threat": "malware_download",
            "tags": ["loader"],
        },
    ]


def _nvd_payload(records):
    return {"vulnerabilities": [{"cve": row} for row in records]}


def test_explicit_cve_extraction_from_urlhaus_record():
    record = {
        "url": "https://example.test/CVE_2025_12345/payload",
        "tags": ["CVE-2024-1111", "loader"],
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
    }

    assert extract_cve_references_from_urlhaus(record) == ["CVE-2024-1111", "CVE-2025-12345"]


def test_deterministic_negative_and_unknown_control_selection():
    provider = FileRelatedEvidenceProvider(urlhaus_records=_urlhaus_records())
    records = {
        "CVE-2025-3001": _nvd_record("CVE-2025-3001", "Unused product memory corruption."),
        "CVE-2025-3002": _nvd_record("CVE-2025-3002", "Windows loader remote code execution."),
    }

    negatives, unknowns = _select_controls(
        records,
        provider=provider,
        explicit_cves={"CVE-2025-1111"},
        positive_records={},
        negative_quota=1,
        unknown_quota=1,
    )

    assert [row["_id"] for row in negatives] == ["CVE-2025-3001"]
    assert [row["_id"] for row in unknowns] == ["CVE-2025-3002"]


def test_benchmark_definition_builds_reviewable_labels_without_network(tmp_path, monkeypatch):
    urlhaus_path = tmp_path / "urlhaus.json"
    negative_path = tmp_path / "negative_nvd.json"
    urlhaus_path.write_text(json.dumps(_urlhaus_records()), encoding="utf-8")
    negative_path.write_text(
        json.dumps(_nvd_payload([_nvd_record("CVE-2025-3001", "Unused product memory corruption.")])),
        encoding="utf-8",
    )

    def fake_load_nvd_cves(**kwargs):
        requested = kwargs["cve_ids"]
        records = {cve_id: _nvd_record(cve_id, f"{cve_id} remote code execution exploit loader.") for cve_id in requested}
        return SimpleNamespace(
            records=records,
            provenance=SimpleNamespace(to_dict=lambda: {"requested_cves": requested, "loaded_cves": sorted(records)}),
        )

    monkeypatch.setattr("evaluation.correlation_benchmark.load_nvd_cves", fake_load_nvd_cves)
    definition = build_correlation_benchmark_definition(
        urlhaus_path=urlhaus_path,
        cache_dir=tmp_path / "cache",
        output_dir=tmp_path / "out",
        nvd_output_path=tmp_path / "out" / "nvd.json",
        negative_nvd_path=negative_path,
        offline=True,
        generated_at=FIXED_NOW,
        unknown_quota=0,
    )

    assert definition["label_counts"] == {"confirmed_negative": 1, "confirmed_positive": 2}
    assert definition["records"][0]["label_provenance"]
    assert (tmp_path / "out" / "correlation_benchmark_definition.json").exists()
    assert (tmp_path / "out" / "correlation_ground_truth.json").exists()


def test_confusion_matrix_excludes_unknown_and_separates_manual_review():
    rows = [
        {"cve_id": "CVE-2025-1", "label": GroundTruthLabel.CONFIRMED_POSITIVE.value, "predicted_status": "accepted"},
        {"cve_id": "CVE-2025-2", "label": GroundTruthLabel.CONFIRMED_POSITIVE.value, "predicted_status": "rejected"},
        {"cve_id": "CVE-2025-3", "label": GroundTruthLabel.CONFIRMED_NEGATIVE.value, "predicted_status": "accepted"},
        {"cve_id": "CVE-2025-4", "label": GroundTruthLabel.CONFIRMED_NEGATIVE.value, "predicted_status": "zero_candidate"},
        {"cve_id": "CVE-2025-5", "label": GroundTruthLabel.UNKNOWN.value, "predicted_status": "accepted"},
        {"cve_id": "CVE-2025-6", "label": GroundTruthLabel.CONFIRMED_POSITIVE.value, "predicted_status": "manual_review"},
    ]

    metrics = _confusion_metrics(rows)

    assert metrics["true_positives"] == 1
    assert metrics["false_positives"] == 1
    assert metrics["true_negatives"] == 1
    assert metrics["false_negatives"] == 1
    assert metrics["unknown_excluded_count"] == 1
    assert metrics["manual_review_positive_count"] == 1
    assert metrics["precision"] == 0.5
    assert metrics["recall"] == 0.5
    assert metrics["f1"] == 0.5


def test_correlation_benchmark_run_outputs_artifacts(tmp_path):
    urlhaus_path = tmp_path / "urlhaus.json"
    definition_path = tmp_path / "definition.json"
    nvd_path = tmp_path / "nvd.json"
    urlhaus_path.write_text(json.dumps(_urlhaus_records()), encoding="utf-8")
    records = [
        _nvd_record("CVE-2025-1111", "CVE-2025-1111 remote code execution exploit loader."),
        _nvd_record("CVE-2025-3001", "Unused product memory corruption."),
    ]
    nvd_path.write_text(json.dumps(_nvd_payload(records)), encoding="utf-8")
    definition_path.write_text(
        json.dumps(
            {
                "version": "test",
                "records": [
                    {
                        "cve_id": "CVE-2025-1111",
                        "label": GroundTruthLabel.CONFIRMED_POSITIVE.value,
                        "label_reason": "exact CVE in URLhaus URL",
                        "label_provenance": {"source": "urlhaus"},
                    },
                    {
                        "cve_id": "CVE-2025-3001",
                        "label": GroundTruthLabel.CONFIRMED_NEGATIVE.value,
                        "label_reason": "control",
                        "label_provenance": {"source": "nvd"},
                    },
                ],
            }
        ),
        encoding="utf-8",
    )

    first = run_correlation_benchmark(
        benchmark_definition_path=definition_path,
        nvd_path=nvd_path,
        urlhaus_path=urlhaus_path,
        output_dir=tmp_path / "first",
        cache_dir=tmp_path / "cache",
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )
    second = run_correlation_benchmark(
        benchmark_definition_path=definition_path,
        nvd_path=nvd_path,
        urlhaus_path=urlhaus_path,
        output_dir=tmp_path / "second",
        cache_dir=tmp_path / "cache",
        generated_at=FIXED_NOW,
        reference_time=FIXED_NOW,
    )

    assert first["benchmark"]["record_count"] == 2
    assert first["correlation_evaluation"]["true_positives"] >= 1
    assert first["records"] == second["records"]
    for name in (
        "correlation_benchmark_definition.json",
        "correlation_ground_truth.json",
        "correlation_evaluation.json",
        "correlation_records.csv",
        "paired_model_results.json",
        "ranking_comparison.csv",
        "false_positive_cases.json",
        "false_negative_cases.json",
        "correlation_case_candidates.json",
        "run_metadata.json",
    ):
        assert (tmp_path / "first" / name).exists()
