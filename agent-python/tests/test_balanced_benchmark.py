import json

from evaluation.balanced_benchmark import (
    BALANCED_BENCHMARK_VERSION,
    BalancedBenchmarkConfig,
    ablation_variants,
    build_ablation_report,
    build_balanced_benchmark_definition,
    run_balanced_benchmark,
)
from evaluation.datasets import EvaluationRecord


FIXED_NOW = "2026-06-10T00:00:00+00:00"


def _nvd_record(cve_id, cvss, published="2024-01-01T00:00:00.000"):
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "lastModified": published,
            "descriptions": [{"lang": "en", "value": f"Official-format test CVE record for {cve_id}."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": cvss, "baseSeverity": "HIGH"}}]},
        }
    }


def _fixture_payload():
    rows = []
    kev = {}
    epss_lines = ["cve,epss,percentile"]
    # 25 KEV positives.
    for index in range(25):
        cve = f"CVE-2024-{10000 + index}"
        rows.append(_nvd_record(cve, 9.8))
        kev[cve] = {"cveID": cve, "vendorProject": "Vendor", "product": "Product", "vulnerabilityName": cve, "dateAdded": "2024-01-01"}
        epss_lines.append(f"{cve},{0.95 - (index * 0.001):.3f},0.99")
    # 10 high EPSS non-KEV.
    for index in range(10):
        cve = f"CVE-2024-{10100 + index}"
        rows.append(_nvd_record(cve, 7.5))
        epss_lines.append(f"{cve},{0.90 - (index * 0.001):.3f},0.98")
    # 10 high CVSS, low EPSS non-KEV.
    for index in range(10):
        cve = f"CVE-2024-{10200 + index}"
        rows.append(_nvd_record(cve, 9.8))
        epss_lines.append(f"{cve},{0.05 + (index * 0.001):.3f},0.20")
    # 10 medium controls.
    for index in range(10):
        cve = f"CVE-2024-{10300 + index}"
        rows.append(_nvd_record(cve, 5.5))
        epss_lines.append(f"{cve},{0.10 + (index * 0.001):.3f},0.30")
    # 5 older controls.
    for index in range(5):
        cve = f"CVE-2014-{10400 + index}"
        rows.append(_nvd_record(cve, 8.0, published="2014-01-01T00:00:00.000"))
        epss_lines.append(f"{cve},{0.15 + (index * 0.001):.3f},0.40")
    return {"vulnerabilities": rows}, {"vulnerabilities": list(kev.values())}, "\n".join(epss_lines)


def _write_fixture_files(tmp_path):
    nvd, kev, epss = _fixture_payload()
    nvd_path = tmp_path / "nvd.json"
    kev_path = tmp_path / "kev.json"
    epss_path = tmp_path / "epss.csv"
    nvd_path.write_text(json.dumps(nvd), encoding="utf-8")
    kev_path.write_text(json.dumps(kev), encoding="utf-8")
    epss_path.write_text(epss, encoding="utf-8")
    return nvd_path, kev_path, epss_path


def _model_rows(cve_ids):
    rows = []
    for index, cve_id in enumerate(cve_ids):
        rows.append(
            {
                "cve_id": cve_id,
                "risk_score": round(8.0 - (index * 0.01), 2),
                "confidence": 0.8,
                "cvss_score": 9.0,
                "evidence": {"related_urlhaus_count": 1 if index < 6 else 0, "related_dread_count": 0},
                "feature_breakdown": {
                    "raw_score_before_clamp": 8.0,
                    "recentness_bonus": 1.0,
                    "age_penalty": 0.25,
                    "urlhaus_correlation_bonus": 0.8 if index < 6 else 0.0,
                    "dread_correlation_bonus": 0.0,
                    "graph_bonus": 0.4,
                },
            }
        )
    return rows


def test_balanced_selection_is_deterministic_and_materially_balanced(tmp_path):
    nvd_path, kev_path, epss_path = _write_fixture_files(tmp_path)

    first = build_balanced_benchmark_definition(nvd_path=nvd_path, kev_path=kev_path, epss_path=epss_path, generated_at=FIXED_NOW)
    second = build_balanced_benchmark_definition(nvd_path=nvd_path, kev_path=kev_path, epss_path=epss_path, generated_at=FIXED_NOW)

    assert first == second
    assert first["version"] == BALANCED_BENCHMARK_VERSION
    assert first["record_count"] == 60
    assert first["kev_count"] == 25
    assert first["non_kev_count"] == 35
    assert first["bucket_counts"] == {
        "high_cvss_low_epss_non_kev": 10,
        "high_epss_non_kev": 10,
        "kev_positive": 25,
        "medium_severity_control": 10,
        "older_control": 5,
    }
    assert len({row["cve_id"] for row in first["records"]}) == 60


def test_selection_tie_breaking_uses_cve_id(tmp_path):
    nvd_path, kev_path, epss_path = _write_fixture_files(tmp_path)
    config = BalancedBenchmarkConfig(kev_positive_quota=3, high_epss_non_kev_quota=0, high_cvss_low_epss_non_kev_quota=0, medium_severity_control_quota=0, older_control_quota=0)

    definition = build_balanced_benchmark_definition(nvd_path=nvd_path, kev_path=kev_path, epss_path=epss_path, generated_at=FIXED_NOW, config=config)

    assert [row["cve_id"] for row in definition["records"]] == ["CVE-2024-10000", "CVE-2024-10001", "CVE-2024-10002"]


def test_ablation_calculation_and_unsupported_reporting():
    record = EvaluationRecord(
        cve_id="CVE-2024-10000",
        model_risk_score=8.0,
        model_confidence=0.5,
        cvss_score=9.0,
        is_kev=True,
        feature_breakdown={
            "raw_score_before_clamp": 8.0,
            "recentness_bonus": 1.0,
            "age_penalty": 0.25,
            "urlhaus_correlation_bonus": 0.8,
            "dread_correlation_bonus": 0.2,
            "graph_bonus": 0.4,
        },
    )
    report = build_ablation_report([record], k_values=[1])

    assert report["supported"]["without_temporal"]["ranking"] == ["CVE-2024-10000"]
    assert report["supported"]["confidence_weighted_full_model"]["metrics"]["precision_at_1"] == 1.0
    assert report["unsupported"]["without_external_evidence"]["status"] == "unsupported"
    assert "requires recomputation" in report["unsupported"]["without_external_evidence"]["reason"]
    assert "without_graph" in ablation_variants()


def test_missing_component_marks_ablation_unsupported():
    record = EvaluationRecord(cve_id="CVE-2024-10000", model_risk_score=8.0, model_confidence=0.5, cvss_score=9.0, feature_breakdown={})

    report = build_ablation_report([record], k_values=[1])

    assert report["unsupported"]["without_graph"]["status"] == "unsupported"
    assert report["unsupported"]["without_graph"]["missing_cve_ids"] == ["CVE-2024-10000"]


def test_balanced_benchmark_artifacts_metrics_and_diagnostics(tmp_path):
    nvd_path, kev_path, epss_path = _write_fixture_files(tmp_path)
    definition_path = tmp_path / "balanced_benchmark_definition.json"
    definition = build_balanced_benchmark_definition(
        nvd_path=nvd_path,
        kev_path=kev_path,
        epss_path=epss_path,
        output_path=definition_path,
        generated_at=FIXED_NOW,
    )
    model_path = tmp_path / "model_results.json"
    model_path.write_text(json.dumps({"records": _model_rows([row["cve_id"] for row in definition["records"]])}), encoding="utf-8")

    report = run_balanced_benchmark(
        benchmark_definition_path=definition_path,
        model_results_path=model_path,
        output_dir=tmp_path / "out",
        generated_at=FIXED_NOW,
    )

    assert report["model_results"]["matched_count"] == 60
    assert report["diagnostics"]["warnings"] == []
    assert report["diagnostics"]["correlation_subset"]["status"] == "validated"
    assert "model_risk" in report["baselines"]
    assert "without_temporal" in report["ablations"]["supported"]
    assert "without_external_evidence" in report["ablations"]["unsupported"]
    assert report["case_candidates"]["strongest_model_vs_cvss_disagreement"]["cve_id"]
    for name in (
        "balanced_benchmark_definition.json",
        "benchmark_summary.json",
        "benchmark_records.csv",
        "baseline_metrics.csv",
        "ablation_metrics.csv",
        "ablation_records.csv",
        "benchmark_diagnostics.json",
        "case_candidates.json",
    ):
        assert (tmp_path / "out" / name).exists()


def test_class_balance_warning_for_skewed_small_definition(tmp_path):
    nvd_path, kev_path, epss_path = _write_fixture_files(tmp_path)
    config = BalancedBenchmarkConfig(kev_positive_quota=5, high_epss_non_kev_quota=0, high_cvss_low_epss_non_kev_quota=0, medium_severity_control_quota=0, older_control_quota=0)
    definition_path = tmp_path / "definition.json"
    definition = build_balanced_benchmark_definition(
        nvd_path=nvd_path,
        kev_path=kev_path,
        epss_path=epss_path,
        output_path=definition_path,
        generated_at=FIXED_NOW,
        config=config,
    )
    model_path = tmp_path / "model_results.json"
    model_path.write_text(json.dumps({"records": _model_rows([row["cve_id"] for row in definition["records"]])}), encoding="utf-8")

    report = run_balanced_benchmark(benchmark_definition_path=definition_path, model_results_path=model_path, output_dir=tmp_path / "out", generated_at=FIXED_NOW)

    assert "benchmark_size_below_requested_minimum" in report["diagnostics"]["warnings"]
    assert "kev_class_imbalance_may_make_metrics_misleading" in report["diagnostics"]["warnings"]
