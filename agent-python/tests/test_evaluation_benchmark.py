import json

from evaluation.ablation import AblationVariant, evaluate_ablations
from evaluation.baselines import default_ranking_strategies, rank_records
from evaluation.datasets import (
    EvaluationRecord,
    join_external_signals,
    records_from_model_results,
)
from evaluation.epss import parse_epss_csv
from evaluation.kev import parse_kev_json
from evaluation.metrics import (
    kev_hit_rate_at_k,
    mean_reciprocal_rank,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    spearman_rank_correlation,
)
from evaluation.runner import build_evaluation_report


def _records():
    return [
        EvaluationRecord("CVE-2026-0001", 9.0, 0.9, 7.0, epss_score=0.8, is_kev=True),
        EvaluationRecord("CVE-2026-0002", 5.0, 0.5, 9.0, epss_score=0.2),
        EvaluationRecord("CVE-2026-0003", 7.0, 0.8, 4.0, epss_score=0.9, exploitation_evidence={"urlhaus": True}),
        EvaluationRecord("CVE-2026-0004", 2.0, 0.4, 3.0, epss_score=None),
    ]


def test_parse_kev_json_handles_duplicates_missing_and_malformed_rows():
    result = parse_kev_json(
        {
            "vulnerabilities": [
                {"cveID": "CVE-2026-0001", "dateAdded": "2026-01-01", "vendorProject": "Vendor"},
                {"cveID": "CVE-2026-0001", "dateAdded": "2026-01-02"},
                {"cveID": "not-a-cve"},
                "bad-row",
            ]
        }
    )

    assert list(result.items) == ["CVE-2026-0001"]
    assert result.total_rows == 4
    assert result.valid_rows == 1
    assert result.duplicate_rows == 1
    assert result.missing_required_rows == 1
    assert result.malformed_rows == 1
    assert result.items["CVE-2026-0001"].date_added == "2026-01-01"


def test_parse_epss_csv_normalizes_duplicates_missing_and_malformed_rows():
    result = parse_epss_csv(
        """# generated metadata
cve,epss,percentile
CVE-2026-0001,0.2,0.7
CVE-2026-0001,0.9,0.8
CVE-2026-0002,bad,0.4
not-a-cve,0.1,0.2
CVE-2026-0003,1.4,-0.5
"""
    )

    assert result.total_rows == 5
    assert result.valid_rows == 2
    assert result.duplicate_rows == 1
    assert result.malformed_rows == 1
    assert result.missing_required_rows == 1
    assert result.items["CVE-2026-0001"].epss == 0.9
    assert result.items["CVE-2026-0003"].epss == 1.0
    assert result.items["CVE-2026-0003"].percentile == 0.0


def test_model_records_join_with_kev_and_epss():
    model_records, stats = records_from_model_results(
        [
            {"cve_id": "CVE-2026-0001", "risk_score": 8, "confidence": 0.7, "cvss_score": 9.8},
            {"cve_id": "CVE-2026-0001", "risk_score": 7, "confidence": 0.7, "cvss_score": 9.8},
            {"cve_id": "bad", "risk_score": 1},
        ]
    )
    kev = parse_kev_json({"vulnerabilities": [{"cveID": "CVE-2026-0001"}]}).items
    epss = parse_epss_csv("cve,epss,percentile\nCVE-2026-0001,0.42,0.88\n").items

    joined = join_external_signals(model_records, kev, epss)

    assert stats == {"total_rows": 3, "valid_rows": 1, "duplicate_rows": 1, "malformed_rows": 1}
    assert joined[0].is_kev is True
    assert joined[0].epss_score == 0.42
    assert joined[0].epss_percentile == 0.88


def test_deterministic_ranking_and_tie_handling():
    tied = [
        EvaluationRecord("CVE-2026-0002", 5.0, 0.5, 7.0),
        EvaluationRecord("CVE-2026-0001", 5.0, 0.5, 7.0),
    ]

    ranked = rank_records(tied, lambda record: record.model_risk_score)

    assert [record.cve_id for record in ranked] == ["CVE-2026-0001", "CVE-2026-0002"]


def test_metrics_cover_precision_recall_ndcg_mrr_kev_and_spearman():
    rows = _records()
    ranked = rank_records(rows, lambda record: record.model_risk_score)

    assert precision_at_k(ranked, 2) == 1.0
    assert recall_at_k(ranked, rows, 2) == 1.0
    assert ndcg_at_k(ranked, 3) > 0.0
    assert mean_reciprocal_rank(ranked) == 1.0
    assert kev_hit_rate_at_k(ranked, 2) == 0.5
    assert spearman_rank_correlation(rows, lambda record: record.model_risk_score, lambda record: record.cvss_score) < 1.0


def test_metrics_handle_empty_and_large_k():
    rows = []

    assert precision_at_k(rows, 10) == 0.0
    assert recall_at_k(rows, rows, 10) == 0.0
    assert ndcg_at_k(rows, 10) == 0.0
    assert mean_reciprocal_rank(rows) == 0.0
    assert spearman_rank_correlation(rows, lambda record: 0.0, lambda record: 0.0) == 0.0

    non_empty = _records()
    ranked = rank_records(non_empty, lambda record: record.model_risk_score)
    assert precision_at_k(ranked, 100) == 0.5


def test_default_baselines_are_deterministic_and_include_expected_strategies():
    rows = _records()
    strategies = default_ranking_strategies(confidence_threshold=0.6)
    names = [strategy.name for strategy in strategies]

    assert names == [
        "cvss_only",
        "epss_only",
        "cvss_epss",
        "kev_first",
        "model_risk",
        "model_confidence_weighted",
        "signal_based_model",
        "model_confidence_filtered",
    ]
    assert [record.cve_id for record in strategies[0].rank(rows)] == [
        "CVE-2026-0002",
        "CVE-2026-0001",
        "CVE-2026-0003",
        "CVE-2026-0004",
    ]


def test_ablation_comparison_uses_explicit_score_variants():
    rows = [
        EvaluationRecord(
            "CVE-2026-0001",
            8.0,
            0.9,
            9.0,
            is_kev=True,
            feature_breakdown={"score_without_graph": 4.0},
        ),
        EvaluationRecord(
            "CVE-2026-0002",
            7.0,
            0.8,
            8.0,
            feature_breakdown={"score_without_graph": 9.0},
        ),
    ]

    result = evaluate_ablations(
        rows,
        [AblationVariant("without_graph", lambda record: record.feature_breakdown["score_without_graph"])],
        k_values=[1],
    )

    assert result["without_graph"]["precision_at_1"] == 0.0
    assert result["without_graph"]["recall_at_1"] == 0.0


def test_structured_report_serializes_with_metadata_and_baselines():
    report = build_evaluation_report(
        model_results=[
            {"cve_id": "CVE-2026-0001", "risk_score": 8.0, "confidence": 0.9, "cvss_score": 9.8},
            {"cve_id": "CVE-2026-0002", "risk_score": 4.0, "confidence": 0.5, "cvss_score": 5.0},
        ],
        kev_loader=lambda: {"vulnerabilities": [{"cveID": "CVE-2026-0001"}]},
        epss_loader=lambda: "cve,epss,percentile\nCVE-2026-0001,0.7,0.9\n",
        k_values=[1, 5],
        generated_at="2026-06-10T00:00:00+00:00",
    )

    assert report["generated_at"] == "2026-06-10T00:00:00+00:00"
    assert report["dataset"]["record_count"] == 2
    assert report["dataset"]["kev_count"] == 1
    assert report["dataset"]["missing_epss_count"] == 1
    assert "cvss_only" in report["baselines"]
    assert "precision_at_1" in report["baselines"]["model_risk"]["metrics"]
    json.dumps(report)
