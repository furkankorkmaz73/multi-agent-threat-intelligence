from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from statistics import mean
from typing import Any, Iterable, Mapping, Sequence

from evaluation.balanced_benchmark import build_ablation_report
from evaluation.datasets import EvaluationRecord, safe_float
from evaluation.runner import write_report_json


DEFAULT_SCENARIO_REPORT = Path("reports/thesis_scenario_report.json")
DEFAULT_OUTPUT_DIR = Path("reports/thesis")
THESIS_ARTIFACT_VERSION = "thesis-artifacts-v1"
SCORING_DISTRIBUTION_FIELDS = [
    "cve_id",
    "cvss_score",
    "epss_score",
    "is_kev",
    "risk_score",
    "confidence",
    "risk_level",
    "severity_signal",
    "epss_signal",
    "kev_signal",
    "recency_signal",
    "correlation_signal",
    "graph_signal",
    "nlp_context_signal",
    "fixture_rationale",
]


def generate_thesis_artifacts(
    *,
    scenario_report_path: str | Path = DEFAULT_SCENARIO_REPORT,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Any]:
    scenario_path = Path(scenario_report_path)
    scenario = json.loads(scenario_path.read_text(encoding="utf-8"))

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    evaluation = dict(scenario.get("evaluation") or {})
    records = _evaluation_records(evaluation.get("records") or [])

    k_values = evaluation.get("metric_config", {}).get("k_values") or [1, 3, 5, 10]
    if records:
        ablation_report = build_ablation_report(records, k_values=k_values)
    else:
        ablation_report = {
            "supported": {},
            "unsupported": {
                "no_records": {
                    "status": "unsupported",
                    "reason": "No evaluation records available.",
                }
            },
        }

    files = {
        "scoring_summary": output / "scoring_summary.md",
        "scoring_distribution": output / "scoring_distribution.csv",
        "scoring_distribution_md": output / "scoring_distribution.md",
        "benchmark_summary": output / "benchmark_summary.csv",
        "benchmark_summary_md": output / "benchmark_summary.md",
        "ablation_summary": output / "ablation_summary.csv",
        "ablation_summary_md": output / "ablation_summary.md",
        "correlation_decisions": output / "correlation_decisions.csv",
        "case_studies": output / "case_studies.json",
        "methodology_summary": output / "methodology_summary.md",
        "manifest": output / "manifest.json",
    }

    files["scoring_summary"].write_text(
        _scoring_summary_markdown(scenario, records),
        encoding="utf-8",
    )
    scoring_distribution_rows = _scoring_distribution_rows(records)
    _write_csv(scoring_distribution_rows, files["scoring_distribution"], SCORING_DISTRIBUTION_FIELDS)
    files["scoring_distribution_md"].write_text(
        _scoring_distribution_markdown(records, scoring_distribution_rows),
        encoding="utf-8",
    )
    _write_benchmark_summary(evaluation.get("baselines") or {}, files["benchmark_summary"])
    files["benchmark_summary_md"].write_text(
        _benchmark_summary_markdown(evaluation.get("baselines") or {}, records),
        encoding="utf-8",
    )
    _write_ablation_summary(ablation_report, files["ablation_summary"])
    files["ablation_summary_md"].write_text(
        _ablation_summary_markdown(ablation_report),
        encoding="utf-8",
    )
    _write_correlation_decisions(
        scenario.get("correlation_decisions") or [],
        files["correlation_decisions"],
    )
    write_report_json({"cases": scenario.get("notable_cases") or []}, files["case_studies"])
    files["methodology_summary"].write_text(_methodology_summary_markdown(), encoding="utf-8")

    manifest = {
        "version": THESIS_ARTIFACT_VERSION,
        "scenario_report_path": str(scenario_report_path),
        "output_dir": str(output),
        "generated_files": {
            name: str(path)
            for name, path in files.items()
            if name != "manifest"
        },
        "record_count": len(records),
        "correlation_decision_count": len(scenario.get("correlation_decisions") or []),
    }
    write_report_json(manifest, files["manifest"])
    return manifest


def _evaluation_records(rows: Iterable[Mapping[str, Any]]) -> list[EvaluationRecord]:
    records: list[EvaluationRecord] = []
    for row in rows:
        records.append(
            EvaluationRecord(
                cve_id=row["cve_id"],
                model_risk_score=safe_float(row.get("model_risk_score")),
                model_confidence=safe_float(row.get("model_confidence")),
                cvss_score=safe_float(row.get("cvss_score")),
                epss_score=row.get("epss_score"),
                epss_percentile=row.get("epss_percentile"),
                is_kev=bool(row.get("is_kev")),
                exploitation_evidence=row.get("exploitation_evidence") or {},
                feature_breakdown=row.get("feature_breakdown") or {},
            )
        )
    return records


def _scoring_summary_markdown(
    scenario: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
) -> str:
    rows = sorted(records, key=lambda record: (-record.model_risk_score, record.cve_id))

    cvss_rank = {
        record.cve_id: index + 1
        for index, record in enumerate(
            sorted(records, key=lambda record: (-record.cvss_score, record.cve_id))
        )
    }
    model_rank = {
        record.cve_id: index + 1
        for index, record in enumerate(rows)
    }

    disagreements = sorted(
        records,
        key=lambda record: (
            abs(model_rank[record.cve_id] - cvss_rank[record.cve_id]),
            record.cve_id,
        ),
        reverse=True,
    )[:5]

    level_counts: dict[str, int] = {}
    for record in records:
        level = _risk_level(record.model_risk_score)
        level_counts[level] = level_counts.get(level, 0) + 1

    lines = [
        "# Scoring Summary",
        "",
        "This artifact summarizes deterministic CVE risk outputs from the controlled thesis evaluation fixture.",
        "",
        f"- Total CVE count: {len(records)}",
        f"- KEV records: {sum(1 for record in records if record.is_kev)}",
        f"- Records with EPSS: {sum(1 for record in records if record.epss_score is not None)}",
        "- Risk level distribution: "
        + ", ".join(f"{level}={count}" for level, count in sorted(level_counts.items()))
        + ".",
        "",
        "## Top 10 Model-Risk CVEs",
        "",
        _markdown_table(
            [
                "Rank",
                "CVE",
                "Risk",
                "Level",
                "Confidence",
                "CVSS",
                "EPSS",
                "KEV",
                "URLhaus",
                "Dread",
            ],
            [
                [
                    index,
                    record.cve_id,
                    record.model_risk_score,
                    _risk_level(record.model_risk_score),
                    record.model_confidence,
                    record.cvss_score,
                    record.epss_score,
                    record.is_kev,
                    _feature_value(record, "related_urlhaus_count", 0),
                    _feature_value(record, "related_dread_count", 0),
                ]
                for index, record in enumerate(rows[:10], start=1)
            ],
            align=[
                "right",
                "left",
                "right",
                "left",
                "right",
                "right",
                "right",
                "left",
                "right",
                "right",
            ],
        ),
        "",
        "## Model Ranking Differs From CVSS-Only",
        "",
        _markdown_table(
            ["CVE", "Model Rank", "CVSS Rank", "Risk", "CVSS", "EPSS", "KEV", "Rationale"],
            [
                [
                    record.cve_id,
                    model_rank[record.cve_id],
                    cvss_rank[record.cve_id],
                    record.model_risk_score,
                    record.cvss_score,
                    record.epss_score,
                    record.is_kev,
                    _feature_value(record, "fixture_rationale", ""),
                ]
                for record in disagreements
            ],
            align=["left", "right", "right", "right", "right", "right", "left", "left"],
        ),
    ]
    return "\n".join(lines) + "\n"


def _scoring_distribution_rows(records: Sequence[EvaluationRecord]) -> list[dict[str, Any]]:
    rows = []
    for record in sorted(records, key=lambda item: item.cve_id):
        rows.append(
            {
                "cve_id": record.cve_id,
                "cvss_score": record.cvss_score,
                "epss_score": record.epss_score,
                "is_kev": record.is_kev,
                "risk_score": record.model_risk_score,
                "confidence": record.model_confidence,
                "risk_level": _risk_level(record.model_risk_score),
                "severity_signal": _feature_value(record, "severity_signal", ""),
                "epss_signal": _feature_value(record, "epss_signal", ""),
                "kev_signal": _feature_value(record, "kev_signal", ""),
                "recency_signal": _feature_value(record, "recency_signal", ""),
                "correlation_signal": _feature_value(record, "correlation_signal", ""),
                "graph_signal": _feature_value(record, "graph_signal", ""),
                "nlp_context_signal": _feature_value(record, "nlp_context_signal", ""),
                "fixture_rationale": _feature_value(record, "fixture_rationale", ""),
            }
        )
    return rows


def _scoring_distribution_markdown(records: Sequence[EvaluationRecord], rows: Sequence[Mapping[str, Any]]) -> str:
    risk_scores = [record.model_risk_score for record in records]
    level_counts: dict[str, int] = {}
    for record in records:
        level = _risk_level(record.model_risk_score)
        level_counts[level] = level_counts.get(level, 0) + 1

    model_ranked = sorted(records, key=lambda record: (-record.model_risk_score, record.cve_id))
    cvss_ranked = sorted(records, key=lambda record: (-record.cvss_score, record.cve_id))
    model_rank = {record.cve_id: index + 1 for index, record in enumerate(model_ranked)}
    cvss_rank = {record.cve_id: index + 1 for index, record in enumerate(cvss_ranked)}
    disagreements = sorted(
        records,
        key=lambda record: (abs(model_rank[record.cve_id] - cvss_rank[record.cve_id]), record.cve_id),
        reverse=True,
    )[:8]

    lines = [
        "# Scoring Distribution Review",
        "",
        f"- Total records: {len(records)}",
        "- Risk level distribution: "
        + ", ".join(f"{level}={count}" for level, count in sorted(level_counts.items()))
        + ".",
        f"- Minimum risk score: {min(risk_scores) if risk_scores else 0.0}",
        f"- Maximum risk score: {max(risk_scores) if risk_scores else 0.0}",
        f"- Mean risk score: {round(mean(risk_scores), 4) if risk_scores else 0.0}",
        "",
        "## Top 10 By Model Risk",
        "",
        _score_rank_table(model_ranked[:10], model_rank=model_rank, cvss_rank=cvss_rank),
        "",
        "## Top 10 By CVSS",
        "",
        _score_rank_table(cvss_ranked[:10], model_rank=model_rank, cvss_rank=cvss_rank),
        "",
        "## Model-Vs-CVSS Ranking Disagreements",
        "",
        _score_rank_table(disagreements, model_rank=model_rank, cvss_rank=cvss_rank),
        "",
        "## Sanity Check Notes",
        "",
        "- High CVSS remains meaningful risk even when EPSS, KEV, and accepted external evidence are weak.",
        "- Weak-confidence high-CVSS controls are not automatically treated as CRITICAL.",
        "- Medium-CVSS records with high EPSS and KEV can outrank high-CVSS records with weak exploitation evidence.",
        "- Accepted correlation, graph context, and recency are visible as bounded signal columns.",
        "- Risk score and confidence are reviewed separately; they should not be interpreted as the same value.",
        f"- CSV rows emitted: {len(rows)}.",
    ]
    return "\n".join(lines) + "\n"


def _score_rank_table(
    records: Sequence[EvaluationRecord],
    *,
    model_rank: Mapping[str, int],
    cvss_rank: Mapping[str, int],
) -> str:
    return _markdown_table(
        ["CVE", "Model Rank", "CVSS Rank", "Risk", "Confidence", "CVSS", "EPSS", "KEV", "Rationale"],
        [
            [
                record.cve_id,
                model_rank[record.cve_id],
                cvss_rank[record.cve_id],
                record.model_risk_score,
                record.model_confidence,
                record.cvss_score,
                record.epss_score,
                record.is_kev,
                _feature_value(record, "fixture_rationale", ""),
            ]
            for record in records
        ],
        align=["left", "right", "right", "right", "right", "right", "right", "left", "left"],
    )


def _methodology_summary_markdown() -> str:
    return "\n".join(
        [
            "# Methodology Summary",
            "",
            "Risk score represents prioritization and operational urgency. Confidence represents reliability of the supporting evidence.",
            "",
            "Normalized signals are bounded in [0, 1]: CVSS severity, EPSS exploit likelihood, CISA KEV listing, recency, accepted correlation support, graph context, and bounded intrinsic NLP context.",
            "",
            "Accepted correlations can increase risk and confidence. Rejected candidates and manual-review candidates remain diagnostic and do not increase risk.",
            "",
            "Dread is optional experimental intelligence and is disabled by default. Thesis artifacts are generated from deterministic fixtures and do not require live Dread crawling.",
            "",
            "The expanded deterministic fixture is a controlled thesis evaluation set. It is not a live threat-intelligence benchmark and should not be used to claim real-world prevalence or statistical significance.",
            "",
            "The fixture validates ranking behavior, ablation behavior, correlation decision exports, and artifact generation. Real-world validation should use larger NVD, EPSS, and CISA KEV exports.",
            "",
            "Citation placeholders: [CVSS-FIRST], [EPSS-FIRST], [CISA-KEV], [CISA-SSVC].",
        ]
    ) + "\n"


def _write_benchmark_summary(baselines: Mapping[str, Any], path: Path) -> None:
    rows = []
    for strategy, payload in sorted(baselines.items()):
        for metric, value in sorted((payload.get("metrics") or {}).items()):
            rows.append({"strategy": strategy, "metric": metric, "value": value})
    _write_csv(rows, path, ["strategy", "metric", "value"])


def _benchmark_summary_markdown(
    baselines: Mapping[str, Any],
    records: Sequence[EvaluationRecord],
) -> str:
    table_rows = []
    for strategy, payload in sorted(baselines.items()):
        metrics = payload.get("metrics") or {}
        ranking = payload.get("ranking") or []
        table_rows.append(
            [
                strategy,
                ", ".join(ranking[:5]),
                metrics.get("precision_at_5", ""),
                metrics.get("recall_at_5", ""),
                metrics.get("ndcg_at_5", ""),
                metrics.get("mean_kev_rank", ""),
            ]
        )

    return "\n".join(
        [
            "# Benchmark Summary",
            "",
            f"Controlled fixture size: {len(records)} CVEs.",
            "",
            _markdown_table(
                ["Strategy", "Top 5 CVEs", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank"],
                table_rows,
                align=["left", "left", "right", "right", "right", "right"],
            ),
        ]
    ) + "\n"


def _write_ablation_summary(report: Mapping[str, Any], path: Path) -> None:
    rows = []
    for variant, payload in sorted((report.get("supported") or {}).items()):
        for metric, value in sorted((payload.get("metrics") or {}).items()):
            rows.append(
                {
                    "variant": variant,
                    "status": payload.get("status"),
                    "metric": metric,
                    "value": value,
                    "reason": "",
                }
            )
    for variant, payload in sorted((report.get("unsupported") or {}).items()):
        rows.append(
            {
                "variant": variant,
                "status": payload.get("status"),
                "metric": "",
                "value": "",
                "reason": payload.get("reason"),
            }
        )
    _write_csv(rows, path, ["variant", "status", "metric", "value", "reason"])


def _ablation_summary_markdown(report: Mapping[str, Any]) -> str:
    table_rows = []

    for variant, payload in sorted((report.get("supported") or {}).items()):
        metrics = payload.get("metrics") or {}
        table_rows.append(
            [
                variant,
                payload.get("status"),
                metrics.get("precision_at_5", ""),
                metrics.get("recall_at_5", ""),
                metrics.get("ndcg_at_5", ""),
                metrics.get("mean_kev_rank", ""),
                "",
            ]
        )

    for variant, payload in sorted((report.get("unsupported") or {}).items()):
        table_rows.append(
            [
                variant,
                payload.get("status"),
                "",
                "",
                "",
                "",
                payload.get("reason"),
            ]
        )

    return "\n".join(
        [
            "# Ablation Summary",
            "",
            _markdown_table(
                ["Variant", "Status", "Precision@5", "Recall@5", "NDCG@5", "Mean KEV Rank", "Reason"],
                table_rows,
                align=["left", "left", "right", "right", "right", "right", "left"],
            ),
        ]
    ) + "\n"


def _write_correlation_decisions(decisions: Sequence[Mapping[str, Any]], path: Path) -> None:
    rows = []
    for decision in decisions:
        provenance = decision.get("provenance_summary") or {}
        rows.append(
            {
                "source_identifier": decision.get("source_identifier"),
                "target_identifier": decision.get("target_identifier"),
                "source": ",".join(provenance.get("sources") or []),
                "lexical_score": decision.get("lexical_score", ""),
                "semantic_score": decision.get("semantic_score", ""),
                "temporal_score": decision.get("temporal_score", ""),
                "entity_score": decision.get("entity_score", ""),
                "shared_term_count": decision.get("shared_term_count", ""),
                "exact_cve": decision.get("exact_cve", ""),
                "high_signal_term_hits": decision.get("high_signal_term_hits", ""),
                "decision": decision.get("decision") or decision.get("status"),
                "primary_reason": decision.get("primary_reason") or (decision.get("reasons") or [""])[0],
                "final_confidence": decision.get("final_confidence"),
            }
        )

    _write_csv(
        rows,
        path,
        [
            "source_identifier",
            "target_identifier",
            "source",
            "lexical_score",
            "semantic_score",
            "temporal_score",
            "entity_score",
            "shared_term_count",
            "exact_cve",
            "high_signal_term_hits",
            "decision",
            "primary_reason",
            "final_confidence",
        ],
    )


def _write_csv(rows: Iterable[Mapping[str, Any]], path: Path, fields: Sequence[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(fields))
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _markdown_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[Any]],
    *,
    align: Sequence[str],
) -> str:
    if len(headers) != len(align):
        raise ValueError("headers and align must have the same length")

    separator = []
    for item in align:
        if item == "right":
            separator.append("---:")
        elif item == "center":
            separator.append(":---:")
        else:
            separator.append("---")

    rendered = [
        _markdown_row(headers),
        _markdown_row(separator),
    ]

    for row in rows:
        if len(row) != len(headers):
            raise ValueError("row length must match header length")
        rendered.append(_markdown_row(row))

    return "\n".join(rendered)


def _markdown_row(values: Sequence[Any]) -> str:
    cells = [_markdown_cell(value) for value in values]
    return "| " + " | ".join(cells) + " |"


def _markdown_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip()


def _feature_value(record: EvaluationRecord, key: str, default: Any = "") -> Any:
    feature_breakdown = record.feature_breakdown or {}
    if key in feature_breakdown:
        return feature_breakdown.get(key, default)

    evidence = feature_breakdown.get("evidence") or {}
    if isinstance(evidence, Mapping):
        return evidence.get(key, default)

    return default


def _risk_level(score: float) -> str:
    if score >= 8.5:
        return "CRITICAL"
    if score >= 6.5:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate deterministic thesis artifact bundle")
    parser.add_argument("--scenario-report", default=str(DEFAULT_SCENARIO_REPORT))
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    manifest = generate_thesis_artifacts(
        scenario_report_path=args.scenario_report,
        output_dir=args.output_dir,
    )
    print(json.dumps({"output_dir": manifest["output_dir"], "record_count": manifest["record_count"]}, sort_keys=True))


if __name__ == "__main__":
    main()
