from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from analysis.correlator import build_correlation_decisions
from evaluation.evidence_inputs import DEFAULT_URLHAUS_CACHE_FILENAME, build_file_evidence_provider
from evaluation.model_export import run_model_export
from evaluation.nvd_cves import parse_nvd_cve_records
from evaluation.real_data import RealDataError
from evaluation.runner import load_model_results_json, write_report_json


DEFAULT_OUTPUT_DIR = Path("reports/real_benchmark/evidence")


def run_evidence_benchmark(
    *,
    benchmark_definition_path: str | Path,
    nvd_path: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    cache_dir: str | Path = ".cache/evidence_benchmark",
    baseline_model_results_path: str | Path | None = None,
    urlhaus_path: str | Path | None = None,
    dread_path: str | Path | None = None,
    refresh_urlhaus: bool = False,
    offline: bool = False,
    timeout_seconds: float = 60.0,
    generated_at: str | None = None,
    reference_time: str | None = None,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    benchmark_ids = _benchmark_ids(benchmark_definition_path)

    baseline_path = Path(baseline_model_results_path) if baseline_model_results_path else output / "cve-only" / "model_results.json"
    if baseline_model_results_path is None:
        run_model_export(
            cve_source_path=nvd_path,
            output_dir=baseline_path.parent,
            cache_dir=cache_dir,
            offline=True,
            generated_at=generated,
            reference_time=reference_time or generated,
            benchmark_definition_path=benchmark_definition_path,
        )

    cache_path = Path(cache_dir) / DEFAULT_URLHAUS_CACHE_FILENAME
    effective_urlhaus_path = Path(urlhaus_path) if urlhaus_path is not None else (cache_path if cache_path.exists() else None)
    evidence_export_dir = output / "evidence-enabled"
    evidence_export = run_model_export(
        cve_source_path=nvd_path,
        output_dir=evidence_export_dir,
        cache_dir=cache_dir,
        offline=offline,
        timeout_seconds=timeout_seconds,
        generated_at=generated,
        reference_time=reference_time or generated,
        benchmark_definition_path=benchmark_definition_path,
        urlhaus_evidence_path=effective_urlhaus_path,
        dread_evidence_path=dread_path,
        refresh_urlhaus_evidence=refresh_urlhaus,
    )
    evidence_path = Path(evidence_export["paths"]["model_results_json"])

    provider, evidence_inputs = build_file_evidence_provider(
        urlhaus_path=urlhaus_path,
        dread_path=dread_path,
        cache_dir=cache_dir,
        refresh_urlhaus=False,
        offline=True,
        timeout_seconds=timeout_seconds,
    )
    nvd_records, nvd_stats, malformed_nvd = parse_nvd_cve_records(Path(nvd_path).read_text(encoding="utf-8"))
    baseline_rows = _rows_by_cve(load_model_results_json(baseline_path), benchmark_ids)
    evidence_rows = _rows_by_cve(load_model_results_json(evidence_path), benchmark_ids)
    paired_rows = _paired_rows(benchmark_ids, baseline_rows, evidence_rows)
    decisions = _correlation_decisions(benchmark_ids, evidence_rows, nvd_records, provider)
    correlation_metrics = _correlation_metrics(decisions, paired_rows)
    coverage = _evidence_coverage(evidence_inputs, decisions, paired_rows)
    ranking_rows = _ranking_comparison(benchmark_ids, baseline_rows, evidence_rows)
    case_candidates = _case_candidates(paired_rows, ranking_rows, decisions)
    report = {
        "generated_at": generated,
        "benchmark_definition_path": str(benchmark_definition_path),
        "nvd_path": str(nvd_path),
        "baseline_model_results_path": str(baseline_path),
        "evidence_model_results_path": str(evidence_path),
        "benchmark_count": len(benchmark_ids),
        "coverage": coverage,
        "correlation_metrics": correlation_metrics,
        "paired_records": paired_rows,
        "ranking_comparison": ranking_rows,
        "case_candidates": case_candidates,
        "correlation_decisions": decisions,
        "run_metadata": {
            "generated_at": generated,
            "reference_time": reference_time or generated,
            "nvd_parse": nvd_stats,
            "nvd_malformed_records": malformed_nvd,
            "baseline_export_reused": baseline_model_results_path is not None,
            "evidence_inputs": evidence_inputs,
            "evidence_export_coverage": evidence_export.get("coverage", {}),
        },
    }
    _write_artifacts(report, output)
    return _stable_json(report)


def _benchmark_ids(path: str | Path) -> list[str]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return [str(row["cve_id"]) for row in payload.get("records", []) if row.get("cve_id")]


def _rows_by_cve(rows: Iterable[Mapping[str, Any]], benchmark_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    wanted = set(benchmark_ids)
    return {str(row.get("cve_id") or row.get("entity_id")): dict(row) for row in rows if str(row.get("cve_id") or row.get("entity_id")) in wanted}


def _paired_rows(benchmark_ids: Sequence[str], baseline: Mapping[str, Mapping[str, Any]], evidence: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for cve_id in benchmark_ids:
        left = dict(baseline.get(cve_id) or {})
        right = dict(evidence.get(cve_id) or {})
        left_evidence = dict(left.get("evidence") or {})
        right_evidence = dict(right.get("evidence") or {})
        left_graph = dict(left.get("graph_summary") or {})
        right_graph = dict(right.get("graph_summary") or {})
        rows.append(
            {
                "cve_id": cve_id,
                "has_baseline_result": bool(left),
                "has_evidence_result": bool(right),
                "baseline_risk_score": _float(left.get("risk_score")),
                "evidence_risk_score": _float(right.get("risk_score")),
                "risk_score_delta": round(_float(right.get("risk_score")) - _float(left.get("risk_score")), 6) if left and right else None,
                "baseline_confidence": _float(left.get("confidence")),
                "evidence_confidence": _float(right.get("confidence")),
                "confidence_delta": round(_float(right.get("confidence")) - _float(left.get("confidence")), 6) if left and right else None,
                "baseline_related_urlhaus_count": int(left_evidence.get("related_urlhaus_count") or 0),
                "evidence_related_urlhaus_count": int(right_evidence.get("related_urlhaus_count") or 0),
                "baseline_related_dread_count": int(left_evidence.get("related_dread_count") or 0),
                "evidence_related_dread_count": int(right_evidence.get("related_dread_count") or 0),
                "baseline_graph_edges": int(left_graph.get("edge_count") or 0),
                "evidence_graph_edges": int(right_graph.get("edge_count") or 0),
                "graph_edge_delta": int(right_graph.get("edge_count") or 0) - int(left_graph.get("edge_count") or 0) if left and right else None,
                "baseline_cross_source_edges": int(left_graph.get("cross_source_edge_count") or 0),
                "evidence_cross_source_edges": int(right_graph.get("cross_source_edge_count") or 0),
                "cross_source_edge_delta": int(right_graph.get("cross_source_edge_count") or 0) - int(left_graph.get("cross_source_edge_count") or 0) if left and right else None,
            }
        )
    return rows


def _correlation_decisions(
    benchmark_ids: Sequence[str],
    evidence_rows: Mapping[str, Mapping[str, Any]],
    nvd_records: Mapping[str, Mapping[str, Any]],
    provider: Any,
) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for cve_id in benchmark_ids:
        row = dict(evidence_rows.get(cve_id) or {})
        evidence = dict(row.get("evidence") or {})
        keywords = list(evidence.get("keywords") or [])
        published = (nvd_records.get(cve_id) or {}).get("published")
        urlhaus_matches = provider.find_related_urlhaus(keywords, limit=25) if keywords else []
        dread_matches = provider.find_related_dread(keywords, limit=25) if keywords else []
        urlhaus_decisions = [decision.to_dict() for decision in build_correlation_decisions(urlhaus_matches, keywords, published, source="urlhaus")]
        dread_decisions = [decision.to_dict() for decision in build_correlation_decisions(dread_matches, keywords, published, source="dread")]
        out[cve_id] = {
            "urlhaus": {
                "candidate_count": len(urlhaus_matches),
                "decisions": urlhaus_decisions,
                "status_counts": _status_counts(urlhaus_decisions),
            },
            "dread": {
                "candidate_count": len(dread_matches),
                "decisions": dread_decisions,
                "status_counts": _status_counts(dread_decisions),
            },
        }
    return out


def _status_counts(decisions: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"accepted": 0, "rejected": 0, "manual_review": 0}
    for decision in decisions:
        status = str(decision.get("status"))
        if status in counts:
            counts[status] += 1
    return counts


def _correlation_metrics(decisions: Mapping[str, Any], paired_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    totals = {"accepted": 0, "rejected": 0, "manual_review": 0, "urlhaus_candidates": 0, "dread_candidates": 0, "exact_cve_matches": 0}
    cves = {"accepted": [], "rejected": [], "manual_review": [], "zero_evidence": []}
    for cve_id, payload in decisions.items():
        per_cve = {"accepted": 0, "rejected": 0, "manual_review": 0}
        candidate_total = 0
        for source in ("urlhaus", "dread"):
            source_payload = payload.get(source, {})
            candidate_total += int(source_payload.get("candidate_count") or 0)
            totals[f"{source}_candidates"] += int(source_payload.get("candidate_count") or 0)
            counts = source_payload.get("status_counts", {}) or {}
            for status in per_cve:
                per_cve[status] += int(counts.get(status) or 0)
            for decision in source_payload.get("decisions", []) or []:
                if decision.get("status") == "accepted" and "exact_cve" in (decision.get("reasons") or []):
                    totals["exact_cve_matches"] += 1
        for status, count in per_cve.items():
            totals[status] += count
            if count:
                cves[status].append(cve_id)
        if candidate_total == 0:
            cves["zero_evidence"].append(cve_id)
    changed = [row for row in paired_rows if row.get("risk_score_delta") not in (None, 0)]
    return {
        "totals": totals,
        "cve_counts": {key: len(value) for key, value in cves.items()},
        "cves": cves,
        "risk_changed_cve_count": len(changed),
    }


def _evidence_coverage(evidence_inputs: Mapping[str, Any], decisions: Mapping[str, Any], paired_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    metrics = _correlation_metrics(decisions, paired_rows)
    zero = metrics["cves"]["zero_evidence"]
    return {
        "urlhaus": dict((evidence_inputs.get("urlhaus") or {}).get("provenance") or {}),
        "dread": dict((evidence_inputs.get("dread") or {}).get("provenance") or {}),
        "benchmark_cve_count": len(paired_rows),
        "cves_with_any_candidate": len(paired_rows) - len(zero),
        "cves_with_accepted_correlations": metrics["cve_counts"]["accepted"],
        "cves_with_manual_review_correlations": metrics["cve_counts"]["manual_review"],
        "cves_with_rejected_candidates": metrics["cve_counts"]["rejected"],
        "zero_evidence_cves": zero,
    }


def _ranking_comparison(benchmark_ids: Sequence[str], baseline: Mapping[str, Mapping[str, Any]], evidence: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    baseline_rank = _ranks(baseline)
    evidence_rank = _ranks(evidence)
    rows = []
    for cve_id in benchmark_ids:
        b_rank = baseline_rank.get(cve_id)
        e_rank = evidence_rank.get(cve_id)
        rows.append(
            {
                "cve_id": cve_id,
                "baseline_rank": b_rank,
                "evidence_rank": e_rank,
                "ranking_delta": (b_rank - e_rank) if b_rank is not None and e_rank is not None else None,
                "baseline_risk_score": _float((baseline.get(cve_id) or {}).get("risk_score")),
                "evidence_risk_score": _float((evidence.get(cve_id) or {}).get("risk_score")),
            }
        )
    return rows


def _ranks(rows: Mapping[str, Mapping[str, Any]]) -> dict[str, int]:
    ranked = sorted(rows.values(), key=lambda row: (-_float(row.get("risk_score")), str(row.get("cve_id") or row.get("entity_id"))))
    return {str(row.get("cve_id") or row.get("entity_id")): index + 1 for index, row in enumerate(ranked)}


def _case_candidates(
    paired_rows: Sequence[Mapping[str, Any]],
    ranking_rows: Sequence[Mapping[str, Any]],
    decisions: Mapping[str, Any],
) -> dict[str, Any]:
    ranking_by_cve = {row["cve_id"]: row for row in ranking_rows}
    rows = [dict(row, **{"ranking_delta": ranking_by_cve.get(row["cve_id"], {}).get("ranking_delta")}) for row in paired_rows]
    accepted = set(_correlation_metrics(decisions, paired_rows)["cves"]["accepted"])
    manual = set(_correlation_metrics(decisions, paired_rows)["cves"]["manual_review"])
    rejected = set(_correlation_metrics(decisions, paired_rows)["cves"]["rejected"])
    return {
        "strongest_risk_score_increase": _max_by(rows, lambda row: row.get("risk_score_delta")),
        "strongest_risk_score_decrease": _min_by(rows, lambda row: row.get("risk_score_delta")),
        "strongest_confidence_increase": _max_by(rows, lambda row: row.get("confidence_delta")),
        "strongest_ranking_improvement": _max_by(rows, lambda row: row.get("ranking_delta")),
        "strongest_ranking_regression": _min_by(rows, lambda row: row.get("ranking_delta")),
        "accepted_correlation_case": _first_case(rows, accepted),
        "manual_review_case": _first_case(rows, manual),
        "rejected_candidate_case": _first_case(rows, rejected),
        "zero_evidence_case": _first_case(rows, set(_correlation_metrics(decisions, paired_rows)["cves"]["zero_evidence"])),
    }


def _first_case(rows: Sequence[Mapping[str, Any]], cve_ids: set[str]) -> Mapping[str, Any] | None:
    for row in sorted(rows, key=lambda item: item.get("cve_id", "")):
        if row.get("cve_id") in cve_ids:
            return dict(row)
    return None


def _max_by(rows: Sequence[Mapping[str, Any]], key: Any) -> Mapping[str, Any] | None:
    candidates = [row for row in rows if key(row) is not None]
    return dict(max(candidates, key=lambda row: (key(row), row.get("cve_id", "")))) if candidates else None


def _min_by(rows: Sequence[Mapping[str, Any]], key: Any) -> Mapping[str, Any] | None:
    candidates = [row for row in rows if key(row) is not None]
    return dict(min(candidates, key=lambda row: (key(row), row.get("cve_id", "")))) if candidates else None


def _write_artifacts(report: Mapping[str, Any], output_dir: Path) -> dict[str, str]:
    paths = {
        "evidence_coverage": output_dir / "evidence_coverage.json",
        "paired_model_results": output_dir / "paired_model_results.json",
        "paired_model_results_csv": output_dir / "paired_model_results.csv",
        "correlation_decisions": output_dir / "correlation_decisions.json",
        "correlation_metrics": output_dir / "correlation_metrics.json",
        "ranking_comparison": output_dir / "ranking_comparison.csv",
        "evidence_case_candidates": output_dir / "evidence_case_candidates.json",
        "run_metadata": output_dir / "run_metadata.json",
    }
    write_report_json(report.get("coverage", {}), paths["evidence_coverage"])
    write_report_json({"generated_at": report.get("generated_at"), "records": report.get("paired_records", [])}, paths["paired_model_results"])
    _write_csv(report.get("paired_records", []), paths["paired_model_results_csv"])
    write_report_json(report.get("correlation_decisions", {}), paths["correlation_decisions"])
    write_report_json(report.get("correlation_metrics", {}), paths["correlation_metrics"])
    _write_csv(report.get("ranking_comparison", []), paths["ranking_comparison"])
    write_report_json(report.get("case_candidates", {}), paths["evidence_case_candidates"])
    write_report_json(report.get("run_metadata", {}), paths["run_metadata"])
    return {name: str(path) for name, path in paths.items()}


def _write_csv(rows: Iterable[Mapping[str, Any]], path: Path) -> None:
    rows = list(rows)
    fields = sorted({key for row in rows for key in row} or {"cve_id"})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _float(value: Any) -> float:
    try:
        if value in (None, ""):
            return 0.0
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _stable_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Run paired CVE-only versus evidence-enabled benchmark")
    parser.add_argument("--benchmark-definition", required=True)
    parser.add_argument("--nvd-file", required=True)
    parser.add_argument("--baseline-model-results", default=None)
    parser.add_argument("--urlhaus-file", default=None)
    parser.add_argument("--dread-file", default=None)
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--cache-dir", default=".cache/evidence_benchmark")
    parser.add_argument("--refresh-urlhaus", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--reference-time", default=None)
    args = parser.parse_args()
    try:
        report = run_evidence_benchmark(
            benchmark_definition_path=args.benchmark_definition,
            nvd_path=args.nvd_file,
            baseline_model_results_path=args.baseline_model_results,
            urlhaus_path=args.urlhaus_file,
            dread_path=args.dread_file,
            output_dir=args.output_dir,
            cache_dir=args.cache_dir,
            refresh_urlhaus=args.refresh_urlhaus,
            offline=args.offline,
            timeout_seconds=args.timeout_seconds,
            generated_at=args.generated_at,
            reference_time=args.reference_time,
        )
    except RealDataError as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "benchmark_count": report["benchmark_count"],
                "cves_with_accepted_correlations": report["coverage"]["cves_with_accepted_correlations"],
                "cves_with_any_candidate": report["coverage"]["cves_with_any_candidate"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
