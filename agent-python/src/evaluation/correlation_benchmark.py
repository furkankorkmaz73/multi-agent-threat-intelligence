from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from analysis.correlator import build_correlation_decisions
from analysis.nlp_features import extract_nlp_features
from evaluation.datasets import normalize_cve_id, safe_float
from evaluation.evidence_benchmark import _paired_rows, _ranking_comparison
from evaluation.evidence_inputs import (
    DEFAULT_URLHAUS_FULL_CACHE_FILENAME,
    FileRelatedEvidenceProvider,
    URLHAUS_JSON_FULL_URL,
    load_urlhaus_records,
)
from evaluation.model_export import run_model_export
from evaluation.nvd_cves import NVD_CVE_API_URL, load_nvd_cves, parse_nvd_cve_records
from evaluation.real_data import DataFormatError, DataUnavailableError, RealDataError
from evaluation.runner import load_model_results_json, write_report_json


VERSION = "correlation-focused-urlhaus-cve-benchmark-v1"
DEFAULT_OUTPUT_DIR = Path("reports/real_benchmark/correlation")
CVE_REF_RE = re.compile(r"CVE[-_ ]?(\d{4})[-_ ]?(\d{4,7})", re.I)


class GroundTruthLabel(str, Enum):
    CONFIRMED_POSITIVE = "confirmed_positive"
    LIKELY_POSITIVE = "likely_positive"
    CONFIRMED_NEGATIVE = "confirmed_negative"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LabelRule:
    label: GroundTruthLabel
    reason: str
    provenance: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"label": self.label.value, "reason": self.reason, "provenance": dict(self.provenance)}


def build_correlation_benchmark_definition(
    *,
    urlhaus_path: str | Path | None = None,
    cache_dir: str | Path,
    output_dir: str | Path,
    nvd_output_path: str | Path | None = None,
    negative_nvd_path: str | Path | None = None,
    refresh_urlhaus: bool = False,
    refresh_nvd: bool = False,
    offline: bool = False,
    timeout_seconds: float = 60.0,
    generated_at: str | None = None,
    positive_limit: int = 20,
    negative_quota: int | None = None,
    unknown_quota: int = 5,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    urlhaus = load_urlhaus_records(
        path=urlhaus_path,
        cache_dir=cache_dir,
        refresh=refresh_urlhaus,
        offline=offline,
        timeout_seconds=timeout_seconds,
        source_url=URLHAUS_JSON_FULL_URL,
        cache_filename=DEFAULT_URLHAUS_FULL_CACHE_FILENAME,
    )
    explicit = _urlhaus_explicit_cve_map(urlhaus.records)
    if not explicit:
        raise DataUnavailableError("Official URLhaus data contained no explicit CVE references")

    positive_cves = sorted(explicit)[:positive_limit]
    positive_nvd = load_nvd_cves(
        cve_ids=positive_cves,
        cache_dir=cache_dir,
        refresh=refresh_nvd,
        offline=offline,
        timeout_seconds=timeout_seconds,
    )
    recent_nvd = _load_recent_negative_nvd(negative_nvd_path, timeout_seconds=timeout_seconds, offline=offline)
    provider = FileRelatedEvidenceProvider(urlhaus_records=urlhaus.records)
    positive_records = dict(positive_nvd.records)
    target_negatives = negative_quota if negative_quota is not None else max(len(positive_records), 1)
    negatives, unknowns = _select_controls(
        recent_nvd,
        provider=provider,
        explicit_cves=set(explicit),
        positive_records=positive_records,
        negative_quota=target_negatives,
        unknown_quota=unknown_quota,
    )
    selected_records = {**positive_records, **{row["_id"]: row for row in negatives + unknowns}}
    if len(positive_records) == 0:
        raise DataUnavailableError("No official NVD metadata could be loaded for URLhaus explicit-CVE positives")

    definition_records = []
    for cve_id in sorted(positive_records):
        evidence_rows = explicit[cve_id]
        definition_records.append(
            _definition_row(
                cve_id=cve_id,
                nvd_record=positive_records[cve_id],
                label_rule=LabelRule(
                    GroundTruthLabel.CONFIRMED_POSITIVE,
                    "Exact CVE identifier appears in an official URLhaus URL, tag, or metadata field.",
                    {
                        "source": "urlhaus",
                        "source_url": URLHAUS_JSON_FULL_URL,
                        "urlhaus_references": [_urlhaus_reference(row) for row in evidence_rows[:8]],
                        "evidence_fields": _evidence_fields_for_cve(cve_id, evidence_rows),
                    },
                ),
                urlhaus_evidence=evidence_rows,
            )
        )
    for row in negatives:
        definition_records.append(
            _definition_row(
                cve_id=row["_id"],
                nvd_record=row,
                label_rule=LabelRule(
                    GroundTruthLabel.CONFIRMED_NEGATIVE,
                    "Recent official NVD control with no explicit CVE reference in official URLhaus; selected as a negative/control case. Lexical URLhaus candidates, if present, are treated as unrelated controls unless attributable CVE evidence exists.",
                    {"source": "nvd_urlhaus_control_selection", "source_url": NVD_CVE_API_URL},
                ),
                urlhaus_evidence=[],
            )
        )
    for row in unknowns:
        definition_records.append(
            _definition_row(
                cve_id=row["_id"],
                nvd_record=row,
                label_rule=LabelRule(
                    GroundTruthLabel.UNKNOWN,
                    "Recent official NVD control had lexical URLhaus candidates but no explicit attributable CVE relationship; excluded from ground-truth metrics.",
                    {"source": "nvd_urlhaus_candidate_control", "source_url": NVD_CVE_API_URL},
                ),
                urlhaus_evidence=[],
            )
        )

    definition_records = sorted(definition_records, key=lambda item: (item["label"], item["cve_id"]))
    definition = {
        "version": VERSION,
        "generated_at": generated,
        "selection_policy": {
            "positive_rule": "confirmed_positive when an exact CVE identifier appears in official URLhaus URL, tags, or metadata",
            "negative_rule": "confirmed_negative when selected recent NVD control has no explicit URLhaus CVE reference and no URLhaus candidate",
            "unknown_rule": "unknown when selected recent NVD control has lexical URLhaus candidates but no explicit attributable relationship",
            "tie_breaking": "ascending CVE ID after deterministic rule filters",
        },
        "record_count": len(definition_records),
        "label_counts": _count_by(definition_records, "label"),
        "source_provenance": {
            "urlhaus": dict(urlhaus.provenance),
            "positive_nvd": positive_nvd.provenance.to_dict(),
            "recent_negative_nvd": _recent_nvd_provenance(recent_nvd),
        },
        "records": definition_records,
    }
    nvd_path = Path(nvd_output_path) if nvd_output_path is not None else output / "correlation_nvd_records.json"
    _write_nvd_subset(selected_records.values(), nvd_path)
    definition["nvd_file"] = str(nvd_path)
    write_report_json(definition, output / "correlation_benchmark_definition.json")
    write_report_json(_ground_truth(definition_records), output / "correlation_ground_truth.json")
    return _stable_json(definition)


def run_correlation_benchmark(
    *,
    benchmark_definition_path: str | Path,
    nvd_path: str | Path,
    urlhaus_path: str | Path,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
    cache_dir: str | Path = ".cache/correlation_benchmark",
    generated_at: str | None = None,
    reference_time: str | None = None,
    timeout_seconds: float = 60.0,
) -> dict[str, Any]:
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    definition = json.loads(Path(benchmark_definition_path).read_text(encoding="utf-8"))
    records = list(definition.get("records", []))
    benchmark_ids = [row["cve_id"] for row in records]
    labels = {row["cve_id"]: row for row in records}
    urlhaus = load_urlhaus_records(path=urlhaus_path, cache_dir=cache_dir, offline=True, source_url=URLHAUS_JSON_FULL_URL, cache_filename=DEFAULT_URLHAUS_FULL_CACHE_FILENAME)
    provider = FileRelatedEvidenceProvider(urlhaus_records=urlhaus.records)
    nvd_records, nvd_stats, malformed_nvd = parse_nvd_cve_records(Path(nvd_path).read_text(encoding="utf-8"))

    baseline = run_model_export(
        cve_source_path=nvd_path,
        benchmark_definition_path=benchmark_definition_path,
        output_dir=output / "cve-only",
        cache_dir=cache_dir,
        offline=True,
        generated_at=generated,
        reference_time=reference_time or generated,
    )
    evidence = run_model_export(
        cve_source_path=nvd_path,
        benchmark_definition_path=benchmark_definition_path,
        output_dir=output / "urlhaus-enabled",
        cache_dir=cache_dir,
        offline=True,
        generated_at=generated,
        reference_time=reference_time or generated,
        urlhaus_evidence_path=urlhaus_path,
    )
    baseline_rows = _rows_by_cve(load_model_results_json(baseline["paths"]["model_results_json"]), benchmark_ids)
    evidence_rows = _rows_by_cve(load_model_results_json(evidence["paths"]["model_results_json"]), benchmark_ids)
    paired = _paired_rows(benchmark_ids, baseline_rows, evidence_rows)
    ranking = _ranking_comparison(benchmark_ids, baseline_rows, evidence_rows)
    decision_records = _evaluate_decisions(benchmark_ids, labels, nvd_records, evidence_rows, provider)
    evaluation = _confusion_metrics(decision_records)
    cases = _case_groups(decision_records, paired, ranking)
    report = {
        "generated_at": generated,
        "benchmark": {"version": definition.get("version"), "record_count": len(records), "label_counts": _count_by(records, "label")},
        "correlation_evaluation": evaluation,
        "records": decision_records,
        "paired_records": paired,
        "ranking_comparison": ranking,
        "case_candidates": cases,
        "run_metadata": {
            "generated_at": generated,
            "reference_time": reference_time or generated,
            "urlhaus_provenance": dict(urlhaus.provenance),
            "nvd_parse": nvd_stats,
            "nvd_malformed_records": malformed_nvd,
            "baseline_export_coverage": baseline.get("coverage", {}),
            "evidence_export_coverage": evidence.get("coverage", {}),
        },
    }
    _write_artifacts(report, definition, output)
    return _stable_json(report)


def _urlhaus_explicit_cve_map(records: Sequence[Mapping[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    refs: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        cves = extract_cve_references_from_urlhaus(record)
        for cve_id in cves:
            refs.setdefault(cve_id, []).append(dict(record))
    return refs


def extract_cve_references_from_urlhaus(record: Mapping[str, Any]) -> list[str]:
    values = [
        record.get("url"),
        record.get("threat"),
        record.get("urlhaus_reference"),
        record.get("urlhaus_link"),
        record.get("reporter"),
        " ".join(str(tag) for tag in (record.get("tags") or [])),
        (record.get("normalized_fields") or {}).get("search_text") if isinstance(record.get("normalized_fields"), Mapping) else None,
    ]
    found = []
    for match in CVE_REF_RE.finditer(" ".join(str(value or "") for value in values)):
        cve_id = normalize_cve_id(f"CVE-{match.group(1)}-{match.group(2)}")
        if cve_id:
            found.append(cve_id)
    return sorted(set(found))


def _load_recent_negative_nvd(path: str | Path | None, *, timeout_seconds: float, offline: bool) -> Mapping[str, dict[str, Any]]:
    if path is not None:
        records, _stats, _malformed = parse_nvd_cve_records(Path(path).read_text(encoding="utf-8"))
        return records
    if offline:
        raise DataUnavailableError("A negative NVD candidate file is required in offline mode")
    url = f"{NVD_CVE_API_URL}?{urlencode({'pubStartDate': '2025-01-01T00:00:00.000', 'pubEndDate': '2025-04-30T00:00:00.000', 'resultsPerPage': 200, 'startIndex': 0})}"
    try:
        request = Request(url, headers={"User-Agent": "multi-agent-threat-intelligence-correlation-benchmark/1.0"})
        with urlopen(request, timeout=timeout_seconds) as response:  # noqa: S310 - fixed official NVD URL
            payload = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        raise DataUnavailableError(f"Unable to download recent NVD controls: {exc}") from exc
    records, _stats, _malformed = parse_nvd_cve_records(payload)
    return records


def _select_controls(
    nvd_records: Mapping[str, Mapping[str, Any]],
    *,
    provider: FileRelatedEvidenceProvider,
    explicit_cves: set[str],
    positive_records: Mapping[str, Mapping[str, Any]],
    negative_quota: int,
    unknown_quota: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    negatives: list[dict[str, Any]] = []
    unknowns: list[dict[str, Any]] = []
    for cve_id in sorted(nvd_records):
        if cve_id in explicit_cves or cve_id in positive_records:
            continue
        record = dict(nvd_records[cve_id])
        description = _description(record)
        if not description or _invalid_description(description):
            continue
        keywords = extract_nlp_features(description, cve_id).all_terms[:18]
        candidates = provider.find_related_urlhaus(keywords, limit=25)
        if not candidates and len(negatives) < negative_quota:
            negatives.append(record)
        elif candidates and len(unknowns) < unknown_quota:
            unknowns.append(record)
        elif candidates and len(negatives) < negative_quota:
            negatives.append(record)
        if len(negatives) >= negative_quota and len(unknowns) >= unknown_quota:
            break
    return negatives, unknowns


def _definition_row(
    *,
    cve_id: str,
    nvd_record: Mapping[str, Any],
    label_rule: LabelRule,
    urlhaus_evidence: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "cve_id": cve_id,
        "label": label_rule.label.value,
        "label_reason": label_rule.reason,
        "label_provenance": dict(label_rule.provenance),
        "published": nvd_record.get("published"),
        "cvss_score": _extract_cvss(nvd_record),
        "urlhaus_evidence_count": len(urlhaus_evidence),
        "urlhaus_evidence": [_minimal_urlhaus(row) for row in urlhaus_evidence[:8]],
    }


def _evaluate_decisions(
    benchmark_ids: Sequence[str],
    labels: Mapping[str, Mapping[str, Any]],
    nvd_records: Mapping[str, Mapping[str, Any]],
    evidence_rows: Mapping[str, Mapping[str, Any]],
    provider: FileRelatedEvidenceProvider,
) -> list[dict[str, Any]]:
    rows = []
    for cve_id in benchmark_ids:
        label_row = labels[cve_id]
        record = nvd_records.get(cve_id, {})
        keywords = list((evidence_rows.get(cve_id, {}).get("evidence") or {}).get("keywords") or [])
        if not keywords:
            keywords = extract_nlp_features(_description(record), cve_id).all_terms[:18]
        matches = provider.find_related_urlhaus(keywords, limit=25)
        decisions = [decision.to_dict() for decision in build_correlation_decisions(matches, keywords, record.get("published"), source="urlhaus")]
        status_counts = _status_counts(decisions)
        predicted = "accepted" if status_counts["accepted"] else "manual_review" if status_counts["manual_review"] else "rejected" if matches else "zero_candidate"
        rows.append(
            {
                "cve_id": cve_id,
                "label": label_row.get("label"),
                "label_reason": label_row.get("label_reason"),
                "candidate_count": len(matches),
                "predicted_status": predicted,
                "accepted_count": status_counts["accepted"],
                "manual_review_count": status_counts["manual_review"],
                "rejected_count": status_counts["rejected"],
                "exact_cve_decision_count": sum(1 for decision in decisions if "exact_cve" in (decision.get("reasons") or [])),
                "decision_reasons": sorted({reason for decision in decisions for reason in (decision.get("reasons") or [])}),
                "shared_terms": sorted({term for decision in decisions for ev in decision.get("evidence_references", []) for term in ([ev.get("reason")] if ev.get("reason") else [])}),
                "decisions": decisions,
            }
        )
    return rows


def _confusion_metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    included = [row for row in rows if row.get("label") != GroundTruthLabel.UNKNOWN.value and row.get("predicted_status") != "manual_review"]
    manual = [row for row in rows if row.get("predicted_status") == "manual_review"]
    tp = sum(1 for row in included if _is_positive(row) and row.get("predicted_status") == "accepted")
    fp = sum(1 for row in included if _is_negative(row) and row.get("predicted_status") == "accepted")
    tn = sum(1 for row in included if _is_negative(row) and row.get("predicted_status") in {"rejected", "zero_candidate"})
    fn = sum(1 for row in included if _is_positive(row) and row.get("predicted_status") in {"rejected", "zero_candidate"})
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    return {
        "decision_counts": _count_by(rows, "predicted_status"),
        "label_counts": _count_by(rows, "label"),
        "included_ground_truth_count": len(included),
        "unknown_excluded_count": sum(1 for row in rows if row.get("label") == GroundTruthLabel.UNKNOWN.value),
        "manual_review_count": len(manual),
        "manual_review_positive_count": sum(1 for row in manual if _is_positive(row)),
        "true_positives": tp,
        "false_positives": fp,
        "true_negatives": tn,
        "false_negatives": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
    }


def _case_groups(
    rows: Sequence[Mapping[str, Any]],
    paired_rows: Sequence[Mapping[str, Any]],
    ranking_rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    paired = {row["cve_id"]: row for row in paired_rows}
    ranking = {row["cve_id"]: row for row in ranking_rows}

    def enrich(items: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for item in items:
            cve_id = item["cve_id"]
            out.append({**dict(item), "paired": dict(paired.get(cve_id, {})), "ranking": dict(ranking.get(cve_id, {}))})
        return sorted(out, key=lambda row: row["cve_id"])

    accepted_positives = [row for row in rows if _is_positive(row) and row.get("predicted_status") == "accepted"]
    rejected_positives = [row for row in rows if _is_positive(row) and row.get("predicted_status") in {"rejected", "zero_candidate"}]
    accepted_negatives = [row for row in rows if _is_negative(row) and row.get("predicted_status") == "accepted"]
    manual_positives = [row for row in rows if _is_positive(row) and row.get("predicted_status") == "manual_review"]
    lexical_false_positive = [row for row in rows if not _is_positive(row) and row.get("candidate_count", 0) > 0 and row.get("accepted_count", 0) == 0]
    zero_candidate = [row for row in rows if row.get("predicted_status") == "zero_candidate"]
    return {
        "accepted_confirmed_positives": enrich(accepted_positives),
        "rejected_confirmed_positives": enrich(rejected_positives),
        "accepted_negatives": enrich(accepted_negatives),
        "manual_review_positives": enrich(manual_positives),
        "lexical_false_positive_candidates": enrich(lexical_false_positive),
        "zero_candidate_cves": enrich(zero_candidate),
    }


def _write_artifacts(report: Mapping[str, Any], definition: Mapping[str, Any], output: Path) -> None:
    write_report_json(definition, output / "correlation_benchmark_definition.json")
    write_report_json(_ground_truth(definition.get("records", [])), output / "correlation_ground_truth.json")
    write_report_json(report.get("correlation_evaluation", {}), output / "correlation_evaluation.json")
    _write_csv(report.get("records", []), output / "correlation_records.csv", exclude=("decisions",))
    write_report_json({"generated_at": report.get("generated_at"), "records": report.get("paired_records", [])}, output / "paired_model_results.json")
    _write_csv(report.get("ranking_comparison", []), output / "ranking_comparison.csv")
    write_report_json(report.get("case_candidates", {}).get("accepted_negatives", []), output / "false_positive_cases.json")
    write_report_json(report.get("case_candidates", {}).get("rejected_confirmed_positives", []), output / "false_negative_cases.json")
    write_report_json(report.get("case_candidates", {}), output / "correlation_case_candidates.json")
    write_report_json(report.get("run_metadata", {}), output / "run_metadata.json")


def _write_csv(rows: Iterable[Mapping[str, Any]], path: Path, exclude: Sequence[str] = ()) -> None:
    rows = list(rows)
    excluded = set(exclude)
    fields = sorted({key for row in rows for key in row if key not in excluded} or {"cve_id"})
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field) for field in fields})


def _write_nvd_subset(records: Iterable[Mapping[str, Any]], path: Path) -> None:
    rows = []
    for record in records:
        row = dict(record)
        row.setdefault("id", row.get("_id"))
        rows.append({"cve": row})
    path.parent.mkdir(parents=True, exist_ok=True)
    write_report_json({"source": "nvd_correlation_benchmark_subset", "vulnerabilities": sorted(rows, key=lambda item: item["cve"].get("_id", ""))}, path)


def _ground_truth(records: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "label_counts": _count_by(records, "label"),
        "records": [
            {
                "cve_id": row.get("cve_id"),
                "label": row.get("label"),
                "reason": row.get("label_reason"),
                "provenance": row.get("label_provenance"),
            }
            for row in records
        ],
    }


def _status_counts(decisions: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    counts = {"accepted": 0, "manual_review": 0, "rejected": 0}
    for decision in decisions:
        status = str(decision.get("status"))
        if status in counts:
            counts[status] += 1
    return counts


def _rows_by_cve(rows: Iterable[Mapping[str, Any]], benchmark_ids: Sequence[str]) -> dict[str, dict[str, Any]]:
    wanted = set(benchmark_ids)
    return {str(row.get("cve_id") or row.get("entity_id")): dict(row) for row in rows if str(row.get("cve_id") or row.get("entity_id")) in wanted}


def _is_positive(row: Mapping[str, Any]) -> bool:
    return row.get("label") in {GroundTruthLabel.CONFIRMED_POSITIVE.value, GroundTruthLabel.LIKELY_POSITIVE.value}


def _is_negative(row: Mapping[str, Any]) -> bool:
    return row.get("label") == GroundTruthLabel.CONFIRMED_NEGATIVE.value


def _description(record: Mapping[str, Any]) -> str:
    descriptions = record.get("descriptions") or []
    for item in descriptions:
        if isinstance(item, Mapping) and str(item.get("lang", "")).lower() == "en":
            return str(item.get("value") or "")
    if descriptions and isinstance(descriptions[0], Mapping):
        return str(descriptions[0].get("value") or "")
    return ""


def _invalid_description(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in ("rejected", "reserved", "do not use", "candidate was issued in error"))


def _extract_cvss(record: Mapping[str, Any]) -> float:
    metrics = record.get("metrics", {}) or {}
    for key in ("cvss_metric_v40", "cvss_metric_v31", "cvss_metric_v30", "cvss_metric_v2", "cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key) or []
        if values:
            data = values[0].get("cvss_data") or values[0].get("cvssData") or {}
            return safe_float(data.get("base_score", data.get("baseScore")))
    return 0.0


def _minimal_urlhaus(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "urlhaus_id": row.get("urlhaus_id") or row.get("id") or row.get("_id"),
        "url": row.get("url"),
        "url_status": row.get("url_status"),
        "threat": row.get("threat"),
        "tags": list(row.get("tags") or []),
        "date_added": row.get("date_added") or row.get("dateadded"),
        "urlhaus_reference": _urlhaus_reference(row),
    }


def _urlhaus_reference(row: Mapping[str, Any]) -> str | None:
    value = row.get("urlhaus_reference") or row.get("urlhaus_link") or row.get("urlhausLink")
    return str(value) if value else None


def _evidence_fields_for_cve(cve_id: str, rows: Sequence[Mapping[str, Any]]) -> list[str]:
    fields = set()
    needle = cve_id.lower()
    for row in rows:
        if needle in str(row.get("url") or "").lower():
            fields.add("url")
        if any(needle == str(tag).lower() for tag in (row.get("tags") or [])):
            fields.add("tags")
        if needle in str(_urlhaus_reference(row) or "").lower():
            fields.add("urlhaus_reference")
    return sorted(fields)


def _recent_nvd_provenance(records: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    return {"source_name": "nvd_recent_controls", "source_url": NVD_CVE_API_URL, "row_count": len(records)}


def _count_by(rows: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _stable_json(value: Mapping[str, Any]) -> dict[str, Any]:
    return json.loads(json.dumps(value, sort_keys=True, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and run a URLhaus/CVE correlation-focused benchmark")
    parser.add_argument("--urlhaus-file", default=None)
    parser.add_argument("--negative-nvd-file", default=None)
    parser.add_argument("--benchmark-definition", default=None)
    parser.add_argument("--nvd-file", default=None)
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR))
    parser.add_argument("--cache-dir", default=".cache/correlation_benchmark")
    parser.add_argument("--refresh-urlhaus", action="store_true")
    parser.add_argument("--refresh-nvd", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--build-only", action="store_true")
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--generated-at", default=None)
    parser.add_argument("--reference-time", default=None)
    args = parser.parse_args()
    try:
        output = Path(args.output_dir)
        definition_path = Path(args.benchmark_definition) if args.benchmark_definition else output / "correlation_benchmark_definition.json"
        nvd_path = Path(args.nvd_file) if args.nvd_file else output / "correlation_nvd_records.json"
        if args.benchmark_definition is None or args.nvd_file is None:
            build_correlation_benchmark_definition(
                urlhaus_path=args.urlhaus_file,
                cache_dir=args.cache_dir,
                output_dir=output,
                nvd_output_path=nvd_path,
                negative_nvd_path=args.negative_nvd_file,
                refresh_urlhaus=args.refresh_urlhaus,
                refresh_nvd=args.refresh_nvd,
                offline=args.offline,
                timeout_seconds=args.timeout_seconds,
                generated_at=args.generated_at,
            )
        if args.build_only:
            print(json.dumps({"output_dir": str(output), "benchmark_definition": str(definition_path), "nvd_file": str(nvd_path)}, sort_keys=True))
            return
        report = run_correlation_benchmark(
            benchmark_definition_path=definition_path,
            nvd_path=nvd_path,
            urlhaus_path=args.urlhaus_file or Path(args.cache_dir) / DEFAULT_URLHAUS_FULL_CACHE_FILENAME,
            output_dir=output,
            cache_dir=args.cache_dir,
            generated_at=args.generated_at,
            reference_time=args.reference_time,
            timeout_seconds=args.timeout_seconds,
        )
    except (RealDataError, DataFormatError, DataUnavailableError) as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(2) from exc
    print(
        json.dumps(
            {
                "output_dir": str(args.output_dir),
                "record_count": report["benchmark"]["record_count"],
                "label_counts": report["benchmark"]["label_counts"],
                "precision": report["correlation_evaluation"]["precision"],
                "recall": report["correlation_evaluation"]["recall"],
                "f1": report["correlation_evaluation"]["f1"],
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
