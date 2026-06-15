from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


EXPECTED_MANIFEST_KEYS = {
    "scoring_summary",
    "scoring_distribution",
    "scoring_distribution_md",
    "scoring_sensitivity",
    "scoring_sensitivity_md",
    "benchmark_summary",
    "benchmark_summary_md",
    "ablation_summary",
    "ablation_summary_md",
    "correlation_decisions",
    "case_studies",
    "risk_explanation_traces",
    "risk_explanation_traces_md",
    "demo_walkthrough",
    "results_summary",
    "thesis_results_section",
    "limitations_and_validity",
    "thesis_defense_pack",
    "methodology_summary",
}

REQUIRED_CASE_STUDIES = {
    "high_risk_correlated",
    "medium_cvss_high_epss_kev",
    "high_cvss_low_external_evidence",
    "dread_only_manual_review",
    "dread_corroborated_by_urlhaus_or_kev",
    "weak_dread_rejected",
    "keyword_only_false_positive_rejected",
    "stale_evidence_rejected_or_capped",
    "unrelated_product_overlap_rejected",
    "manual_review_not_risk_boost",
    "asset_applicability_difference",
    "patched_asset_reduction",
    "compensating_control_reduction",
    "stale_low_risk",
}

REQUIRED_TRACE_CVES = {
    "CVE-2026-9001",
    "CVE-2026-9002",
    "CVE-2026-9007",
    "CVE-2026-9017",
    "CVE-2015-0001",
}

REQUIRED_TRACE_FIELDS = {
    "generic_cve_risk_score",
    "confidence",
    "risk_level",
    "top_positive_risk_contributors",
    "top_evidence_decisions",
    "asset_operational_risk_examples",
    "explanation",
}

REQUIRED_CORRELATION_COLUMNS = {
    "source_identifier",
    "target_identifier",
    "source",
    "decision",
    "primary_reason",
    "final_confidence",
    "evidence_source",
    "evidence_reliability",
    "dread_evidence_present",
    "dread_only_evidence",
    "corroborated_dread_evidence",
    "manual_review_reason",
    "confidence_cap_reason",
    "evidence_gate_passed",
    "evidence_gate_reason",
    "rejection_reason",
    "accepted_evidence_count",
    "rejected_evidence_count",
    "manual_review_evidence_count",
    "false_positive_control",
}

REQUIRED_SENSITIVITY_COLUMNS = {
    "variant",
    "changed_weight",
    "direction",
    "precision_at_5",
    "recall_at_5",
    "ndcg_at_5",
    "mean_kev_rank",
    "top5_cves",
    "top5_overlap_with_baseline",
    "guardrails_passed",
    "notes",
}

REQUIRED_SCORING_DISTRIBUTION_COLUMNS = {
    "cve_id",
    "risk_score",
    "confidence",
    "score_before_intrinsic_floor",
    "intrinsic_criticality_floor_applied",
    "intrinsic_criticality_floor_value",
    "intrinsic_criticality_reason",
    "urlhaus_raw_candidate_count",
    "urlhaus_ignored_low_signal_count",
    "urlhaus_evaluated_candidate_count",
    "urlhaus_signal_candidate_count",
    "urlhaus_accepted_match_count",
    "urlhaus_manual_review_match_count",
    "urlhaus_rejected_match_count",
    "assessment_confidence",
    "data_completeness",
    "uncertainty_penalty",
    "coverage_limitations",
}

MARKDOWN_REGRESSIONS = (
    "Mean KEVRank",
    "boundedperturbation",
    "stableunder",
    "Variantweights",
    "Recall@5|",
    "6.714286|",
    "hand-pickedweight",
    "removalrequires",
    "likelihood,KEV",
    "fixture,while",
    "evidence,graph",
    "confidence,while",
    "donot",
    "deterministicanalysis",
    "acceptedcorrelation",
    "toinfer",
    "representsreliability",
    "analysisperturbs",
    "casesin",
    "notto",
    "doesnot",
    "orsimilar",
    "fieldperformance",
    "operational-riskexamples",
    "fixtureto",
)

LIMITATIONS_AND_VALIDITY_HEADINGS = (
    "# Limitations and Validity",
    "## Claim Scope",
    "## Multi-Agent Interpretation",
    "## Controlled Fixture Limitation",
    "## Heuristic Scoring Weights Limitation",
    "## Sensitivity Analysis Limitation",
    "## Dread Evidence Limitation",
    "## Asset-Aware Operational Risk Limitation",
    "## Graph Persistence Limitation",
    "## Real-World Generalization Limitation",
    "## Future Work",
)

THESIS_DEFENSE_PACK_HEADINGS = (
    "# Thesis Defense Pack",
    "## One-Paragraph Thesis Claim",
    "## Contributions",
    "## What the System Does Not Claim",
    "## Methodology Summary",
    "## Evaluation Summary",
    "## Key Limitations",
    "## Suggested Defense Q&A",
)

DEMO_WALKTHROUGH_HEADINGS = (
    "# Thesis Demo Walkthrough",
    "## What This Demo Runs",
    "## Output Files",
    "## Key Demonstrated Capabilities",
    "## How to Read the Results",
    "## Asset-Aware Operational Risk Example",
    "## Evidence-Gating and False-Positive Handling",
    "## Reproducibility Notes",
    "## Claim Boundaries",
)

METHODOLOGY_SAFE_FRAMING = (
    "deterministic controlled fixture",
    "behavioral validation",
    "not a live CTI benchmark",
    "not statistical calibration",
    "heuristic engineering choices",
    "Dread cases in thesis artifacts are local deterministic fixtures",
    "do not require live Dread access",
    "False-positive stress cases",
    "Explanation traces",
    "Asset-aware examples",
)

UNSAFE_CLAIM_PHRASES = (
    "fully autonomous",
    "production-ready",
    "SOC-grade",
    "statistically significant",
    "statistically significance",
    "statistical significance",
    "real-world validated",
    "optimized weights",
    "learned optimal weights",
    "dark web crawler",
    "outperforms in the real world",
)


class ArtifactQualityError(RuntimeError):
    def __init__(self, errors: Sequence[str]) -> None:
        super().__init__("\n".join(errors))
        self.errors = list(errors)


def validate_thesis_artifacts(artifact_dir: str | Path) -> dict[str, Any]:
    root = Path(artifact_dir)
    errors: list[str] = []
    manifest = _load_manifest(root, errors)
    if manifest:
        _validate_manifest(root, manifest, errors)
    _validate_case_studies(root, errors)
    _validate_traces(root, errors)
    _validate_csv_columns(root / "correlation_decisions.csv", REQUIRED_CORRELATION_COLUMNS, errors)
    _validate_csv_columns(root / "scoring_sensitivity.csv", REQUIRED_SENSITIVITY_COLUMNS, errors)
    _validate_csv_columns(root / "scoring_distribution.csv", REQUIRED_SCORING_DISTRIBUTION_COLUMNS, errors)
    _validate_required_markdown_sections(root / "limitations_and_validity.md", LIMITATIONS_AND_VALIDITY_HEADINGS, errors)
    _validate_required_markdown_sections(root / "thesis_defense_pack.md", THESIS_DEFENSE_PACK_HEADINGS, errors)
    _validate_required_markdown_sections(root / "demo_walkthrough.md", DEMO_WALKTHROUGH_HEADINGS, errors)
    _validate_methodology_framing(root / "methodology_summary.md", errors)
    checked_markdown = _validate_markdown_files(root, errors)

    if errors:
        raise ArtifactQualityError(errors)
    return {
        "artifact_dir": str(root),
        "checked_files": _count_checked_files(root),
        "checked_markdown_files": checked_markdown,
        "status": "passed",
    }


def _load_manifest(root: Path, errors: list[str]) -> Mapping[str, Any]:
    path = root / "manifest.json"
    if not path.exists():
        errors.append(f"manifest.json is missing: {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"manifest.json is not valid JSON: {exc}")
        return {}


def _validate_manifest(root: Path, manifest: Mapping[str, Any], errors: list[str]) -> None:
    generated = manifest.get("generated_files")
    if not isinstance(generated, Mapping):
        errors.append("manifest generated_files must be an object")
        return
    missing_keys = sorted(EXPECTED_MANIFEST_KEYS - set(generated))
    if missing_keys:
        errors.append(f"manifest missing generated_files keys: {', '.join(missing_keys)}")
    for key, value in sorted(generated.items()):
        path = _manifest_path(root, value)
        if not path.exists():
            errors.append(f"manifest listed file does not exist for {key}: {value}")


def _manifest_path(root: Path, value: Any) -> Path:
    path = Path(str(value))
    if path.is_absolute():
        return path
    if path.exists():
        return path
    candidate = root / path.name
    return candidate


def _validate_case_studies(root: Path, errors: list[str]) -> None:
    path = root / "case_studies.json"
    payload = _load_json(path, errors)
    cases = payload.get("cases") if isinstance(payload, Mapping) else None
    if not isinstance(cases, list):
        errors.append("case_studies.json must contain a cases list")
        return
    present = {str(item.get("case")) for item in cases if isinstance(item, Mapping)}
    missing = sorted(REQUIRED_CASE_STUDIES - present)
    if missing:
        errors.append(f"case_studies.json missing required cases: {', '.join(missing)}")


def _validate_traces(root: Path, errors: list[str]) -> None:
    path = root / "risk_explanation_traces.json"
    payload = _load_json(path, errors)
    traces = payload.get("traces") if isinstance(payload, Mapping) else None
    if not isinstance(traces, list):
        errors.append("risk_explanation_traces.json must contain a traces list")
        return
    by_cve = {
        str(item.get("cve_id")): item
        for item in traces
        if isinstance(item, Mapping)
    }
    missing = sorted(REQUIRED_TRACE_CVES - set(by_cve))
    if missing:
        errors.append(f"risk_explanation_traces.json missing required CVEs: {', '.join(missing)}")
    for cve_id in sorted(REQUIRED_TRACE_CVES & set(by_cve)):
        trace = by_cve[cve_id]
        missing_fields = sorted(field for field in REQUIRED_TRACE_FIELDS if field not in trace)
        if missing_fields:
            errors.append(f"risk trace {cve_id} missing fields: {', '.join(missing_fields)}")


def _load_json(path: Path, errors: list[str]) -> Mapping[str, Any]:
    if not path.exists():
        errors.append(f"required JSON artifact is missing: {path.name}")
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        errors.append(f"{path.name} is not valid JSON: {exc}")
        return {}
    if not isinstance(payload, Mapping):
        errors.append(f"{path.name} must contain a JSON object")
        return {}
    return payload


def _validate_csv_columns(path: Path, required: set[str], errors: list[str]) -> None:
    if not path.exists():
        errors.append(f"required CSV artifact is missing: {path.name}")
        return
    with path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        columns = set(reader.fieldnames or [])
    missing = sorted(required - columns)
    if missing:
        errors.append(f"{path.name} missing required columns: {', '.join(missing)}")


def _validate_markdown_files(root: Path, errors: list[str]) -> int:
    count = 0
    for path in sorted(root.glob("*.md")):
        count += 1
        text = path.read_text(encoding="utf-8")
        lowered_text = text.lower()
        for item in MARKDOWN_REGRESSIONS:
            if item.lower() in lowered_text:
                errors.append(f"{path.name} contains malformed text: {item}")
        for item in _unsafe_claims(text):
            errors.append(f"{path.name} contains unsafe thesis claim: {item}")
        _validate_markdown_tables(path, text, errors)
    return count


def _validate_required_markdown_sections(path: Path, headings: Sequence[str], errors: list[str]) -> None:
    if not path.exists():
        errors.append(f"required Markdown artifact is missing: {path.name}")
        return
    text = path.read_text(encoding="utf-8")
    missing = [heading for heading in headings if heading not in text]
    if missing:
        errors.append(f"{path.name} missing required headings: {', '.join(missing)}")


def _validate_methodology_framing(path: Path, errors: list[str]) -> None:
    if not path.exists():
        errors.append(f"required Markdown artifact is missing: {path.name}")
        return
    text = path.read_text(encoding="utf-8")
    missing = [item for item in METHODOLOGY_SAFE_FRAMING if item not in text]
    if missing:
        errors.append(f"{path.name} missing safe methodology framing: {', '.join(missing)}")


def _unsafe_claims(text: str) -> list[str]:
    unsafe: list[str] = []
    for paragraph in _claim_units(text):
        lowered = paragraph.lower()
        for phrase in UNSAFE_CLAIM_PHRASES:
            if phrase.lower() in lowered and not _is_safe_limited_claim(lowered, phrase.lower()):
                unsafe.append(phrase)
    return sorted(set(unsafe))


def _claim_units(text: str) -> list[str]:
    units: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("|") or stripped.startswith("```"):
            continue
        units.extend(part.strip() for part in stripped.split(".") if part.strip())
    return units


def _is_safe_limited_claim(text: str, phrase: str) -> bool:
    phrase_index = text.find(phrase)
    if phrase_index < 0:
        return True
    prefix = text[max(0, phrase_index - 80):phrase_index]
    suffix = text[phrase_index + len(phrase): phrase_index + len(phrase) + 80]
    safe_prefix_markers = (
        "not ",
        "not a ",
        "not an ",
        "does not ",
        "do not ",
        "no ",
        "without ",
        "avoid ",
        "what the system does not claim",
        "should not ",
        "not be described as ",
        "not claim ",
        "does not claim ",
        "cannot ",
    )
    safe_suffix_markers = (
        "?",
    )
    return any(marker in prefix for marker in safe_prefix_markers) or any(marker in suffix for marker in safe_suffix_markers)


def _validate_markdown_tables(path: Path, text: str, errors: list[str]) -> None:
    table_counts: list[int] = []
    for line_number, line in enumerate([*text.splitlines(), ""], start=1):
        if line.startswith("|"):
            if not line.startswith("| "):
                errors.append(f"{path.name}:{line_number} table row must start with '| '")
            if not line.endswith(" |"):
                errors.append(f"{path.name}:{line_number} table row must end with ' |'")
            table_counts.append(_unescaped_pipe_count(line))
            continue
        if table_counts:
            if len(set(table_counts)) != 1:
                errors.append(f"{path.name}:{line_number} table has inconsistent pipe counts")
            table_counts = []


def _unescaped_pipe_count(line: str) -> int:
    count = 0
    for index, character in enumerate(line):
        if character == "|" and (index == 0 or line[index - 1] != "\\"):
            count += 1
    return count


def _count_checked_files(root: Path) -> int:
    return sum(1 for path in root.iterdir() if path.is_file()) if root.exists() else 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate generated thesis artifacts")
    parser.add_argument("--artifact-dir", default="reports/thesis", help="Generated thesis artifact directory")
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        summary = validate_thesis_artifacts(args.artifact_dir)
    except ArtifactQualityError as exc:
        print(json.dumps({"artifact_dir": args.artifact_dir, "status": "failed", "errors": exc.errors}, indent=2, sort_keys=True))
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
