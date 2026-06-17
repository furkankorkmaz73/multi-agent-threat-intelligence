from __future__ import annotations

import argparse
import csv
import json
import subprocess
from copy import deepcopy
from datetime import datetime, timezone
from math import ceil, floor, log2
from pathlib import Path
from random import Random
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping, Sequence

import pymongo
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

from config import DB_NAME, MONGO_URI, get_settings

SETTINGS = get_settings()

from .constants import *
from .common import *
from .artifacts import _learned_calibration_artifact_specs
from .optional_dependencies import _load_sklearn as _default_load_sklearn


def _load_sklearn():
    import evaluation.learned_calibration as learned_calibration

    loader = getattr(learned_calibration, "_load_sklearn", _default_load_sklearn)
    if loader is _load_sklearn:
        return _default_load_sklearn()
    return loader()


def _current_git_metadata_for_snapshot():
    import evaluation.learned_calibration as learned_calibration

    current = getattr(learned_calibration, "_current_git_metadata", _current_git_metadata)
    if current is _current_git_metadata_for_snapshot:
        return _current_git_metadata()
    return current()


def build_consistency_audit(artifact_dir: str | Path) -> dict[str, Any]:
    root = Path(artifact_dir)
    checks: list[dict[str, Any]] = []
    dataset_rows = _read_csv_rows(root / "learned_calibration_dataset.csv")
    label_rows = _read_csv_rows(root / "learned_calibration_labels.csv")
    dataset_ids = [row.get("cve_id", "") for row in dataset_rows]
    label_ids = [row.get("cve_id", "") for row in label_rows]
    checks.append(_audit_check("dataset_label_row_count_match", len(dataset_rows) == len(label_rows), f"dataset={len(dataset_rows)} labels={len(label_rows)}"))
    checks.append(_audit_check("dataset_cve_ids_unique", len(dataset_ids) == len(set(dataset_ids)), f"unique={len(set(dataset_ids))} total={len(dataset_ids)}"))
    checks.append(_audit_check("label_ids_match_dataset_ids", set(label_ids) == set(dataset_ids), f"dataset_only={len(set(dataset_ids) - set(label_ids))} labels_only={len(set(label_ids) - set(dataset_ids))}"))
    prediction_rows = _read_csv_rows(root / "learned_calibration_predictions.csv")
    prediction_ids = {row.get("cve_id", "") for row in prediction_rows if row.get("cve_id")}
    checks.append(_audit_check("prediction_ids_subset_dataset_ids", prediction_ids.issubset(set(dataset_ids)), f"prediction_ids={len(prediction_ids)}"))
    for filename in _learned_calibration_json_filenames_for_audit():
        checks.append(_audit_check(f"json_parseable:{filename}", _json_file_parseable(root / filename), filename))
    for filename in _learned_calibration_csv_filenames_for_audit():
        checks.append(_audit_check(f"csv_no_duplicate_headers:{filename}", not _csv_has_duplicate_headers(root / filename), filename))
    for filename in _learned_calibration_markdown_filenames_for_audit():
        checks.append(_audit_check(f"markdown_limitation_language:{filename}", _markdown_has_limitation_language(root / filename), filename))
    checks.append(_audit_check("sklearn_unavailable_model_report_skipped", _sklearn_skip_consistent(root / "learned_calibration_model_report.json"), "model report status matches sklearn availability"))
    checks.append(_audit_check("no_ground_truth_exploitation_prediction_claim", not _contains_unsafe_exploitation_prediction_claim(root), "artifact text avoids ground-truth exploitation prediction claims"))
    status = "passed" if all(check["status"] == "passed" for check in checks) else "failed"
    return {
        "status": status,
        "artifact_dir": str(root),
        "dataset_row_count": len(dataset_rows),
        "label_row_count": len(label_rows),
        "check_count": len(checks),
        "checks": checks,
        "notes": [
            "Consistency audit validates learned-calibration artifact structure and limitation language.",
            "It does not validate proxy labels as ground truth and does not change production scoring.",
        ],
    }

def render_consistency_audit_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Artifact Consistency Audit",
        "",
        "This artifact checks structural consistency across learned-calibration outputs.",
        "It does not validate proxy labels as ground truth and does not change production scoring.",
        "",
        f"- Status: `{payload.get('status', '')}`",
        f"- Dataset rows: `{payload.get('dataset_row_count', 0)}`",
        f"- Label rows: `{payload.get('label_row_count', 0)}`",
        f"- Checks: `{payload.get('check_count', 0)}`",
        "",
        "| Check | Status | Details |",
        "| --- | --- | --- |",
    ]
    for check in payload.get("checks") or []:
        lines.append(f"| {check.get('check', '')} | {check.get('status', '')} | {check.get('details', '')} |")
    lines.append("")
    return "\n".join(lines)

def build_runtime_snapshot(
    artifact_dir: str | Path,
    *,
    generated_at: str | None = None,
    git_metadata: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    root = Path(artifact_dir)
    generated = generated_at or datetime.now(timezone.utc).isoformat()
    git_info = dict(git_metadata or _current_git_metadata_for_snapshot())
    core_files = [
        "learned_calibration_dataset.csv",
        "learned_calibration_labels.csv",
        "learned_calibration_report.json",
        "learned_calibration_model_report.json",
        "learned_calibration_manifest.json",
        "learned_calibration_consistency_audit.json",
        "learned_calibration_appendix.md",
    ]
    row_count_files = [
        "learned_calibration_dataset.csv",
        "learned_calibration_labels.csv",
        "learned_calibration_predictions.csv",
        "learned_calibration_case_studies.csv",
        "learned_calibration_proxy_sensitivity.csv",
        "learned_calibration_bootstrap_stability.csv",
        "learned_calibration_coverage_strata.csv",
    ]
    status_files = [
        "learned_calibration_report.json",
        "learned_calibration_model_report.json",
        "learned_calibration_leakage_checks.json",
        "learned_calibration_bootstrap_stability.json",
        "learned_calibration_coverage_strata.json",
        "learned_calibration_negative_controls.json",
        "learned_calibration_consistency_audit.json",
        "learned_calibration_manifest.json",
    ]
    core_existence = {filename: (root / filename).exists() for filename in core_files}
    row_counts = {filename: _csv_row_count(root / filename) for filename in row_count_files}
    status_values = {filename: _json_status(root / filename) for filename in status_files}
    model_report = _read_json_mapping(root / "learned_calibration_model_report.json")
    warnings = _runtime_snapshot_warnings(root, row_counts)
    return {
        "status": "available" if all(core_existence.values()) else "incomplete",
        "generated_at": generated,
        "git": {
            "branch": git_info.get("branch", "unknown"),
            "head_commit": git_info.get("head_commit", "unknown"),
        },
        "artifact_dir": str(root),
        "core_artifact_existence": core_existence,
        "row_counts": row_counts,
        "json_status_values": status_values,
        "model_training_status": model_report.get("status", "unavailable"),
        "model_skip_reason": model_report.get("skip_reason", ""),
        "sklearn_available": _load_sklearn() is not None,
        "final_test_commands": [
            "make test-python",
            "make thesis-artifacts",
            "make thesis-artifact-quality",
            "make thesis-learned-calibration",
            "make thesis-learned-calibration-quality",
        ],
        "warnings": warnings,
        "notes": [
            "Runtime snapshot uses local files and git metadata only.",
            "It does not run full analysis, mutate MongoDB, train a model, or push commits.",
        ],
    }

def render_runtime_snapshot_markdown(snapshot: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Runtime Snapshot",
        "",
        "This snapshot summarizes local learned-calibration artifact health from files and git metadata only.",
        "It does not run full analysis, mutate MongoDB, train a model, or push commits.",
        "",
        f"- Status: `{snapshot.get('status', '')}`",
        f"- Generated at: `{snapshot.get('generated_at', '')}`",
        f"- Branch: `{(snapshot.get('git') or {}).get('branch', '')}`",
        f"- HEAD: `{(snapshot.get('git') or {}).get('head_commit', '')}`",
        f"- Model status: `{snapshot.get('model_training_status', '')}`",
        f"- scikit-learn available: `{snapshot.get('sklearn_available', False)}`",
        "",
        "## Core Artifacts",
        "",
        "| Artifact | Exists |",
        "| --- | --- |",
    ]
    for filename, exists in (snapshot.get("core_artifact_existence") or {}).items():
        lines.append(f"| {filename} | {exists} |")
    lines.extend(["", "## Row Counts", "", "| CSV | Rows |", "| --- | ---: |"])
    for filename, count in (snapshot.get("row_counts") or {}).items():
        lines.append(f"| {filename} | {count} |")
    lines.extend(["", "## JSON Status Values", "", "| JSON | Status |", "| --- | --- |"])
    for filename, status in (snapshot.get("json_status_values") or {}).items():
        lines.append(f"| {filename} | {status} |")
    lines.extend(["", "## Known Validation Commands", ""])
    lines.extend(f"- `{command}`" for command in snapshot.get("final_test_commands") or [])
    lines.extend(["", "## Warnings", ""])
    warnings = list(snapshot.get("warnings") or [])
    lines.extend(f"- {warning}" for warning in warnings) if warnings else lines.append("- None.")
    lines.append("")
    return "\n".join(lines)

def build_reviewer_checklist(artifact_dir: str | Path) -> dict[str, Any]:
    root = Path(artifact_dir)
    model = _read_json_mapping(root / "learned_calibration_model_report.json")
    consistency = _read_json_mapping(root / "learned_calibration_consistency_audit.json")
    leakage = _read_json_mapping(root / "learned_calibration_leakage_checks.json")
    baseline = _read_json_mapping(root / "learned_calibration_baseline_metrics.json")
    runtime = _read_json_mapping(root / "learned_calibration_runtime_snapshot.json")
    sections = [
        ("reproducibility checks", [
            _checklist_item("repro-commands", _exists(root / "learned_calibration_runtime_snapshot.json"), "learned_calibration_runtime_snapshot.json", "Runtime snapshot records known validation commands and git metadata."),
            _checklist_item("repro-manifest", _exists(root / "learned_calibration_manifest.json"), "learned_calibration_manifest.json", "Manifest should list generated learned-calibration artifacts."),
        ]),
        ("artifact checks", [
            _checklist_item("artifact-consistency", consistency.get("status") == "passed", "learned_calibration_consistency_audit.json", "Consistency audit should pass before using artifacts."),
            _checklist_item("artifact-runtime-status", runtime.get("status") == "available", "learned_calibration_runtime_snapshot.json", "Runtime snapshot should report available core artifacts."),
        ]),
        ("proxy-label validity checks", [
            _manual_item("proxy-label-review", "learned_calibration_labels.csv", "Review Strategy A/B/C proxy definitions; proxy labels are not ground truth."),
            _checklist_item("proxy-baseline-present", bool((baseline.get("strategies") or {}).get("strategy_a")), "learned_calibration_baseline_metrics.json", "Strategy A baseline metrics should be present."),
        ]),
        ("leakage checks", [
            _checklist_item("leakage-status", leakage.get("status") == "passed", "learned_calibration_leakage_checks.json", "Leakage checks should pass."),
            _checklist_item("risk-score-excluded", "final_risk_score_not_model_input" in json.dumps(leakage), "learned_calibration_leakage_checks.json", "Leakage artifact should document production risk_score exclusion."),
        ]),
        ("model-training checks", [
            _status_item("model-status", _model_training_check_status(model), "learned_calibration_model_report.json", _model_training_note(model)),
            _manual_item("model-dependency-review", "learned_calibration_model_report.json", "If model training is skipped, decide whether an approved scikit-learn environment is allowed."),
        ]),
        ("ranking metric checks", [
            _checklist_item("baseline-metrics-present", bool((baseline.get("strategies") or {}).get("strategy_a")), "learned_calibration_baseline_metrics.json", "Heuristic baseline metrics should be available."),
            _checklist_item("negative-controls-present", _exists(root / "learned_calibration_negative_controls.json"), "learned_calibration_negative_controls.json", "Negative controls should be generated for sanity checking."),
        ]),
        ("limitations checks", [
            _checklist_item("limitations-present", _exists(root / "learned_calibration_limitations.md"), "learned_calibration_limitations.md", "Limitations artifact should be available."),
            _manual_item("limitations-review", "learned_calibration_appendix.md", "Confirm thesis text states proxy labels are not ground truth and learned calibration is experimental."),
        ]),
        ("no-overclaim checks", [
            _checklist_item("no-ground-truth-claim", consistency.get("status") == "passed", "learned_calibration_consistency_audit.json", "Audit should reject ground-truth exploitation prediction claims."),
            _manual_item("claim-review", "learned_calibration_appendix.md", "Avoid claims of real-world predictive performance or production replacement."),
        ]),
        ("defense-readiness checks", [
            _checklist_item("appendix-present", _exists(root / "learned_calibration_appendix.md"), "learned_calibration_appendix.md", "Appendix draft should be available for thesis review."),
            _manual_item("defense-review", "learned_calibration_runtime_snapshot.md", "Review skipped model status, sparse evidence coverage, and manual thesis talking points."),
        ]),
        ("manual review items for the thesis author", [
            _manual_item("external-label-plan", "learned_calibration_limitations.md", "Identify what external labels would be required for any future supervised claim."),
            _manual_item("evidence-coverage-plan", "learned_calibration_coverage_strata.md", "Review EPSS/KEV and accepted-evidence gaps before thesis defense."),
        ]),
    ]
    flat_items = [item for _section, items in sections for item in items]
    return {
        "status": "ready_with_manual_review" if all(item["status"] in {"pass", "manual", "warning"} for item in flat_items) else "incomplete",
        "sections": [{"section": section, "items": items} for section, items in sections],
        "item_count": len(flat_items),
        "status_counts": _checklist_status_counts(flat_items),
        "notes": [
            "Checklist statuses are derived from generated artifact files where possible.",
            "Manual items require thesis-author review and are not automatic pass/fail evidence.",
        ],
    }

def render_reviewer_checklist_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Reviewer Checklist",
        "",
        "This checklist supports thesis review of learned-calibration artifacts. Proxy labels are not ground truth, and manual items require thesis-author judgment.",
        "",
        f"- Status: `{payload.get('status', '')}`",
        f"- Items: `{payload.get('item_count', 0)}`",
        "",
    ]
    for section in payload.get("sections") or []:
        lines.extend([f"## {section.get('section', '').title()}", "", "| Check ID | Status | Evidence Artifact | Reviewer Note |", "| --- | --- | --- | --- |"])
        for item in section.get("items") or []:
            lines.append(
                "| {check_id} | {status} | {artifact} | {note} |".format(
                    check_id=item.get("check_id", ""),
                    status=item.get("status", ""),
                    artifact=item.get("evidence_artifact", ""),
                    note=item.get("reviewer_note", ""),
                )
            )
        lines.append("")
    return "\n".join(lines)

def build_limitations_matrix() -> dict[str, Any]:
    rows = [
        _limitation_row(
            "proxy labels are not ground truth",
            "Proxy-label metrics cannot be interpreted as verified exploitation prediction.",
            "Artifacts repeatedly label proxy outcomes as deterministic thesis aids.",
            "Use curated external exploitation or incident labels.",
            "Proxy labels support feasibility discussion, not ground-truth validation.",
        ),
        _limitation_row(
            "EPSS coverage sparse or unavailable",
            "Exploit-likelihood context is incomplete where EPSS is missing.",
            "Coverage fields and strata expose EPSS availability explicitly.",
            "Ingest vetted EPSS snapshots and document version dates.",
            "Missing EPSS is a coverage limitation, not evidence of low risk.",
        ),
        _limitation_row(
            "KEV status sparse or unavailable",
            "Active-exploitation evidence may be absent or unknown.",
            "KEV-known and KEV-listed fields are exported separately.",
            "Add reproducible CISA KEV snapshot enrichment.",
            "Unknown KEV status should not be treated as proof of no exploitation.",
        ),
        _limitation_row(
            "accepted external evidence sparse or absent",
            "Evidence-supported labels and confidence remain limited.",
            "Accepted, rejected, manual-review, and ignored evidence are separated.",
            "Evaluate with richer URLhaus, KEV, EPSS, and asset-context data.",
            "Sparse accepted evidence limits confidence and learned calibration claims.",
        ),
        _limitation_row(
            "Dread live crawling disabled",
            "Dread evidence is not available as live validation in this experiment.",
            "Dread remains optional, bounded, default-off, and not ground truth.",
            "Use ethically reviewed, static, corroborated datasets if needed.",
            "Live Dread crawling was not used in learned-calibration artifacts.",
        ),
        _limitation_row(
            "URLhaus correlation evidence gated and conservative",
            "Accepted URLhaus evidence may be zero even when candidates exist.",
            "Strict gates prevent weak keyword overlap from boosting risk.",
            "Improve high-quality IOC-to-CVE linkage datasets.",
            "Zero accepted URLhaus can reflect conservative gates, not system failure.",
        ),
        _limitation_row(
            "model training skipped if scikit-learn unavailable",
            "Learned model metrics may be unavailable in the local environment.",
            "Model report records skipped status and dependency reason.",
            "Run in an approved environment with pinned dependencies.",
            "Skipped model training is reported transparently, not filled with fabricated results.",
        ),
        _limitation_row(
            "CVSS/severity dominance risk",
            "Proxy labels may be partly aligned with technical severity.",
            "Negative controls and sensitivity artifacts expose CVSS-only behavior.",
            "Use labels independent of CVSS-driven scoring signals.",
            "CVSS dominance is a limitation of proxy-label interpretation.",
        ),
        _limitation_row(
            "confidence not equivalent to correctness",
            "Confidence measures support quality, not factual correctness of outcomes.",
            "Risk and confidence remain separate exported fields.",
            "Validate against external outcomes and analyst review.",
            "Confidence is evidence reliability, not a correctness guarantee.",
        ),
        _limitation_row(
            "deterministic fixture validation is not real-world generalization",
            "Controlled behavior does not establish field performance.",
            "Artifacts explicitly frame deterministic tests as behavioral validation.",
            "Evaluate on larger curated real-world datasets with external labels.",
            "Deterministic validation supports reproducibility, not generalization claims.",
        ),
        _limitation_row(
            "learned calibration does not replace production scoring",
            "Learned artifacts are diagnostic and do not change runtime decisions.",
            "Leakage checks and docs state production risk_score remains heuristic.",
            "Consider a separate reviewed calibration layer after external validation.",
            "Learned calibration is future work and does not replace heuristic scoring.",
        ),
    ]
    return {
        "status": "available",
        "row_count": len(rows),
        "rows": rows,
        "notes": [
            "Limitations matrix is thesis-supporting documentation.",
            "It does not change scoring, evidence gates, or model training behavior.",
        ],
    }

def render_limitations_matrix_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration Limitations Matrix",
        "",
        "This matrix consolidates thesis-safe limitations for learned calibration. It does not change production scoring and does not treat proxy labels as ground truth.",
        "",
        "| Limitation | Impact | Mitigation Already Implemented | Future Work | Thesis-Safe Wording |",
        "| --- | --- | --- | --- | --- |",
    ]
    for row in payload.get("rows") or []:
        lines.append(
            "| {limitation} | {impact} | {mitigation} | {future} | {wording} |".format(
                limitation=row.get("limitation", ""),
                impact=row.get("impact_on_interpretation", ""),
                mitigation=row.get("mitigation_already_implemented", ""),
                future=row.get("future_work", ""),
                wording=row.get("thesis_safe_wording", ""),
            )
        )
    lines.append("")
    return "\n".join(lines)

def _limitation_row(
    limitation: str,
    impact: str,
    mitigation: str,
    future_work: str,
    wording: str,
) -> dict[str, str]:
    return {
        "limitation": limitation,
        "impact_on_interpretation": impact,
        "mitigation_already_implemented": mitigation,
        "future_work": future_work,
        "thesis_safe_wording": wording,
    }

def build_no_overclaim_audit(artifact_dir: str | Path) -> dict[str, Any]:
    root = Path(artifact_dir)
    findings: list[dict[str, str]] = []
    scanned_files = _no_overclaim_scan_files(root)
    for path in scanned_files:
        findings.extend(_unsafe_claim_findings(path))
    return {
        "status": "passed" if not findings else "failed",
        "scanned_file_count": len(scanned_files),
        "findings": findings,
        "unsafe_phrases": _unsafe_overclaim_phrases(),
        "notes": [
            "This audit flags unsafe learned-calibration claims unless they are explicitly negated or framed as limitations.",
            "Proxy labels are not ground truth, and learned calibration does not replace production scoring.",
        ],
    }

def render_no_overclaim_audit_markdown(payload: Mapping[str, Any]) -> str:
    lines = [
        "# Learned Calibration No-Overclaim Audit",
        "",
        "This audit checks learned-calibration docs and generated reports for unsafe thesis claims. Safe negated or limitation wording is allowed.",
        "",
        f"- Status: `{payload.get('status', '')}`",
        f"- Scanned files: `{payload.get('scanned_file_count', 0)}`",
        f"- Findings: `{len(payload.get('findings') or [])}`",
        "",
        "| File | Phrase | Line | Excerpt |",
        "| --- | --- | ---: | --- |",
    ]
    findings = list(payload.get("findings") or [])
    if findings:
        for finding in findings:
            lines.append(
                "| {file} | {phrase} | {line} | {excerpt} |".format(
                    file=finding.get("file", ""),
                    phrase=finding.get("phrase", ""),
                    line=finding.get("line", ""),
                    excerpt=finding.get("excerpt", ""),
                )
            )
    else:
        lines.append("| none | none | 0 | No unsafe overclaim wording detected. |")
    lines.append("")
    return "\n".join(lines)

def _unsafe_claim_findings(path: Path) -> list[dict[str, str]]:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except FileNotFoundError:
        return []
    findings: list[dict[str, str]] = []
    for line_number, line in enumerate(lines, start=1):
        lower = line.lower()
        for phrase in _unsafe_overclaim_phrases():
            if phrase in lower and not _is_safe_overclaim_context(lower):
                findings.append(
                    {
                        "file": str(path),
                        "phrase": phrase,
                        "line": str(line_number),
                        "excerpt": line.strip()[:240],
                    }
                )
    return findings

def _unsafe_overclaim_phrases() -> list[str]:
    return [
        "ground truth",
        "proven exploitation prediction",
        "production-ready",
        "autonomous agent",
        "optimal weights",
        "dark web crawler",
        "statistically proven real-world performance",
        "learned model replaces heuristic scoring",
        "confidence equals correctness",
    ]

def _is_safe_overclaim_context(line: str) -> bool:
    safe_markers = [
        "not ground truth",
        "not a ground truth",
        "not treated as ground truth",
        "not negative ground truth",
        "what would change with real ground truth labels",
        "not factual correctness",
        "not equivalent to correctness",
        "does not prove",
        "does not replace",
        "do not claim",
        "avoid claims",
        "unsafe claims",
        "limitation",
        "limitations",
        "future work",
        "would require",
        "would allow",
        "requires",
        "required",
        "disabled",
        "was not used",
        "not used",
        "no ",
    ]
    return any(marker in line for marker in safe_markers)

def _no_overclaim_scan_files(root: Path) -> list[Path]:
    filenames = {
        "learned_calibration_report.json",
        "learned_calibration_summary.md",
        *[
            spec["filename"]
            for spec in _learned_calibration_artifact_specs()
            if "no_overclaim_audit" not in spec["filename"] and "consistency_audit" not in spec["filename"]
        ],
    }
    files = [root / filename for filename in sorted(filenames) if (root / filename).exists()]
    docs_path = Path(__file__).resolve().parents[3] / "docs" / "learned_calibration.md"
    if docs_path.exists():
        files.append(docs_path)
    return files

def _checklist_item(check_id: str, passed: bool, evidence_artifact: str, note: str) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": "pass" if passed else "unavailable",
        "evidence_artifact": evidence_artifact,
        "reviewer_note": note,
    }

def _manual_item(check_id: str, evidence_artifact: str, note: str) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": "manual",
        "evidence_artifact": evidence_artifact,
        "reviewer_note": note,
    }

def _status_item(check_id: str, status: str, evidence_artifact: str, note: str) -> dict[str, str]:
    return {
        "check_id": check_id,
        "status": status,
        "evidence_artifact": evidence_artifact,
        "reviewer_note": note,
    }

def _model_training_check_status(model_report: Mapping[str, Any]) -> str:
    status = str(model_report.get("status", ""))
    if status == "completed":
        return "pass"
    if status == "skipped":
        return "warning"
    return "unavailable"

def _model_training_note(model_report: Mapping[str, Any]) -> str:
    status = str(model_report.get("status", "unavailable"))
    if status == "skipped":
        return f"Model training skipped: {model_report.get('skip_reason', 'reason unavailable')}"
    return f"Model training status: {status}"

def _checklist_status_counts(items: Sequence[Mapping[str, str]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        status = item.get("status", "unavailable")
        counts[status] = counts.get(status, 0) + 1
    return counts

def _exists(path: Path) -> bool:
    return path.exists()

def _current_git_metadata() -> dict[str, str]:
    return {
        "branch": _git_command(["rev-parse", "--abbrev-ref", "HEAD"]),
        "head_commit": _git_command(["rev-parse", "--short", "HEAD"]),
    }

def _git_command(args: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=Path(__file__).resolve().parents[3],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"

def _csv_row_count(path: Path) -> int | None:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return sum(1 for _row in csv.DictReader(handle))
    except FileNotFoundError:
        return None

def _json_status(path: Path) -> str:
    payload = _read_json_mapping(path)
    if not payload:
        return "missing_or_malformed"
    return str(payload.get("status") or payload.get("proxy_supervised_learning_feasibility") or "available")

def _read_json_mapping(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}

def _runtime_snapshot_warnings(root: Path, row_counts: Mapping[str, int | None]) -> list[str]:
    warnings: list[str] = []
    optional_files = [
        "learned_calibration_predictions.csv",
        "learned_calibration_feature_importance.csv",
        "learned_calibration_disagreements.csv",
    ]
    for filename in optional_files:
        path = root / filename
        if not path.exists():
            warnings.append(f"Optional artifact missing: {filename}")
        elif row_counts.get(filename) == 0:
            warnings.append(f"Optional artifact has no data rows: {filename}")
    return warnings

def _audit_check(name: str, passed: bool, details: str) -> dict[str, str]:
    return {"check": name, "status": "passed" if passed else "failed", "details": details}

def _learned_calibration_json_filenames_for_audit() -> list[str]:
    filenames = [
        spec["filename"]
        for spec in _learned_calibration_artifact_specs()
        if spec["filename"].endswith(".json") and "consistency_audit" not in spec["filename"] and "manifest" not in spec["filename"]
    ]
    return ["learned_calibration_report.json", *filenames]

def _learned_calibration_csv_filenames_for_audit() -> list[str]:
    return [
        spec["filename"]
        for spec in _learned_calibration_artifact_specs()
        if spec["filename"].endswith(".csv")
    ]

def _learned_calibration_markdown_filenames_for_audit() -> list[str]:
    filenames = [
        spec["filename"]
        for spec in _learned_calibration_artifact_specs()
        if spec["filename"].endswith(".md") and "consistency_audit" not in spec["filename"] and "manifest" not in spec["filename"]
    ]
    return ["learned_calibration_summary.md", *filenames]

def _read_csv_rows(path: Path) -> list[dict[str, str]]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))
    except FileNotFoundError:
        return []

def _json_file_parseable(path: Path) -> bool:
    try:
        json.loads(path.read_text(encoding="utf-8"))
        return True
    except Exception:
        return False

def _csv_has_duplicate_headers(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            header = handle.readline().strip("\n\r").split(",")
            return len(header) != len(set(header))
    except FileNotFoundError:
        return True

def _markdown_has_limitation_language(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8").lower()
    except FileNotFoundError:
        return False
    markers = [
        "not ground truth",
        "does not",
        "unchanged",
        "skipped",
        "limitation",
        "limitations",
        "experimental",
        "proxy",
    ]
    return any(marker in text for marker in markers)

def _sklearn_skip_consistent(model_report_path: Path) -> bool:
    try:
        report = json.loads(model_report_path.read_text(encoding="utf-8"))
    except Exception:
        return False
    if _load_sklearn() is not None:
        return True
    return report.get("status") == "skipped" and "scikit-learn" in str(report.get("skip_reason", ""))

def _contains_unsafe_exploitation_prediction_claim(root: Path) -> bool:
    unsafe = [
        "ground truth exploitation prediction",
        "proves real-world exploitation",
        "real-world exploitation prediction",
    ]
    filenames = {
        "learned_calibration_report.json",
        "learned_calibration_summary.md",
        *[spec["filename"] for spec in _learned_calibration_artifact_specs()],
    }
    for filename in filenames:
        path = root / filename
        if path.is_file() and path.suffix in {".json", ".md", ".csv"}:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
            text = text.replace("does not prove real-world exploitation prediction", "")
            text = text.replace("does proxy-supervised learning prove real-world exploitation prediction?", "")
            text = text.replace("avoid claims of production readiness, real-world exploitation prediction", "avoid claims of production readiness")
            for phrase in unsafe:
                if phrase in text:
                    return True
    return False
