from __future__ import annotations

import argparse
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Mapping, Optional

from agents.diagnostic import DiagnosticAgent
from agents.recommender import RecommenderAgent
import analysis.risk_engine as risk_engine_module
from analysis.applicability import VulnerableProduct
from analysis.assets import Asset
from analysis.correlation_decisions import build_correlation_candidate, correlation_decision_row, decide_correlation_candidate
from analysis.operational_risk import OperationalRiskService
from api.mappers import to_finding_detail, to_finding_summary
from api.schemas import AnalyzeResponse, FindingDetail, FindingSummary
from evaluation.runner import build_evaluation_report, write_report_json
from integration.thesis_fixtures import (
    fixture_assets,
    fixture_cves,
    fixture_dread,
    fixture_epss_csv,
    fixture_evaluation_model_results,
    fixture_kev_json,
    fixture_urlhaus,
    fixture_vulnerable_products,
)
from worker.executor import WorkerJobExecutor
from worker.job_repository import InMemoryJobRepository
from worker.observability import StructuredJobLogger, WorkerMetrics


GENERATED_AT = "2026-06-10T00:00:00+00:00"
DEFAULT_REPORT_PATH = Path("reports/thesis_scenario_report.json")


class DeterministicClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 6, 10, 0, 0, 0, tzinfo=timezone.utc)

    def now(self) -> datetime:
        value = self.current
        self.current = self.current + timedelta(milliseconds=1)
        return value


class InMemoryScenarioRepository:
    def __init__(self, cves: Iterable[Mapping[str, Any]], urlhaus: Iterable[Mapping[str, Any]], dread: Iterable[Mapping[str, Any]]) -> None:
        self.records: Dict[str, Dict[str, Dict[str, Any]]] = {
            "cve": {str(item["_id"]): dict(item) for item in cves},
            "urlhaus": {str(item["_id"]): dict(item) for item in urlhaus},
            "dread": {str(item["_id"]): dict(item) for item in dread},
        }

    def get_unprocessed(self, source: str, limit: int = 10) -> List[Dict[str, Any]]:
        return [dict(item) for item in self.records[source].values() if not item.get("processed")][:limit]

    def update_analysis(self, source: str, doc_id: Any, analysis: Dict[str, Any]) -> None:
        record = self.records[source][str(doc_id)]
        record["processed"] = True
        record["analysis"] = dict(analysis)
        record["analysis_updated_at"] = GENERATED_AT

    def find_related_urlhaus(self, keywords: List[str], limit: int = 25) -> List[Dict[str, Any]]:
        return self._find_related("urlhaus", keywords, fields=("url", "threat", "tags"), limit=limit)

    def find_related_dread(self, keywords: List[str], limit: int = 25) -> List[Dict[str, Any]]:
        return self._find_related("dread", keywords, fields=("title", "content", "category"), limit=limit)

    def find_related_cves(self, keywords: List[str], limit: int = 25) -> List[Dict[str, Any]]:
        return self._find_related("cve", keywords, fields=("_id", "descriptions"), limit=limit)

    def get_recent_findings(self, source: str, limit: int = 10) -> List[Dict[str, Any]]:
        docs = [dict(item) for item in self.records[source].values() if item.get("analysis")]
        return sorted(docs, key=lambda item: str(item.get("_id")), reverse=False)[:limit]

    def get_finding_by_entity_id(self, source: str, entity_id: str) -> Optional[Dict[str, Any]]:
        for record in self.records[source].values():
            analysis = record.get("analysis", {}) or {}
            if entity_id in {str(record.get("_id")), str(analysis.get("entity_id"))}:
                return dict(record)
        return None

    def get_cve_model_results(self) -> List[Dict[str, Any]]:
        rows = []
        for record in self.records["cve"].values():
            analysis = dict(record.get("analysis") or {})
            evidence = dict(analysis.get("evidence") or {})
            rows.append(
                {
                    "entity_id": analysis.get("entity_id", record.get("_id")),
                    "risk_score": analysis.get("risk_score", 0.0),
                    "confidence": analysis.get("confidence", 0.0),
                    "cvss_score": evidence.get("cvss_score", 0.0),
                    "evidence": evidence,
                    "feature_breakdown": dict(analysis.get("feature_breakdown") or {}),
                }
            )
        return sorted(rows, key=lambda item: str(item["entity_id"]))

    def analyzed_records(self) -> Dict[str, List[Dict[str, Any]]]:
        return {
            source: [dict(item) for item in sorted(records.values(), key=lambda row: str(row.get("_id")))]
            for source, records in self.records.items()
        }

    def _find_related(self, source: str, keywords: List[str], *, fields: Iterable[str], limit: int) -> List[Dict[str, Any]]:
        terms = {str(term).lower() for term in keywords if str(term).strip()}
        hits: List[Dict[str, Any]] = []
        for record in self.records[source].values():
            text = _flatten_record_text(record, fields)
            if any(term in text for term in terms):
                hits.append(dict(record))
        return hits[:limit]


def run_thesis_scenario(report_path: str | Path | None = None) -> Dict[str, Any]:
    cves = fixture_cves()
    urlhaus = fixture_urlhaus()
    dread = fixture_dread()
    assets = fixture_assets()
    vulnerable_products = fixture_vulnerable_products()
    repository = InMemoryScenarioRepository(cves, urlhaus, dread)
    job_repository = InMemoryJobRepository()
    event_logger = StructuredJobLogger()
    metrics = WorkerMetrics()
    clock = DeterministicClock()
    executor = WorkerJobExecutor(
        repository=job_repository,
        event_logger=event_logger,
        metrics=metrics,
        clock=clock,
        analysis_version="thesis-fixture-v1",
    )
    with _fixed_analysis_age_clock():
        thinker = DiagnosticAgent()
        recommender = RecommenderAgent()

        for source in ("cve", "urlhaus", "dread"):
            for record in repository.get_unprocessed(source, limit=100):
                executor.process_document(source, record, repository, thinker, recommender)

        duplicate_outcome = executor.process_document("cve", cves[0], repository, thinker, recommender)
    model_results = fixture_evaluation_model_results()
    evaluation = build_evaluation_report(
        model_results=model_results,
        kev_loader=fixture_kev_json,
        epss_loader=fixture_epss_csv,
        k_values=(1, 3, 5, 10),
        generated_at=GENERATED_AT,
    )
    operational_risk = _build_operational_risk(repository, assets, vulnerable_products)
    correlation_decisions = _build_correlation_decisions()
    report = {
        "generated_at": GENERATED_AT,
        "fixture_metadata": {
            "cve_count": len(cves),
            "urlhaus_count": len(urlhaus),
            "dread_count": len(dread),
            "asset_count": len(assets),
            "kev_count": evaluation["dataset"]["kev_count"],
            "epss_count": evaluation["dataset"]["epss_available_count"],
            "evaluation_record_count": evaluation["dataset"]["record_count"],
        },
        "source_results": _source_results(repository),
        "api_compatible_results": _api_results(repository),
        "job_lifecycle": {
            "metrics": metrics.to_dict(),
            "jobs": [job.to_dict() for job in sorted(job_repository.jobs.values(), key=lambda item: item.job_id)],
            "duplicate_suppressed": bool(duplicate_outcome.skipped_duplicate),
            "events": [record for record in event_logger.records],
        },
        "correlation_decisions": correlation_decisions,
        "asset_operational_risk": operational_risk,
        "evaluation": evaluation,
        "notable_cases": _notable_cases(repository, operational_risk, correlation_decisions),
    }
    if report_path is not None:
        path = Path(report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        write_report_json(report, path)
    return json.loads(json.dumps(report, sort_keys=True, default=str))


@contextmanager
def _fixed_analysis_age_clock() -> Iterator[None]:
    original = risk_engine_module.calculate_age_days
    risk_engine_module.calculate_age_days = _fixture_age_days
    try:
        yield
    finally:
        risk_engine_module.calculate_age_days = original


def _fixture_age_days(value: Any) -> Optional[int]:
    if not value:
        return None
    text = str(value)
    age_by_date = {
        "2026-06-09": 1,
        "2026-06-08": 2,
        "2026-02-11": 119,
        "2026-02-10": 120,
        "2015-02-01": 4148,
        "2015-01-01": 4179,
    }
    for prefix, age in age_by_date.items():
        if text.startswith(prefix):
            return age
    return None


def _source_results(repository: InMemoryScenarioRepository) -> List[Dict[str, Any]]:
    rows = []
    for source, records in repository.analyzed_records().items():
        for record in records:
            analysis = dict(record.get("analysis") or {})
            rows.append(
                {
                    "source": source,
                    "entity_id": analysis.get("entity_id"),
                    "risk_score": analysis.get("risk_score"),
                    "risk_level": analysis.get("risk_level"),
                    "confidence": analysis.get("confidence"),
                    "evidence_summary": {
                        "related_urlhaus_count": (analysis.get("evidence") or {}).get("related_urlhaus_count"),
                        "related_dread_count": (analysis.get("evidence") or {}).get("related_dread_count"),
                        "related_cve_count": (analysis.get("evidence") or {}).get("related_cve_count"),
                    },
                    "orchestration_summary": {
                        "trace_count": len(analysis.get("orchestration_trace", []) or []),
                        "plan_count": len(analysis.get("execution_plan", []) or []),
                        "critic_status": (analysis.get("critic_review") or {}).get("status"),
                    },
                }
            )
    return sorted(rows, key=lambda item: (item["source"], str(item["entity_id"])))


def _api_results(repository: InMemoryScenarioRepository) -> Dict[str, Any]:
    summary = FindingSummary(**to_finding_summary("cve", repository.get_recent_findings("cve", limit=1)[0]).model_dump()).model_dump()
    detail_doc = repository.get_finding_by_entity_id("cve", "CVE-2026-9001")
    detail = FindingDetail(**to_finding_detail("cve", detail_doc).model_dump()).model_dump()
    analyze = AnalyzeResponse(**dict(detail, entity_type="cve")).model_dump()
    return {
        "finding_summary_keys": sorted(summary.keys()),
        "finding_detail_keys": sorted(detail.keys()),
        "analyze_response_keys": sorted(analyze.keys()),
        "sample_summary": summary,
    }


def _build_operational_risk(
    repository: InMemoryScenarioRepository,
    assets: List[Asset],
    vulnerable_products: Dict[str, List[VulnerableProduct]],
) -> List[Dict[str, Any]]:
    service = OperationalRiskService()
    rows = []
    for cve_id, products in vulnerable_products.items():
        record = repository.get_finding_by_entity_id("cve", cve_id)
        analysis = dict(record.get("analysis") or {}) if record else {"entity_id": cve_id, "risk_score": 0.0, "confidence": 0.0}
        for asset in assets:
            result = service.assess(analysis, products, asset)
            payload = result.to_dict()
            payload["cve_id"] = cve_id
            rows.append(payload)
    return sorted(rows, key=lambda item: (item["cve_id"], item["asset_id"]))


def _build_correlation_decisions() -> List[Dict[str, Any]]:
    candidates = [
        build_correlation_candidate(
            source="urlhaus",
            source_identifier="CVE-2026-9001",
            target_identifier="UH-9001",
            relation_type="cve_ioc",
            lexical=0.5,
            semantic=0.4,
            temporal=0.8,
            entity_score=0.6,
            shared_term_count=3,
            exact_cve=True,
            high_signal_term_hits=2,
            raw_reference="https://malware.example/CVE-2026-9001/payload.exe",
        ),
        build_correlation_candidate(
            source="urlhaus",
            source_identifier="CVE-2026-9002",
            target_identifier="UH-9002",
            relation_type="cve_ioc",
            lexical=0.03,
            semantic=0.14,
            temporal=0.2,
            entity_score=0.32,
            shared_term_count=1,
            exact_cve=False,
            high_signal_term_hits=0,
            raw_reference="https://cdn.example/vpn-admin-check",
        ),
        build_correlation_candidate(
            source="urlhaus",
            source_identifier="CVE-2026-9005",
            target_identifier="UH-9005",
            relation_type="cve_ioc",
            lexical=0.18,
            semantic=0.24,
            temporal=0.7,
            entity_score=0.42,
            shared_term_count=2,
            exact_cve=False,
            high_signal_term_hits=2,
            raw_reference="https://payloads.example/vpn-gateway-rce-loader.exe",
        ),
        build_correlation_candidate(
            source="urlhaus",
            source_identifier="CVE-2026-9016",
            target_identifier="UH-9016",
            relation_type="cve_ioc",
            lexical=0.04,
            semantic=0.02,
            temporal=0.0,
            entity_score=0.0,
            shared_term_count=1,
            exact_cve=False,
            high_signal_term_hits=0,
            raw_reference="https://generic.example/windows/update",
        ),
        build_correlation_candidate(
            source="dread",
            source_identifier="CVE-2026-9017",
            target_identifier="DR-9017",
            relation_type="cve_forum",
            lexical=0.04,
            semantic=0.13,
            temporal=0.2,
            entity_score=0.20,
            shared_term_count=1,
            exact_cve=False,
            high_signal_term_hits=1,
            raw_reference="dread://DR-9017",
        ),
        build_correlation_candidate(
            source="dread",
            source_identifier="CVE-2015-0001",
            target_identifier="DR-9002",
            relation_type="cve_forum",
            lexical=0.0,
            semantic=0.05,
            temporal=0.0,
            entity_score=0.0,
            shared_term_count=0,
            exact_cve=False,
            high_signal_term_hits=0,
            raw_reference="dread://DR-9002",
        ),
    ]
    decisions = []
    for candidate in candidates:
        decision = decide_correlation_candidate(candidate, min_shared_terms=2, min_lexical_overlap=0.08, min_semantic_support=0.22)
        decisions.append({**decision.to_dict(), **correlation_decision_row(candidate, decision)})
    return sorted(decisions, key=lambda item: (item["status"], item["target_identifier"]))


def _notable_cases(repository: InMemoryScenarioRepository, operational_risk: List[Dict[str, Any]], decisions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    high = repository.get_finding_by_entity_id("cve", "CVE-2026-9001")
    stale = repository.get_finding_by_entity_id("cve", "CVE-2015-0001")
    applicable = next(item for item in operational_risk if item["cve_id"] == "CVE-2026-9001" and item["asset_id"] == "asset-vpn-prod")
    no_controls = next(item for item in operational_risk if item["cve_id"] == "CVE-2026-9001" and item["asset_id"] == "asset-vpn-prod-no-controls")
    patched = next(item for item in operational_risk if item["cve_id"] == "CVE-2026-9001" and item["asset_id"] == "asset-vpn-prod-patched")
    non_applicable = next(item for item in operational_risk if item["cve_id"] == "CVE-2026-9001" and item["asset_id"] == "asset-backup-internal")
    controlled_comparison = next(item for item in operational_risk if item["cve_id"] == "CVE-2026-9002" and item["asset_id"] == "asset-vpn-prod")
    uncontrolled_comparison = next(item for item in operational_risk if item["cve_id"] == "CVE-2026-9002" and item["asset_id"] == "asset-vpn-prod-no-controls")
    return [
        {
            "case": "high_risk_correlated",
            "entity_id": "CVE-2026-9001",
            "risk_score": high["analysis"]["risk_score"],
            "accepted_decisions": sum(1 for item in decisions if item["status"] == "accepted"),
        },
        {
            "case": "medium_cvss_high_epss_kev",
            "entity_id": "CVE-2026-9002",
            "description": "Medium CVSS item that should rank above some high-CVSS controls because EPSS and KEV are strong.",
        },
        {
            "case": "high_cvss_low_external_evidence",
            "entity_id": "CVE-2026-9007",
            "description": "High CVSS item with low EPSS and no accepted external evidence.",
        },
        {
            "case": "dread_only_manual_review",
            "entity_id": "CVE-2026-9017",
            "manual_review_decisions": sum(1 for item in decisions if item["source_identifier"] == "CVE-2026-9017" and item["status"] == "manual_review"),
        },
        {
            "case": "asset_applicability_difference",
            "entity_id": "CVE-2026-9001",
            "generic_cve_risk_score": applicable["source_risk_score"],
            "applicable_asset_score": applicable["final_operational_risk_score"],
            "non_applicable_asset_score": non_applicable["final_operational_risk_score"],
            "applicable_asset_id": applicable["asset_id"],
            "non_applicable_asset_id": non_applicable["asset_id"],
        },
        {
            "case": "non_applicable_asset",
            "entity_id": "CVE-2026-9001",
            "generic_cve_risk_score": applicable["source_risk_score"],
            "applicable_asset_score": applicable["final_operational_risk_score"],
            "non_applicable_asset_score": non_applicable["final_operational_risk_score"],
        },
        {
            "case": "patched_asset_reduction",
            "entity_id": "CVE-2026-9001",
            "generic_cve_risk_score": patched["source_risk_score"],
            "unpatched_asset_score": no_controls["final_operational_risk_score"],
            "patched_asset_score": patched["final_operational_risk_score"],
            "unpatched_asset_id": no_controls["asset_id"],
            "patched_asset_id": patched["asset_id"],
        },
        {
            "case": "compensating_control_reduction",
            "entity_id": "CVE-2026-9002",
            "generic_cve_risk_score": controlled_comparison["source_risk_score"],
            "uncontrolled_asset_score": uncontrolled_comparison["final_operational_risk_score"],
            "controlled_asset_score": controlled_comparison["final_operational_risk_score"],
            "compensating_control_reduction": controlled_comparison["compensating_control_reduction"],
            "uncontrolled_asset_id": uncontrolled_comparison["asset_id"],
            "controlled_asset_id": controlled_comparison["asset_id"],
        },
        {
            "case": "stale_low_risk",
            "entity_id": "CVE-2015-0001",
            "risk_score": stale["analysis"]["risk_score"],
        },
    ]


def _flatten_record_text(record: Mapping[str, Any], fields: Iterable[str]) -> str:
    values: List[str] = []
    for field in fields:
        value = record.get(field)
        if isinstance(value, list):
            values.extend(_flatten_list(value))
        elif value is not None:
            values.append(str(value))
    return " ".join(values).lower()


def _flatten_list(values: Iterable[Any]) -> List[str]:
    out: List[str] = []
    for value in values:
        if isinstance(value, Mapping):
            out.extend(str(item) for item in value.values())
        else:
            out.append(str(value))
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Run deterministic thesis end-to-end scenario")
    parser.add_argument("--output", default=str(DEFAULT_REPORT_PATH), help="Path to write the JSON report")
    args = parser.parse_args()
    report = run_thesis_scenario(args.output)
    print(json.dumps({"output": args.output, "source_results": len(report["source_results"]), "duplicate_suppressed": report["job_lifecycle"]["duplicate_suppressed"]}, sort_keys=True))


if __name__ == "__main__":
    main()
