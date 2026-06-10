from __future__ import annotations

import inspect
from datetime import datetime
from typing import Any, Dict, List, Optional

import pymongo
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from agents.diagnostic import DiagnosticAgent
from agents.recommender import RecommenderAgent
from api.mappers import evidence_summary as _evidence_summary
from api.mappers import to_finding_detail as _to_finding_detail
from api.mappers import to_finding_summary as _to_finding_summary
from api.audit import AuditEvent, AuditOutcome, StructuredAuditLogger
from api.schemas import AnalyzeResponse, BatchAnalyzeItem, BatchAnalyzeResponse, CaseStudyResponse, ComparisonRow, EvaluationDiagnosticsResponse, EvaluationExportResponse, EvaluationSnapshotResponse, EvaluationSummaryResponse, ExecutionPlanResponse, FindingDetail, FindingSummary, HealthResponse, MethodologySummaryResponse, RefinementSummaryResponse, ReportBriefResponse, SettingsResponse, StatusOverviewResponse
from api.security import APIKeyAuthenticator, AuthenticatedActor, Authorizer, Permission, permission_dependency
from config import APP_VERSION, DB_NAME, MONGO_URI, get_settings
from core.database import DatabaseManager
from evaluation.comparative import build_case_study_rows, build_comparison_summary, build_cve_comparison_frame, build_cve_rows_from_docs
from evaluation.ml_refinement import summarize_refinement_model
from reporting.narrative import build_report_brief
from reporting.technical_summary import build_methodology_summary


diagnostic_agent = DiagnosticAgent()
recommender_agent = RecommenderAgent()
SETTINGS = get_settings()

app = FastAPI(title="Threat-Agent API", version="0.2.0", description="API for multi-source cyber threat intelligence analysis results.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=SETTINGS.api.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
audit_logger = StructuredAuditLogger()
authenticator = APIKeyAuthenticator(SETTINGS.security, audit_sink=audit_logger)
authorizer = Authorizer(audit_sink=audit_logger)
app.state.audit_logger = audit_logger
app.state.authenticator = authenticator
app.state.authorizer = authorizer

READ_ANALYSES = permission_dependency(Permission.READ_ANALYSES, target="analyses")
TRIGGER_ANALYSIS = permission_dependency(Permission.TRIGGER_ANALYSIS, target="analysis")
VIEW_JOBS = permission_dependency(Permission.VIEW_JOBS, target="jobs")
ADMINISTER_SYSTEM = permission_dependency(Permission.ADMINISTER_SYSTEM, target="system")


class APIRepository:
    def __init__(self) -> None:
        self.client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=SETTINGS.database.server_selection_timeout_ms, connectTimeoutMS=SETTINGS.database.connect_timeout_ms)
        self.db = self.client[DB_NAME]
        self.collections = {"cve": self.db["cve_intel"], "urlhaus": self.db["urlhaus_intel"], "dread": self.db["dread_intel"]}

    def ping(self) -> bool:
        try:
            self.client.admin.command("ping")
            return True
        except Exception:
            return False

    def get_recent_findings(self, source: str, limit: int = 10) -> List[Dict[str, Any]]:
        return list(self.collections[source].find({"analysis": {"$exists": True}}).sort([("analysis.analyzed_at", pymongo.DESCENDING), ("_id", pymongo.DESCENDING)]).limit(limit))

    def get_top_risky_findings(self, source: Optional[str] = None, limit: int = 10, mode: str = "top") -> List[Dict[str, Any]]:
        collections = [source] if source else ["cve", "urlhaus", "dread"]
        all_docs: List[Dict[str, Any]] = []
        for src in collections:
            for doc in self.collections[src].find({"analysis": {"$exists": True}}):
                doc["_source"] = src
                all_docs.append(doc)

        def risk(doc: Dict[str, Any]) -> float:
            return float((doc.get("analysis", {}) or {}).get("risk_score", 0.0) or 0.0)

        def confidence(doc: Dict[str, Any]) -> float:
            return float((doc.get("analysis", {}) or {}).get("confidence", 0.0) or 0.0)

        def evidence_strength(doc: Dict[str, Any]) -> int:
            return int(sum(1 for item in _evidence_summary(doc.get("analysis", {}) or {}).values() if item is True) * 10) + int((_evidence_summary(doc.get("analysis", {}) or {}).get("urlhaus_accepted") or 0) * 4) + int((_evidence_summary(doc.get("analysis", {}) or {}).get("exact_cve_hits") or 0) * 8) + int((_evidence_summary(doc.get("analysis", {}) or {}).get("high_signal_hits") or 0) * 6)

        def analyzed_ts(doc: Dict[str, Any]) -> float:
            return _parse_datetime_sort_value((doc.get("analysis", {}) or {}).get("analyzed_at"))

        def published_ts(doc: Dict[str, Any]) -> float:
            return _parse_datetime_sort_value(doc.get("published") or doc.get("date_added") or doc.get("created_at"))

        if mode == "highest_confidence":
            all_docs.sort(key=lambda doc: (confidence(doc), risk(doc), analyzed_ts(doc)), reverse=True)
        elif mode == "active_evidence":
            all_docs.sort(key=lambda doc: (evidence_strength(doc), risk(doc), confidence(doc)), reverse=True)
        elif mode == "needs_review":
            all_docs.sort(key=lambda doc: (risk(doc) >= 6.5, risk(doc), 1.0 - confidence(doc), evidence_strength(doc)), reverse=True)
        elif mode == "recent_high":
            all_docs.sort(key=lambda doc: (published_ts(doc), risk(doc), confidence(doc)), reverse=True)
        else:
            all_docs.sort(key=lambda doc: (risk(doc), confidence(doc), analyzed_ts(doc)), reverse=True)
        return all_docs[:limit]

    def get_cve_analysis_docs(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        projection = {
            "_id": 1,
            "published": 1,
            "descriptions": 1,
            "analysis.risk_score": 1,
            "analysis.risk_level": 1,
            "analysis.confidence": 1,
            "analysis.counterfactuals": 1,
            "analysis.source_contributions": 1,
            "analysis.relation_summary": 1,
            "analysis.evidence.cvss_score": 1,
            "analysis.evidence.age_days": 1,
            "analysis.evidence.related_urlhaus_count": 1,
            "analysis.evidence.related_dread_count": 1,
            "analysis.evidence.keywords": 1,
            "analysis.feature_breakdown.base_cvss_component": 1,
            "analysis.feature_breakdown.recentness_bonus": 1,
            "analysis.feature_breakdown.urlhaus_correlation_bonus": 1,
            "analysis.feature_breakdown.dread_correlation_bonus": 1,
            "analysis.feature_breakdown.graph_bonus": 1,
            "analysis.feature_breakdown.pre_graph_score": 1,
            "analysis.feature_breakdown.final_score": 1,
            "analysis.feature_breakdown.urlhaus_avg_semantic_score": 1,
            "analysis.feature_breakdown.dread_avg_semantic_score": 1,
            "analysis.diagnosis": 1,
            "analysis.graph_summary.centrality_score": 1,
            "analysis.graph_summary.average_edge_confidence": 1,
            "analysis.graph_summary.structural_strength": 1,
            "analysis.critic_review.status": 1,
            "analysis.pipeline_version": 1,
            "analysis.persistence_meta": 1,
            "analysis.recommendations": 1,
        }
        cursor = self.collections["cve"].find({"analysis": {"$exists": True}}, projection).sort([("analysis.risk_score", pymongo.DESCENDING), ("_id", pymongo.DESCENDING)])
        if limit:
            cursor = cursor.limit(limit)
        return list(cursor)

    def get_finding_by_entity_id(self, source: str, entity_id: str) -> Optional[Dict[str, Any]]:
        query = {"analysis": {"$exists": True}, "$or": [{"analysis.entity_id": entity_id}, {"_id": entity_id}, {"urlhaus_id": entity_id}, {"url": entity_id}, {"title": entity_id}]}
        return self.collections[source].find_one(query)


repo = APIRepository()
analysis_db = DatabaseManager()


def _validate_source(source: str) -> None:
    if source not in {"cve", "urlhaus", "dread"}:
        raise HTTPException(status_code=400, detail="Unsupported source")


def _parse_datetime_sort_value(value: Any) -> float:
    if value is None:
        return 0.0
    if isinstance(value, datetime):
        return value.timestamp()
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return 0.0

def _audit(actor: Optional[AuthenticatedActor], action: str, target: str, outcome: AuditOutcome, details: Optional[Dict[str, Any]] = None) -> None:
    actor_id = actor.actor_id if actor else "system"
    role = actor.role.value if actor else "system"
    audit_logger.write(AuditEvent(actor_id=actor_id, role=role, action=action, target=target, outcome=outcome, details=details or {}))


def _analyze(source: str, payload: dict, persist: bool = False, actor: Optional[AuthenticatedActor] = None) -> AnalyzeResponse:
    _validate_source(source)
    _audit(actor, "analysis_trigger", source, AuditOutcome.SUCCESS, {"persist": persist})
    result = diagnostic_agent.analyze(source, payload, db=analysis_db)
    if result is None:
        raise HTTPException(status_code=400, detail="Analysis returned no result")
    result["recommendations"] = recommender_agent.suggest(analysis_result=result, source=source, original_doc=payload)
    if persist:
        result["source"] = source
        result["pipeline_version"] = result.get("pipeline_version") or APP_VERSION
        analysis_db.persist_analysis_result(source=source, original_doc=payload, analysis_result=result)
    return AnalyzeResponse(**result)


def _invoke_analyze(source: str, payload: dict, *, persist: bool = False, actor: Optional[AuthenticatedActor] = None) -> AnalyzeResponse:
    if "actor" in inspect.signature(_analyze).parameters:
        return _analyze(source, payload, persist=persist, actor=actor)
    return _analyze(source, payload, persist=persist)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    db_ok = repo.ping()
    return HealthResponse(status="ok" if db_ok else "degraded", service="threat-agent-api", database="ok" if db_ok else "unreachable")


@app.get("/settings", response_model=SettingsResponse)
def settings(actor: AuthenticatedActor = ADMINISTER_SYSTEM) -> SettingsResponse:
    _audit(actor, "admin_view_settings", "settings", AuditOutcome.SUCCESS)
    return SettingsResponse(**SETTINGS.to_dict())


@app.get("/sources")
def list_sources() -> Dict[str, List[str]]:
    return {"sources": ["cve", "urlhaus", "dread"]}


@app.post("/analyze/cve", response_model=AnalyzeResponse)
def analyze_cve(payload: dict, actor: AuthenticatedActor = TRIGGER_ANALYSIS):
    return _invoke_analyze("cve", payload, actor=actor)


@app.post("/analyze/urlhaus", response_model=AnalyzeResponse)
def analyze_urlhaus(payload: dict, actor: AuthenticatedActor = TRIGGER_ANALYSIS):
    return _invoke_analyze("urlhaus", payload, actor=actor)


@app.post("/analyze/dread", response_model=AnalyzeResponse)
def analyze_dread(payload: dict, actor: AuthenticatedActor = TRIGGER_ANALYSIS):
    return _invoke_analyze("dread", payload, actor=actor)


@app.post("/analyze/{source}/persist", response_model=AnalyzeResponse)
def analyze_and_persist(source: str, payload: dict, actor: AuthenticatedActor = TRIGGER_ANALYSIS):
    return _invoke_analyze(source, payload, persist=True, actor=actor)


@app.post("/analyze/batch/{source}", response_model=BatchAnalyzeResponse)
def analyze_batch(source: str, payloads: List[dict], persist: bool = Query(False), limit: int = Query(25, ge=1, le=250), actor: AuthenticatedActor = TRIGGER_ANALYSIS) -> BatchAnalyzeResponse:
    _validate_source(source)
    limited = payloads[:limit]
    results: List[AnalyzeResponse] = []
    items: List[BatchAnalyzeItem] = []
    failures = 0
    for index, payload in enumerate(limited):
        try:
            result = _invoke_analyze(source, payload, persist=persist, actor=actor)
            results.append(result)
            items.append(BatchAnalyzeItem(index=index, success=True, entity_id=result.entity_id, risk_level=result.risk_level, risk_score=result.risk_score))
        except HTTPException as exc:
            failures += 1
            items.append(BatchAnalyzeItem(index=index, success=False, error=str(exc.detail)))
        except Exception as exc:
            failures += 1
            items.append(BatchAnalyzeItem(index=index, success=False, error=str(exc)))
    return BatchAnalyzeResponse(source=source, requested=len(payloads), analyzed=len(results), failed=failures, persisted=persist, results=results, items=items)


@app.get("/status/overview", response_model=StatusOverviewResponse)
def status_overview(actor: AuthenticatedActor = VIEW_JOBS) -> StatusOverviewResponse:
    return StatusOverviewResponse(**analysis_db.get_status_overview())


@app.get("/findings/recent", response_model=List[FindingSummary])
def recent_findings(source: str = Query(..., pattern="^(cve|urlhaus|dread)$"), limit: int = Query(10, ge=1, le=100), actor: AuthenticatedActor = READ_ANALYSES) -> List[FindingSummary]:
    docs = repo.get_recent_findings(source=source, limit=limit)
    return [_to_finding_summary(source, doc) for doc in docs]


@app.get("/findings/top", response_model=List[FindingSummary])
def top_findings(
    source: Optional[str] = Query(None, pattern="^(cve|urlhaus|dread)$"),
    limit: int = Query(10, ge=1, le=100),
    mode: str = Query("top", pattern="^(top|recent_high|highest_confidence|active_evidence|needs_review)$"),
    actor: AuthenticatedActor = READ_ANALYSES,
) -> List[FindingSummary]:
    docs = repo.get_top_risky_findings(source=source, limit=limit, mode=mode)
    return [_to_finding_summary(str(doc.get("_source")), doc) for doc in docs]


@app.get("/findings/search", response_model=List[FindingSummary])
def search_findings(source: str = Query(..., pattern="^(cve|urlhaus|dread)$"), query: str = Query(..., min_length=1), limit: int = Query(10, ge=1, le=100), actor: AuthenticatedActor = READ_ANALYSES) -> List[FindingSummary]:
    docs = analysis_db.search_analyzed_findings(source=source, query=query, limit=limit)
    return [_to_finding_summary(source, doc) for doc in docs]


@app.get("/findings/detail", response_model=FindingDetail)
def finding_detail(source: str = Query(..., pattern="^(cve|urlhaus|dread)$"), entity_id: str = Query(..., min_length=1), actor: AuthenticatedActor = READ_ANALYSES) -> FindingDetail:
    doc = repo.get_finding_by_entity_id(source=source, entity_id=entity_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _to_finding_detail(source, doc)


def _build_cve_evaluation_snapshot(limit: int = 50, top_k: int = 10) -> Dict[str, Any]:
    docs = repo.get_cve_analysis_docs(limit=limit)
    rows = build_cve_rows_from_docs(docs)
    frame = build_cve_comparison_frame(rows)
    if frame.empty:
        raise HTTPException(status_code=404, detail="No analyzed CVE records available for evaluation")
    summary = build_comparison_summary(frame.to_dict(orient="records"), top_k=top_k)
    display_rows = frame.sort_values(["lift_from_cvss_only", "final_dynamic_score"], ascending=[False, False]).head(min(limit, 25))[["cve_id", "baseline_cvss_only_score", "baseline_plus_correlation", "baseline_plus_semantic", "baseline_plus_graph", "final_dynamic_score", "lift_from_cvss_only", "lift_from_correlation", "graph_only_delta", "semantic_only_delta", "semantic_signal", "risk_level", "confidence", "related_urlhaus_count", "related_dread_count"]].to_dict(orient="records")
    return {"summary": summary, "rows": display_rows}


@app.get("/evaluation/cve", response_model=EvaluationSnapshotResponse)
def evaluation_cve_snapshot(limit: int = Query(25, ge=1, le=100), top_k: int = Query(10, ge=1, le=50), actor: AuthenticatedActor = READ_ANALYSES) -> EvaluationSnapshotResponse:
    return EvaluationSnapshotResponse(**_build_cve_evaluation_snapshot(limit=limit, top_k=top_k))


@app.get("/evaluation/cve/summary", response_model=EvaluationSummaryResponse)
def evaluation_cve_summary(limit: int = Query(100, ge=1, le=500), top_k: int = Query(10, ge=1, le=50), actor: AuthenticatedActor = READ_ANALYSES) -> EvaluationSummaryResponse:
    payload = _build_cve_evaluation_snapshot(limit=limit, top_k=top_k)
    return EvaluationSummaryResponse(**payload["summary"])


@app.get("/evaluation/cve/case-studies", response_model=CaseStudyResponse)
def evaluation_cve_case_studies(limit: int = Query(12, ge=1, le=100), actor: AuthenticatedActor = READ_ANALYSES) -> CaseStudyResponse:
    docs = repo.get_cve_analysis_docs(limit=max(limit * 5, 50))
    rows = build_cve_rows_from_docs(docs)
    return CaseStudyResponse(rows=build_case_study_rows(rows, limit=limit))


@app.get("/evaluation/cve/refinement", response_model=RefinementSummaryResponse)
def evaluation_cve_refinement(limit: int = Query(250, ge=10, le=1000), actor: AuthenticatedActor = READ_ANALYSES) -> RefinementSummaryResponse:
    docs = repo.get_cve_analysis_docs(limit=limit)
    rows = build_cve_rows_from_docs(docs)
    return RefinementSummaryResponse(**summarize_refinement_model(rows))


@app.post("/analyze/plan/{source}", response_model=ExecutionPlanResponse)
def analyze_plan(source: str, payload: dict, actor: AuthenticatedActor = TRIGGER_ANALYSIS) -> ExecutionPlanResponse:
    _validate_source(source)
    _audit(actor, "analysis_plan", source, AuditOutcome.SUCCESS)
    return ExecutionPlanResponse(**diagnostic_agent.plan(source, payload))


@app.get("/evaluation/cve/report-brief", response_model=ReportBriefResponse)
def evaluation_cve_report_brief(limit: int = Query(100, ge=10, le=1000), top_k: int = Query(10, ge=1, le=50), actor: AuthenticatedActor = READ_ANALYSES) -> ReportBriefResponse:
    docs = repo.get_cve_analysis_docs(limit=limit)
    rows = build_cve_rows_from_docs(docs)
    brief = build_report_brief(rows, top_k=top_k)
    if not brief.get("summary"):
        raise HTTPException(status_code=404, detail="No analyzed CVE records available for report brief")
    return ReportBriefResponse(**brief)


@app.get("/evaluation/cve/methodology", response_model=MethodologySummaryResponse)
def evaluation_cve_methodology(limit: int = Query(100, ge=10, le=1000), top_k: int = Query(10, ge=1, le=50), actor: AuthenticatedActor = READ_ANALYSES) -> MethodologySummaryResponse:
    docs = repo.get_cve_analysis_docs(limit=limit)
    rows = build_cve_rows_from_docs(docs)
    summary = build_methodology_summary(rows, top_k=top_k)
    if not summary.get("methodology"):
        raise HTTPException(status_code=404, detail="No analyzed CVE records available for methodology summary")
    return MethodologySummaryResponse(**summary)



def _build_cve_evaluation_diagnostics(limit: int = 250) -> Dict[str, Any]:
    docs = repo.get_cve_analysis_docs(limit=limit)
    if not docs:
        raise HTTPException(status_code=404, detail="No analyzed CVE records available for diagnostics")
    rows = build_cve_rows_from_docs(docs)
    frame = build_cve_comparison_frame(rows)
    record_count = len(docs)
    coverage_rate = round(len(frame) / max(record_count, 1), 4)
    avg_confidence = round(sum(float((d.get("analysis", {}) or {}).get("confidence", 0.0) or 0.0) for d in docs) / max(record_count, 1), 4)
    avg_recommendation_count = round(sum(len(((d.get("analysis", {}) or {}).get("recommendations", [])) or []) for d in docs) / max(record_count, 1), 4)
    pipeline_versions = sorted({
        str(
            (d.get("analysis", {}) or {}).get("pipeline_version")
            or ((d.get("analysis", {}) or {}).get("persistence_meta", {}) or {}).get("pipeline_version")
            or "unknown"
        )
        for d in docs
    })
    risk_levels: Dict[str, int] = {}
    critic_status: Dict[str, int] = {}
    for d in docs:
        a = d.get("analysis", {}) or {}
        risk_levels[str(a.get("risk_level", "UNKNOWN"))] = risk_levels.get(str(a.get("risk_level", "UNKNOWN")), 0) + 1
        status = str((a.get("critic_review", {}) or {}).get("status", "unknown"))
        critic_status[status] = critic_status.get(status, 0) + 1
    return {
        "record_count": record_count,
        "coverage_rate": coverage_rate,
        "avg_confidence": avg_confidence,
        "avg_semantic_signal": round(float(frame["semantic_signal"].mean()), 4) if not frame.empty else 0.0,
        "avg_graph_centrality": round(float(frame["centrality_score"].fillna(0).mean()), 4) if not frame.empty and "centrality_score" in frame else 0.0,
        "avg_source_diversity_score": round(float(frame["source_diversity_score"].mean()), 4) if not frame.empty and "source_diversity_score" in frame else 0.0,
        "avg_recommendation_count": avg_recommendation_count,
        "pipeline_versions": pipeline_versions,
        "risk_level_distribution": risk_levels,
        "critic_status_distribution": critic_status,
    }


@app.get("/evaluation/cve/export", response_model=EvaluationExportResponse)
def evaluation_cve_export(limit: int = Query(100, ge=10, le=1000), top_k: int = Query(10, ge=1, le=50), actor: AuthenticatedActor = READ_ANALYSES) -> EvaluationExportResponse:
    docs = repo.get_cve_analysis_docs(limit=limit)
    rows = build_cve_rows_from_docs(docs)
    frame = build_cve_comparison_frame(rows)
    if frame.empty:
        raise HTTPException(status_code=404, detail="No analyzed CVE records available for export")
    summary = build_comparison_summary(frame.to_dict(orient="records"), top_k=top_k)
    case_rows = build_case_study_rows(rows, limit=min(15, len(rows)))
    refinement = summarize_refinement_model(rows)
    export_rows = frame.sort_values(["lift_from_cvss_only", "final_dynamic_score"], ascending=[False, False]).head(min(limit, 50)).to_dict(orient="records")
    return EvaluationExportResponse(summary=EvaluationSummaryResponse(**summary), rows=[ComparisonRow(**row) for row in export_rows], case_studies=case_rows, refinement=refinement)


@app.get("/evaluation/cve/diagnostics", response_model=EvaluationDiagnosticsResponse)
def evaluation_cve_diagnostics(limit: int = Query(250, ge=10, le=2000), actor: AuthenticatedActor = READ_ANALYSES) -> EvaluationDiagnosticsResponse:
    return EvaluationDiagnosticsResponse(**_build_cve_evaluation_diagnostics(limit=limit))
