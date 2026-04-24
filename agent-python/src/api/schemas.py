from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    service: str
    database: str


class FindingSummary(BaseModel):
    source: str
    entity_id: str
    risk_level: str
    risk_score: float
    confidence: float
    diagnosis: str
    analyzed_at: Optional[str] = None
    pipeline_version: Optional[str] = None
    persistence_meta: Dict[str, Any] = Field(default_factory=dict)


class FindingDetail(BaseModel):
    source: str
    entity_id: str
    risk_level: str
    risk_score: float
    confidence: float
    diagnosis: str
    explanation: List[str]
    recommendations: List[str]
    evidence: Dict[str, Any]
    feature_breakdown: Dict[str, Any]
    graph_summary: Dict[str, Any]
    graph_edges: List[Dict[str, Any]]
    counterfactuals: Dict[str, Any] = Field(default_factory=dict)
    source_contributions: Dict[str, Any] = Field(default_factory=dict)
    relation_summary: Dict[str, Any] = Field(default_factory=dict)
    orchestration_trace: List[Dict[str, Any]] = Field(default_factory=list)
    execution_plan: List[Dict[str, Any]] = Field(default_factory=list)
    critic_review: Dict[str, Any] = Field(default_factory=dict)
    agent_outputs: Dict[str, Any] = Field(default_factory=dict)
    pipeline_version: Optional[str] = None
    persistence_meta: Dict[str, Any] = Field(default_factory=dict)
    analyzed_at: Optional[str] = None


class AnalyzeResponse(BaseModel):
    entity_type: str
    entity_id: str
    risk_level: str
    risk_score: float
    confidence: float
    diagnosis: str
    explanation: List[str]
    recommendations: List[str]
    feature_breakdown: Dict[str, Any]
    graph_summary: Dict[str, Any]
    graph_edges: List[Dict[str, Any]]
    counterfactuals: Dict[str, Any] = Field(default_factory=dict)
    source_contributions: Dict[str, Any] = Field(default_factory=dict)
    relation_summary: Dict[str, Any] = Field(default_factory=dict)
    orchestration_trace: List[Dict[str, Any]] = Field(default_factory=list)
    execution_plan: List[Dict[str, Any]] = Field(default_factory=list)
    critic_review: Dict[str, Any] = Field(default_factory=dict)
    agent_outputs: Dict[str, Any] = Field(default_factory=dict)
    pipeline_version: Optional[str] = None
    persistence_meta: Dict[str, Any] = Field(default_factory=dict)


class ComparisonRow(BaseModel):
    cve_id: str
    baseline_cvss_only_score: float
    baseline_plus_correlation: float
    baseline_plus_semantic: Optional[float] = None
    baseline_plus_graph: float
    final_dynamic_score: float
    lift_from_cvss_only: float
    lift_from_correlation: float
    graph_only_delta: float
    semantic_only_delta: Optional[float] = None
    semantic_signal: Optional[float] = None
    risk_level: Optional[str] = None
    confidence: Optional[float] = None
    related_urlhaus_count: Optional[int] = None
    related_dread_count: Optional[int] = None


class EvaluationSummaryResponse(BaseModel):
    record_count: int
    avg_cvss_only_score: float
    avg_cvss_plus_correlated: float
    avg_cvss_plus_graph: float
    avg_cvss_plus_semantic: Optional[float] = None
    avg_final_dynamic_score: float
    avg_lift_from_cvss_only: float
    avg_lift_from_correlation: Optional[float] = None
    avg_graph_only_delta: float
    avg_semantic_only_delta: Optional[float] = None
    avg_semantic_signal: Optional[float] = None
    avg_source_diversity_score: Optional[float] = None
    avg_graph_support_ratio: Optional[float] = None
    top_k: int
    top_overlap_cvss_vs_dynamic: int
    top_overlap_graph_vs_dynamic: int
    top_overlap_semantic_vs_dynamic: Optional[int] = None
    dynamic_vs_cvss_hit_rate: Optional[float] = None
    dynamic_vs_graph_hit_rate: Optional[float] = None
    dynamic_vs_semantic_hit_rate: Optional[float] = None
    map_dynamic_vs_cvss: Optional[float] = None
    map_dynamic_vs_graph: Optional[float] = None
    map_dynamic_vs_semantic: Optional[float] = None
    reprioritized_count_lift_ge_1_5: int
    graph_supported_count: int
    semantic_supported_count: Optional[int] = None
    top_decile_avg_dynamic_score: Optional[float] = None
    top_decile_avg_semantic_signal: Optional[float] = None
    ndcg_dynamic_top_k: Optional[float] = None
    reprioritized_examples: List[Dict[str, Any]]


class EvaluationSnapshotResponse(BaseModel):
    summary: EvaluationSummaryResponse
    rows: List[ComparisonRow]




class EvaluationDiagnosticsResponse(BaseModel):
    record_count: int
    coverage_rate: float
    avg_confidence: float
    avg_semantic_signal: float
    avg_graph_centrality: float
    avg_source_diversity_score: float
    avg_recommendation_count: float
    pipeline_versions: List[str]
    risk_level_distribution: Dict[str, int]
    critic_status_distribution: Dict[str, int]

class SettingsResponse(BaseModel):
    database: Dict[str, Any]
    llm: Dict[str, Any]
    runtime: Dict[str, Any]
    scoring: Dict[str, Any]
    retrieval: Dict[str, Any]
    semantic: Dict[str, Any]


class CaseStudyRow(BaseModel):
    cve_id: str
    baseline_cvss_only_score: float
    baseline_plus_correlation: float
    baseline_plus_semantic: Optional[float] = None
    baseline_plus_graph: float
    final_dynamic_score: float
    lift_from_cvss_only: float
    lift_from_correlation: float
    graph_only_delta: float
    semantic_only_delta: Optional[float] = None
    semantic_signal: Optional[float] = None
    correlation_count: Optional[int] = None
    source_diversity_score: Optional[float] = None
    risk_level: Optional[str] = None
    confidence: Optional[float] = None
    description: Optional[str] = None


class CaseStudyResponse(BaseModel):
    rows: List[CaseStudyRow]


class RefinementSummaryResponse(BaseModel):
    record_count: int
    positive_rate: float
    iterations: Optional[int] = None
    intercept: Optional[float] = None
    feature_importance: List[Dict[str, Any]]


class ReportBriefResponse(BaseModel):
    summary: Dict[str, Any]
    case_studies: List[Dict[str, Any]]
    refinement: Dict[str, Any]
    markdown: str


class MethodologySummaryResponse(BaseModel):
    methodology: Dict[str, Any]
    summary: Dict[str, Any]
    refinement: Dict[str, Any]
    case_studies: List[Dict[str, Any]]
    strengths: List[str]
    markdown: str


class ExecutionPlanResponse(BaseModel):
    source: str
    execution_plan: List[Dict[str, Any]]


class BatchAnalyzeItem(BaseModel):
    index: int
    success: bool
    entity_id: Optional[str] = None
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    error: Optional[str] = None


class BatchAnalyzeResponse(BaseModel):
    source: str
    requested: int
    analyzed: int
    failed: int
    persisted: bool
    results: List[AnalyzeResponse]
    items: List[BatchAnalyzeItem] = Field(default_factory=list)


class SourceStatusItem(BaseModel):
    total: int
    processed: int
    unprocessed: int
    analyzed: int
    analysis_coverage: float
    avg_risk_score: float


class StatusOverviewResponse(BaseModel):
    sources: Dict[str, SourceStatusItem]
    totals: Dict[str, Any]
    pipeline_version: str


class EvaluationExportResponse(BaseModel):
    summary: EvaluationSummaryResponse
    rows: List[ComparisonRow]
    case_studies: List[CaseStudyRow]
    refinement: Dict[str, Any]
