export const criticalCorrelatedCveSummary = {
  source: "cve",
  entity_id: "CVE-2026-9101",
  risk_level: "CRITICAL",
  risk_score: 10,
  confidence: 0.95,
  diagnosis: "CVE-2026-9101 evaluated as CRITICAL.",
  analyzed_at: "2026-06-10T14:35:05Z",
  evidence_summary: {
    cvss_score: 9.8,
    accepted_match_count: 1,
    rejected_match_count: 1,
    exact_cve_hits: 1,
    has_active_evidence: true,
  },
};

export const mediumCveSummary = {
  source: "cve",
  entity_id: "CVE-2026-9102",
  risk_level: "MEDIUM",
  risk_score: 5.17,
  confidence: 0.494,
  diagnosis: "CVE-2026-9102 evaluated as MEDIUM.",
  analyzed_at: "2026-06-10T14:35:06Z",
  evidence_summary: {
    cvss_score: 5.4,
    accepted_match_count: 0,
    rejected_match_count: 1,
    exact_cve_hits: 0,
  },
};

export const urlhausIocSummary = {
  source: "urlhaus",
  entity_id: "UH-E2E-9101",
  risk_level: "MEDIUM",
  risk_score: 5.12,
  confidence: 0.682,
  diagnosis: "URLhaus IOC evaluated as MEDIUM.",
  analyzed_at: "2026-06-10T14:35:07Z",
  evidence_summary: {},
};

export const criticalCorrelatedCveDetail = {
  ...criticalCorrelatedCveSummary,
  explanation: ["Base risk derived from CVSS.", "Cross-source urlhaus correlation accepted."],
  recommendations: ["Patch affected VPN gateway.", "Block correlated IOC."],
  evidence: {
    cvss_score: 9.8,
    related_urlhaus_count: 1,
    candidate_urlhaus_count: 2,
    urlhaus_match_stats: {
      accepted_match_count: 1,
      rejected_match_count: 1,
      manual_review_count: 0,
      exact_cve_hits: 1,
      high_signal_hits: 0,
      shared_terms: ["cve-2026-9101"],
      acceptance_reasons: ["exact_cve"],
      accepted_matches: [
        {
          url: "https://malware.invalid/e2e/CVE-2026-9101/payload.exe",
          threat: "malware_download",
          url_status: "online",
          score: 0.9708,
          acceptance_reason: "exact_cve",
          tags: ["ui-fixture", "CVE-2026-9101"],
        },
      ],
    },
    nlp_entities: {
      cve_ids: ["cve-2026-9101"],
      products: ["example vpn gateway"],
      vuln_types: ["remote_code_execution"],
    },
  },
  feature_breakdown: {
    base_cvss_component: 7.06,
    urlhaus_correlation_bonus: 1.51,
    graph_bonus: 0.18,
    final_score: 10,
  },
  confidence_breakdown: {
    metadata_confidence: 0.39,
    external_evidence_confidence: 0.29,
    final_confidence: 0.95,
  },
  graph_summary: {
    node_count: 18,
    edge_count: 17,
    cross_source_edge_count: 1,
    centrality_score: 1.8,
    graph_density: 0.1111,
    relation_distribution: { correlated_urlhaus: 1, mentions_keyword: 10 },
    provenance_distribution: { cve: 2, urlhaus: 1, keyword_extractor: 10 },
  },
  graph_edges: [{ source: "cve:CVE-2026-9101", target: "urlhaus:payload", relation: "correlated_urlhaus", confidence: 0.97 }],
  source_contributions: { urlhaus: 1.51, graph: 0.18 },
  counterfactuals: { score_without_urlhaus: 9.03, score_without_graph: 9.82 },
  critic_review: { status: "passed", summary: "Critic review passed.", warnings: [], issues: [] },
  orchestration_trace: [{ agent: "risk", action: "evaluate", status: "completed" }],
  execution_plan: [{ agent: "risk", action: "score", status: "completed" }],
};

export const statusOverview = {
  sources: {
    cve: { total: 2, processed: 2, unprocessed: 0, analyzed: 2, analysis_coverage: 1, avg_risk_score: 7.58 },
    urlhaus: { total: 2, processed: 2, unprocessed: 0, analyzed: 2, analysis_coverage: 1, avg_risk_score: 4.5 },
  },
  totals: { total: 4, processed: 4, unprocessed: 0, analyzed: 4, analysis_coverage: 1 },
  pipeline_version: "0.4.0",
};

export const unauthorizedResponse = { detail: "Authentication required" };
export const forbiddenResponse = { detail: "Insufficient permissions" };
export const emptyFindingsResponse = [];
