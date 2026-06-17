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
  evidence_summary: {
    url_status: "online",
    threat: "malware_download",
    tags: ["loader", "vpn"],
    malware_family: "ExampleLoader",
  },
};

export const offlineUrlhausIocSummary = {
  source: "urlhaus",
  entity_id: "UH-E2E-9102",
  risk_level: "LOW",
  risk_score: 3.1,
  confidence: 0.58,
  diagnosis: "Offline URLhaus IOC retained for review.",
  analyzed_at: "2026-06-10T14:35:08Z",
  evidence_summary: {
    url_status: "offline",
    threat: "malware_download",
    tags: ["dropper", "exe"],
    malware_family: "ExampleDropper",
  },
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
      manual_review_match_count: 1,
      exact_cve_hits: 1,
      high_signal_hits: 0,
      raw_candidate_count: 3,
      ignored_low_signal_count: 1,
      shared_terms: ["cve-2026-9101"],
      acceptance_reasons: ["exact_cve"],
      rejection_reasons: ["weak_entity_overlap"],
      manual_review_reasons: ["dread_only_uncorroborated"],
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
      rejected_matches: [
        {
          url: "https://malware.invalid/unrelated/payload.exe",
          threat: "malware_download",
          url_status: "offline",
          score: 0.118,
          rejection_reason: "weak_entity_overlap",
          tags: ["legacy"],
        },
      ],
      manual_review_matches: [
        {
          id: "DR-9101",
          title: "Exploit rumor without corroborating IOC",
          evidence_type: "dread_thread",
          provenance: "dread",
          score: 0.421,
          manual_review_reason: "dread_only_uncorroborated",
          confidence_cap_reason: "dread_manual_review_cap",
          tags: ["exploit", "vpn"],
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
  relation_summary: { relation_count: 11, accepted_correlation_count: 1, manual_review_count: 1, rejected_count: 1 },
  graph_edges: [{ source: "cve:CVE-2026-9101", target: "urlhaus:payload", relation: "correlated_urlhaus", confidence: 0.97 }],
  source_contributions: { urlhaus: 1.51, graph: 0.18 },
  counterfactuals: { score_without_urlhaus: 9.03, score_without_graph: 9.82 },
  asset_operational_risk_examples: [
    {
      asset_id: "asset-vpn-prod",
      asset_applicable: true,
      asset_match_reason: "product and version matched exposed VPN gateway",
      generic_cve_risk_score: 10,
      operational_risk_score: 9.2,
      operational_risk_delta: -0.8,
      final_risk_level: "CRITICAL",
      confidence: 0.91,
      component_breakdown: { exposure: "internet", patch_state: "unpatched", criticality: "high" },
      compensating_controls: [{ name: "WAF virtual patch", control_type: "waf", effectiveness: 0.5 }],
      explanation: "Internet exposure and unpatched state keep this asset actionable despite a partial compensating control.",
    },
    {
      asset_id: "asset-backup-internal",
      asset_applicable: false,
      asset_match_reason: "affected product not present on asset",
      generic_cve_risk_score: 10,
      operational_risk_score: 0,
      operational_risk_delta: -10,
      final_risk_level: "LOW",
      confidence: 0.88,
      component_breakdown: { exposure: "internal", patch_state: "patched", criticality: "medium" },
      explanation: "The generic CVE remains severe, but this asset is not applicable.",
    },
  ],
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

export const evaluationDiagnostics = {
  record_count: 4,
  avg_confidence: 0.6765,
  risk_level_distribution: { CRITICAL: 1, MEDIUM: 2, LOW: 1 },
};
