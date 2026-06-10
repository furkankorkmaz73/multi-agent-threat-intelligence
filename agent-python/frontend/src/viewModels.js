const RISK_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

export function findingKey(finding) {
  return `${finding?.source || "unknown"}:${finding?.entity_id || "unknown"}`;
}

export function filterAndSortFindings(findings, { riskLevel = "", sortBy = "risk_desc" } = {}) {
  const rows = Array.isArray(findings) ? findings.slice() : [];
  const filtered = riskLevel ? rows.filter((finding) => String(finding.risk_level || "").toUpperCase() === riskLevel) : rows;
  return filtered.sort((left, right) => compareFindings(left, right, sortBy));
}

export function compareFindings(left, right, sortBy = "risk_desc") {
  if (sortBy === "confidence_desc") {
    return numericDesc(left.confidence, right.confidence) || stableName(left, right);
  }
  if (sortBy === "analyzed_desc") {
    return dateDesc(left.analyzed_at, right.analyzed_at) || stableName(left, right);
  }
  if (sortBy === "source_asc") {
    return String(left.source || "").localeCompare(String(right.source || "")) || stableName(left, right);
  }
  return riskRank(right) - riskRank(left) || numericDesc(left.risk_score, right.risk_score) || stableName(left, right);
}

export function evidenceCounts(finding) {
  const summary = finding?.evidence_summary || {};
  return {
    accepted: Number(summary.urlhaus_accepted ?? summary.accepted_urlhaus_count ?? summary.accepted_match_count ?? 0),
    rejected: Number(summary.urlhaus_rejected ?? summary.rejected_urlhaus_count ?? summary.rejected_match_count ?? 0),
    manualReview: Number(summary.manual_review_count ?? summary.urlhaus_manual_review ?? 0),
    exact: Number(summary.exact_cve_hits ?? 0),
    highSignal: Number(summary.high_signal_hits ?? 0),
  };
}

export function detailEvidenceGroups(detail) {
  const stats = detail?.evidence?.urlhaus_match_stats || {};
  return {
    accepted: asArray(stats.accepted_matches),
    rejected: asArray(stats.rejected_matches),
    manualReview: asArray(stats.manual_review_matches || stats.manual_review_candidates),
    counts: {
      accepted: Number(stats.accepted_match_count || 0),
      rejected: Number(stats.rejected_match_count || 0),
      manualReview: Number(stats.manual_review_count || 0),
    },
    reasons: asArray(stats.acceptance_reasons),
    sharedTerms: asArray(stats.shared_terms),
  };
}

function riskRank(finding) {
  return RISK_ORDER[String(finding?.risk_level || "UNKNOWN").toUpperCase()] || 0;
}

function numericDesc(left, right) {
  return Number(right || 0) - Number(left || 0);
}

function dateDesc(left, right) {
  return new Date(right || 0).getTime() - new Date(left || 0).getTime();
}

function stableName(left, right) {
  return findingKey(left).localeCompare(findingKey(right));
}

function asArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}
