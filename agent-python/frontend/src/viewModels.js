const RISK_ORDER = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
const RISK_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
const CONFIDENCE_BUCKETS = [
  { id: "high", label: "High" },
  { id: "elevated", label: "Elevated" },
  { id: "medium", label: "Medium" },
  { id: "low", label: "Low" },
];

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
    accepted: asArray(stats.accepted_matches || stats.accepted_urlhaus_matches),
    rejected: asArray(stats.rejected_matches || stats.rejected_urlhaus_matches),
    manualReview: asArray(stats.manual_review_matches || stats.manual_review_candidates || stats.manual_review_urlhaus_matches),
    counts: {
      accepted: Number(stats.accepted_match_count || stats.accepted_urlhaus_count || 0),
      rejected: Number(stats.rejected_match_count || stats.rejected_urlhaus_count || 0),
      manualReview: Number(stats.manual_review_match_count || stats.manual_review_count || stats.manual_review_evidence_count || 0),
    },
    reasons: asArray(stats.acceptance_reasons),
    manualReviewReasons: asArray(stats.manual_review_reasons),
    rejectionReasons: asArray(stats.rejection_reasons),
    sharedTerms: asArray(stats.shared_terms),
  };
}

export function confidenceBand(value) {
  const numeric = Number(value || 0);
  if (numeric >= 0.85) return "high";
  if (numeric >= 0.7) return "elevated";
  if (numeric >= 0.5) return "medium";
  return "low";
}

export function riskDistribution(findings, diagnostics) {
  const diagnosticDistribution = diagnostics?.risk_level_distribution;
  const counts = isPlainObject(diagnosticDistribution) ? { ...diagnosticDistribution } : {};
  if (!Object.keys(counts).length) {
    for (const finding of asArray(findings)) {
      const level = String(finding?.risk_level || "UNKNOWN").toUpperCase();
      counts[level] = Number(counts[level] || 0) + 1;
    }
  }
  return orderedCountRows(counts, RISK_LEVELS);
}

export function confidenceDistribution(findings) {
  const counts = Object.fromEntries(CONFIDENCE_BUCKETS.map((bucket) => [bucket.id, 0]));
  for (const finding of asArray(findings)) {
    const numeric = Number(finding?.confidence);
    if (!Number.isFinite(numeric)) continue;
    counts[confidenceBand(numeric)] += 1;
  }
  return CONFIDENCE_BUCKETS.map((bucket) => ({
    id: bucket.id,
    label: bucket.label,
    count: counts[bucket.id],
  })).filter((row) => row.count > 0);
}

export function sourceCoverageRows(status, findings) {
  const statusSources = status?.sources || {};
  if (isPlainObject(statusSources) && Object.keys(statusSources).length) {
    return Object.entries(statusSources)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([source, row]) => {
        const total = Number(row?.total ?? 0);
        const analyzed = Number(row?.analyzed ?? 0);
        const coverage = finiteNumber(row?.analysis_coverage, total > 0 ? analyzed / total : 0);
        return {
          id: source,
          label: source.toUpperCase(),
          total,
          analyzed,
          coverage: clamp01(coverage),
          count: analyzed,
        };
      });
  }

  const counts = {};
  for (const finding of asArray(findings)) {
    const source = String(finding?.source || "unknown").toLowerCase();
    counts[source] = Number(counts[source] || 0) + 1;
  }
  return Object.entries(counts)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([source, count]) => ({
      id: source,
      label: source.toUpperCase(),
      total: count,
      analyzed: count,
      coverage: count > 0 ? 1 : 0,
      count,
    }));
}

export function urlhausStatusDistribution(findings) {
  const counts = {};
  for (const finding of asArray(findings)) {
    const summary = finding?.evidence_summary || {};
    const source = String(finding?.source || "").toLowerCase();
    const hasUrlhausFields = source === "urlhaus" || firstPresent(summary.url_status, summary.status, finding?.url_status);
    if (!hasUrlhausFields) continue;
    const status = String(firstPresent(finding?.url_status, summary.url_status, summary.status, "unknown")).toLowerCase();
    counts[status] = Number(counts[status] || 0) + 1;
  }
  return orderedCountRows(counts, ["online", "offline", "unknown"]);
}

export function topTagFamilies(findings, limit = 8) {
  const counts = new Map();
  for (const finding of asArray(findings)) {
    const summary = finding?.evidence_summary || {};
    const values = [
      ...arrayFrom(finding?.tags),
      ...arrayFrom(summary.tags),
      ...arrayFrom(summary.malware_tags),
      ...arrayFrom(firstPresent(finding?.malware_family, summary.malware_family, finding?.family, summary.family)),
      ...arrayFrom(firstPresent(finding?.signature, summary.signature)),
      ...arrayFrom(firstPresent(finding?.threat, summary.threat)),
    ];
    for (const value of values) {
      const label = String(value || "").trim();
      if (!label) continue;
      const key = label.toLowerCase();
      const current = counts.get(key) || { id: key, label, count: 0 };
      current.count += 1;
      counts.set(key, current);
    }
  }
  return Array.from(counts.values())
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label))
    .slice(0, limit);
}

export function operationalRiskRows(detail) {
  const containers = [
    detail?.asset_operational_risk_examples,
    detail?.operational_risk_examples,
    detail?.asset_operational_risk,
    detail?.operational_risk,
    detail?.evidence?.asset_operational_risk_examples,
    detail?.evaluation_trace?.asset_operational_risk_examples,
    detail?.explanation_trace?.asset_operational_risk_examples,
    detail?.thesis_trace?.asset_operational_risk_examples,
    detail?.trace?.asset_operational_risk_examples,
  ];
  const rows = containers.flatMap(extractOperationalRows).filter(isPlainObject);
  const seen = new Set();
  return rows.map((row) => normalizeOperationalRow(row, detail)).filter((row) => {
    const key = `${row.assetId}:${row.operationalRisk}:${row.genericRisk}:${row.matchReason}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function normalizeOperationalRow(row, detail) {
  const component = isPlainObject(row.component_breakdown) ? row.component_breakdown : {};
  const applicability = isPlainObject(row.applicability) ? row.applicability : {};
  const operationalRisk = firstFinite(
    row.final_operational_risk_score,
    row.operational_risk_score,
    row.asset_operational_risk_score,
  );
  return {
    assetId: String(firstPresent(row.asset_id, row.asset, row.hostname, row.name, "asset context")),
    applicable: normalizeApplicability(firstPresent(row.asset_applicable, row.applicable, applicability.status)),
    matchReason: firstPresent(row.asset_match_reason, row.match_reason, applicability.reason, row.reason, ""),
    genericRisk: firstFinite(row.generic_cve_risk_score, row.source_risk_score, row.generic_risk_score, row.risk_score, detail?.risk_score),
    operationalRisk,
    delta: firstFiniteOrNull(row.operational_risk_delta, row.asset_operational_risk_delta),
    finalRiskLevel: firstPresent(row.final_risk_level, row.operational_risk_level, row.risk_level, ""),
    confidence: firstFinite(row.confidence, detail?.confidence),
    exposure: firstPresent(row.exposure, row.network_exposure, component.exposure, component.network_exposure, ""),
    patchState: firstPresent(row.patch_state, row.patch_status, component.patch_state, component.patch_status, ""),
    criticality: firstPresent(row.criticality, row.business_criticality, component.criticality, component.business_criticality, ""),
    controls: arrayFrom(firstPresent(row.compensating_controls, component.compensating_controls)),
    controlReduction: firstFinite(row.compensating_control_reduction, component.compensating_control_reduction),
    explanation: firstPresent(row.explanation, row.summary, ""),
  };
}

function extractOperationalRows(value) {
  if (Array.isArray(value)) return value;
  if (!isPlainObject(value)) return [];
  for (const key of ["examples", "rows", "items", "top_operational_risk_cases", "asset_operational_risk_examples", "asset_operational_risk"]) {
    if (Array.isArray(value[key])) return value[key];
  }
  if (
    value.asset_id ||
    value.final_operational_risk_score !== undefined ||
    value.operational_risk_score !== undefined ||
    value.asset_operational_risk_score !== undefined
  ) {
    return [value];
  }
  return [];
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

function arrayFrom(value) {
  if (Array.isArray(value)) return value.filter(Boolean);
  if (value === undefined || value === null || value === "") return [];
  return [value];
}

function orderedCountRows(counts, order) {
  const normalized = {};
  Object.entries(counts || {}).forEach(([key, value]) => {
    const normalizedKey = String(key || "unknown").toUpperCase();
    normalized[normalizedKey] = Number(normalized[normalizedKey] || 0) + Number(value || 0);
  });

  const preferred = order.map((key) => {
    const normalizedKey = String(key).toUpperCase();
    return {
      id: String(key).toLowerCase(),
      label: normalizedKey,
      count: Number(normalized[normalizedKey] || 0),
    };
  });
  const extras = Object.entries(normalized)
    .filter(([key]) => !order.map((item) => String(item).toUpperCase()).includes(key))
    .map(([key, count]) => ({ id: key.toLowerCase(), label: key, count }))
    .sort((left, right) => right.count - left.count || left.label.localeCompare(right.label));

  return [...preferred, ...extras].filter((row) => row.count > 0);
}

function firstPresent(...values) {
  return values.find((value) => value !== undefined && value !== null && value !== "");
}

function firstFinite(...values) {
  for (const value of values) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric;
  }
  return 0;
}

function firstFiniteOrNull(...values) {
  for (const value of values) {
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric;
  }
  return null;
}

function finiteNumber(value, fallback) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : fallback;
}

function clamp01(value) {
  return Math.max(0, Math.min(1, Number(value || 0)));
}

function normalizeApplicability(value) {
  if (typeof value === "boolean") return value ? "applicable" : "not applicable";
  if (value === undefined || value === null || value === "") return "";
  return String(value).replace(/_/g, " ");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
