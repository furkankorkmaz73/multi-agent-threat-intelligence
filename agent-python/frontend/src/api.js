const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

let runtimeApiKey = "";

/**
 * @typedef {Object} FindingSummary
 * @property {string} source
 * @property {string} entity_id
 * @property {string} risk_level
 * @property {number} risk_score
 * @property {number} confidence
 * @property {string} diagnosis
 * @property {string=} analyzed_at
 * @property {Object<string, unknown>=} evidence_summary
 */

/**
 * @typedef {Object} FindingDetail
 * @property {string} source
 * @property {string} entity_id
 * @property {string} risk_level
 * @property {number} risk_score
 * @property {number} confidence
 * @property {string} diagnosis
 * @property {string[]} explanation
 * @property {string[]} recommendations
 * @property {Object<string, unknown>} evidence
 * @property {Object<string, unknown>} feature_breakdown
 * @property {Object<string, unknown>} graph_summary
 * @property {Object<string, unknown>[]} graph_edges
 */

export class ApiError extends Error {
  constructor(message, { status = 0, detail = null, path = "" } = {}) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
    this.path = path;
  }

  get kind() {
    if (this.status === 401) return "unauthorized";
    if (this.status === 403) return "forbidden";
    if (this.status >= 500 || this.status === 0) return "server";
    return "request";
  }
}

export function setRuntimeApiKey(value) {
  runtimeApiKey = String(value || "").trim();
}

export function clearRuntimeApiKey() {
  runtimeApiKey = "";
}

export function getAuthStatus() {
  if (runtimeApiKey) return { configured: true, source: "session" };
  return { configured: false, source: "missing" };
}

function configuredApiKey() {
  return runtimeApiKey;
}

function authHeaders(getApiKey) {
  const apiKey = String(getApiKey?.() || "").trim();
  return apiKey ? { "x-api-key": apiKey } : {};
}

async function parseError(response, path) {
  let detail = null;
  let message = `API request failed: ${response.status}`;
  try {
    const payload = await response.json();
    detail = payload?.detail ?? payload;
    if (payload?.detail) message = typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload.detail);
  } catch {
    // Preserve the status-based message when the server does not return JSON.
  }
  return new ApiError(message, { status: response.status, detail, path });
}

function params(query) {
  const search = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  });
  return search.toString();
}

function assertObject(payload, label) {
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new ApiError(`Malformed ${label} response`, { detail: payload });
  }
  return payload;
}

function assertArray(payload, label) {
  if (!Array.isArray(payload)) {
    throw new ApiError(`Malformed ${label} response`, { detail: payload });
  }
  return payload;
}

function validateFindingSummary(row) {
  assertObject(row, "finding summary");
  for (const field of ["source", "entity_id", "risk_level", "risk_score", "confidence", "diagnosis"]) {
    if (row[field] === undefined || row[field] === null) {
      throw new ApiError(`Malformed finding summary response: missing ${field}`, { detail: row });
    }
  }
  return row;
}

function validateFindingDetail(payload) {
  assertObject(payload, "finding detail");
  for (const field of ["source", "entity_id", "risk_level", "risk_score", "confidence", "diagnosis", "evidence", "feature_breakdown", "graph_summary"]) {
    if (payload[field] === undefined || payload[field] === null) {
      throw new ApiError(`Malformed finding detail response: missing ${field}`, { detail: payload });
    }
  }
  return payload;
}

function validateAnalyzeResponse(payload) {
  assertObject(payload, "analysis");
  for (const field of ["entity_id", "risk_level", "risk_score", "confidence", "diagnosis", "feature_breakdown", "graph_summary", "graph_edges"]) {
    if (payload[field] === undefined || payload[field] === null) {
      throw new ApiError(`Malformed analysis response: missing ${field}`, { detail: payload });
    }
  }
  return payload;
}

function validateStatusOverview(payload) {
  assertObject(payload, "status overview");
  if (!payload.sources || !payload.totals) {
    throw new ApiError("Malformed status overview response", { detail: payload });
  }
  return payload;
}

function validateEvaluationSnapshot(payload) {
  assertObject(payload, "evaluation snapshot");
  if (!payload.summary || !Array.isArray(payload.rows)) {
    throw new ApiError("Malformed evaluation snapshot response", { detail: payload });
  }
  return payload;
}

export function createApiClient({ baseUrl = API_BASE, getApiKey = configuredApiKey, fetchImpl = globalThis.fetch } = {}) {
  async function fetchJSON(path, { auth = true, validate, ...options } = {}) {
    const headers = {
      ...(auth ? authHeaders(getApiKey) : {}),
      ...(options.headers || {}),
    };
    const response = await fetchImpl(`${baseUrl}${path}`, { ...options, headers });
    if (!response.ok) {
      throw await parseError(response, path);
    }
    const payload = await response.json();
    return validate ? validate(payload) : payload;
  }

  return {
    getHealth: () => fetchJSON("/health", { auth: false, validate: (payload) => assertObject(payload, "health") }),
    getStatusOverview: () => fetchJSON("/status/overview", { validate: validateStatusOverview }),
    getTopFindings: ({ source = "", limit = 25, mode = "top" } = {}) =>
      fetchJSON(`/findings/top?${params({ source, limit, mode })}`, {
        validate: (payload) => assertArray(payload, "top findings").map(validateFindingSummary),
      }),
    getRecentFindings: ({ source = "cve", limit = 25 } = {}) =>
      fetchJSON(`/findings/recent?${params({ source, limit })}`, {
        validate: (payload) => assertArray(payload, "recent findings").map(validateFindingSummary),
      }),
    searchFindings: ({ source = "cve", query, limit = 25 }) =>
      fetchJSON(`/findings/search?${params({ source, query, limit })}`, {
        validate: (payload) => assertArray(payload, "search findings").map(validateFindingSummary),
      }),
    getFindingDetail: ({ source, entityId }) =>
      fetchJSON(`/findings/detail?${params({ source, entity_id: entityId })}`, { validate: validateFindingDetail }),
    getEvaluationSnapshot: ({ limit = 50, topK = 10 } = {}) =>
      fetchJSON(`/evaluation/cve?${params({ limit, top_k: topK })}`, { validate: validateEvaluationSnapshot }),
    getEvaluationDiagnostics: ({ limit = 500 } = {}) =>
      fetchJSON(`/evaluation/cve/diagnostics?${params({ limit })}`, { validate: (payload) => assertObject(payload, "evaluation diagnostics") }),
    analyzeInput: (source, payload) =>
      fetchJSON(`/analyze/${source}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        validate: validateAnalyzeResponse,
      }),
  };
}

const defaultClient = createApiClient();

export const getHealth = defaultClient.getHealth;
export const getStatusOverview = defaultClient.getStatusOverview;
export const getTopFindings = defaultClient.getTopFindings;
export const getRecentFindings = defaultClient.getRecentFindings;
export const searchFindings = defaultClient.searchFindings;
export const getFindingDetail = defaultClient.getFindingDetail;
export const getEvaluationSnapshot = defaultClient.getEvaluationSnapshot;
export const getEvaluationDiagnostics = defaultClient.getEvaluationDiagnostics;
export const analyzeInput = defaultClient.analyzeInput;

export function describeApiError(error) {
  if (!(error instanceof ApiError)) {
    return { title: "Request failed", message: error?.message || String(error), kind: "server" };
  }
  if (error.status === 401) {
    return { title: "Authentication required", message: error.message, kind: "unauthorized" };
  }
  if (error.status === 403) {
    return { title: "Insufficient role", message: error.message, kind: "forbidden" };
  }
  return { title: "API request failed", message: error.message, kind: error.kind };
}
