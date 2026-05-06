const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

async function fetchJSON(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, options);
  if (!response.ok) {
    let message = `API request failed: ${response.status}`;
    try {
      const payload = await response.json();
      if (payload?.detail) message = typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload.detail);
    } catch {
      // ignore invalid error body
    }
    throw new Error(message);
  }
  return response.json();
}

function params(query) {
  const search = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  });
  return search.toString();
}

export function getHealth() {
  return fetchJSON("/health");
}

export function getStatusOverview() {
  return fetchJSON("/status/overview");
}

export function getTopFindings({ source = "", limit = 25, mode = "top" } = {}) {
  return fetchJSON(`/findings/top?${params({ source, limit, mode })}`);
}

export function getRecentFindings({ source = "cve", limit = 25 } = {}) {
  return fetchJSON(`/findings/recent?${params({ source, limit })}`);
}

export function searchFindings({ source = "cve", query, limit = 25 }) {
  return fetchJSON(`/findings/search?${params({ source, query, limit })}`);
}

export function getFindingDetail({ source, entityId }) {
  return fetchJSON(`/findings/detail?${params({ source, entity_id: entityId })}`);
}

export function getEvaluationSnapshot({ limit = 50, topK = 10 } = {}) {
  return fetchJSON(`/evaluation/cve?${params({ limit, top_k: topK })}`);
}

export function getEvaluationDiagnostics({ limit = 500 } = {}) {
  return fetchJSON(`/evaluation/cve/diagnostics?${params({ limit })}`);
}

export function analyzeInput(source, payload) {
  return fetchJSON(`/analyze/${source}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}
