const API_BASE = "http://127.0.0.1:8000";

async function fetchJSON(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, options);

  if (!res.ok) {
    let message = `API request failed: ${res.status}`;
    try {
      const data = await res.json();
      if (data?.detail) {
        message = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail);
      }
    } catch {
      // ignore json parse failure
    }
    throw new Error(message);
  }

  return res.json();
}

export async function getHealth() {
  return fetchJSON("/health");
}

export async function getTopFindings(limit = 10, source = "") {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  if (source) params.set("source", source);
  return fetchJSON(`/findings/top?${params.toString()}`);
}

export async function getRecentFindings(source, limit = 10) {
  const params = new URLSearchParams();
  params.set("source", source);
  params.set("limit", String(limit));
  return fetchJSON(`/findings/recent?${params.toString()}`);
}

export async function getFindingDetail(source, entityId) {
  const params = new URLSearchParams();
  params.set("source", source);
  params.set("entity_id", entityId);
  return fetchJSON(`/findings/detail?${params.toString()}`);
}

export async function analyzeInput(source, payload) {
  return fetchJSON(`/analyze/${source}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
}

export async function getCveEvaluationSnapshot(limit = 25, topK = 10) {
  const params = new URLSearchParams();
  params.set("limit", String(limit));
  params.set("top_k", String(topK));
  return fetchJSON(`/evaluation/cve?${params.toString()}`);
}
