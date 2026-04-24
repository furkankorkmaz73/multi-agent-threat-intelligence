import { useEffect, useMemo, useState } from "react";
import {
  analyzeInput,
  getFindingDetail,
  getHealth,
  getTopFindings,
  getCveEvaluationSnapshot,
} from "./api";
import GraphView from "./GraphView";
import "./App.css";

const SOURCES = ["", "cve", "urlhaus", "dread"];
const ANALYZE_SOURCES = ["cve", "urlhaus", "dread"];

const DEFAULT_PAYLOADS = {
  cve: `{
  "_id": "CVE-TEST-1234",
  "published": "2026-04-23T00:00:00+00:00",
  "descriptions": [
    {
      "lang": "en",
      "value": "Remote code execution vulnerability in Example Product."
    }
  ],
  "metrics": {
    "cvss_metric_v31": [
      {
        "cvss_data": {
          "base_score": 9.8
        }
      }
    ]
  }
}`,
  urlhaus: `{
  "url": "http://test.com/a.exe",
  "threat": "malware",
  "tags": ["loader"],
  "url_status": "online"
}`,
  dread: `{
  "_id": "dread-test-1",
  "title": "Exploit sale thread",
  "content": "Selling exploit for CVE-2026-1111 with RCE access",
  "author": "user1",
  "category": "market"
}`,
};

function downloadJSON(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function RiskBadge({ level }) {
  return (
    <span className="badge" data-level={level || "LOW"}>
      {level || "LOW"}
    </span>
  );
}

function SectionCard({ title, description, children, action = null }) {
  return (
    <section className="section-card glass-card">
      <div className="section-header">
        <div className="section-title-wrap">
          <h2>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
        {action}
      </div>
      {children}
    </section>
  );
}

function StatCard({ label, value, tone = "default" }) {
  return (
    <div className="stat-card glass-card" data-tone={tone}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
    </div>
  );
}

function MiniStat({ label, value, note }) {
  return (
    <div className="mini-stat glass-card">
      <div className="mini-stat-label">{label}</div>
      <div className="mini-stat-value">{value}</div>
      {note ? <div className="mini-stat-note">{note}</div> : null}
    </div>
  );
}

function KeyValueGrid({ items }) {
  return (
    <div className="key-grid">
      {items.map((item) => (
        <div key={item.label} className="key-item">
          <div className="key-label">{item.label}</div>
          <div className="key-value">{item.value}</div>
        </div>
      ))}
    </div>
  );
}

function MetricCard({ label, value }) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
    </div>
  );
}

function formatNumber(value, digits = 2) {
  if (value === null || value === undefined || value === "") return "-";
  const n = Number(value);
  if (Number.isNaN(n)) return String(value);
  return n.toFixed(digits);
}

export default function App() {
  const [health, setHealth] = useState(null);
  const [source, setSource] = useState("");
  const [query, setQuery] = useState("");
  const [findings, setFindings] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [error, setError] = useState("");
  const [loadingList, setLoadingList] = useState(false);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const [analyzeSource, setAnalyzeSource] = useState("urlhaus");
  const [analyzeText, setAnalyzeText] = useState(DEFAULT_PAYLOADS.urlhaus);
  const [analyzeLoading, setAnalyzeLoading] = useState(false);
  const [evaluation, setEvaluation] = useState(null);
  const [evaluationLoading, setEvaluationLoading] = useState(false);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch((err) => setError(err.message));
  }, []);

  useEffect(() => {
    setEvaluationLoading(true);
    getCveEvaluationSnapshot(12, 10)
      .then(setEvaluation)
      .catch((err) => setError(err.message))
      .finally(() => setEvaluationLoading(false));
  }, []);

  useEffect(() => {
    setLoadingList(true);
    setError("");

    getTopFindings(20, source)
      .then((data) => {
        setFindings(data);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoadingList(false));
  }, [source]);

  const filteredFindings = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return findings;

    return findings.filter((item) => {
      return (
        item.entity_id.toLowerCase().includes(q) ||
        item.source.toLowerCase().includes(q) ||
        item.risk_level.toLowerCase().includes(q) ||
        item.diagnosis.toLowerCase().includes(q)
      );
    });
  }, [findings, query]);

  useEffect(() => {
    if (filteredFindings.length === 0) {
      setSelected(null);
      if (!detail?.__live) {
        setDetail(null);
      }
      return;
    }

    const stillVisible = filteredFindings.find(
      (item) =>
        item.source === selected?.source && item.entity_id === selected?.entity_id
    );

    if (!stillVisible && !detail?.__live) {
      setSelected(filteredFindings[0]);
    }
  }, [filteredFindings, selected, detail]);

  useEffect(() => {
    if (!selected) return;

    setLoadingDetail(true);
    setError("");

    getFindingDetail(selected.source, selected.entity_id)
      .then((data) => setDetail(data))
      .catch((err) => setError(err.message))
      .finally(() => setLoadingDetail(false));
  }, [selected?.source, selected?.entity_id]);

  const stats = useMemo(() => {
    const total = filteredFindings.length;
    const critical = filteredFindings.filter((x) => x.risk_level === "CRITICAL").length;
    const high = filteredFindings.filter((x) => x.risk_level === "HIGH").length;
    const medium = filteredFindings.filter((x) => x.risk_level === "MEDIUM").length;
    const low = filteredFindings.filter((x) => x.risk_level === "LOW").length;

    return { total, critical, high, medium, low };
  }, [filteredFindings]);

  const healthTone = useMemo(() => {
    if (!health) return "warn";
    return health.status === "ok" ? "good" : "warn";
  }, [health]);

  const evaluationSummary = useMemo(() => evaluation?.summary || null, [evaluation]);

  const priorityHeadline = useMemo(() => {
    if (!detail) return "Select a finding to inspect risk drivers, graph context, and analyst guidance.";
    const relationCount = detail.relation_summary?.total_relations ?? detail.graph_edges?.length ?? 0;
    const sourceCount = detail.graph_summary?.source_breakdown
      ? Object.keys(detail.graph_summary.source_breakdown).length
      : 0;
    return `${relationCount} linked relation${relationCount === 1 ? "" : "s"} across ${sourceCount || 1} source${sourceCount === 1 ? "" : "s"}.`;
  }, [detail]);

  function handleAnalyzeSourceChange(nextSource) {
    setAnalyzeSource(nextSource);
    setAnalyzeText(DEFAULT_PAYLOADS[nextSource]);
  }

  async function handleAnalyzeSubmit() {
    setAnalyzeLoading(true);
    setError("");

    try {
      const payload = JSON.parse(analyzeText);
      const result = await analyzeInput(analyzeSource, payload);

      setSelected(null);
      setDetail({
        ...result,
        source: analyzeSource,
        analyzed_at: new Date().toISOString(),
        __live: true,
      });
    } catch (err) {
      setError(err.message);
    } finally {
      setAnalyzeLoading(false);
    }
  }

  function handleLoadSample() {
    setAnalyzeText(DEFAULT_PAYLOADS[analyzeSource]);
    setError("");
  }

  function handleClearInput() {
    setAnalyzeText("");
    setError("");
  }

  function handlePrettyFormat() {
    try {
      const parsed = JSON.parse(analyzeText);
      setAnalyzeText(JSON.stringify(parsed, null, 2));
      setError("");
    } catch {
      setError("Invalid JSON: unable to format input.");
    }
  }

  function handleExportResult() {
    if (!detail) return;

    const rawName = `${detail.source || "analysis"}-${detail.entity_id || "result"}.json`;
    const filename = rawName.replace(/[^\w.-]+/g, "_");
    downloadJSON(filename, detail);
  }

  async function refreshFindings() {
    setLoadingList(true);
    try {
      const data = await getTopFindings(20, source);
      setFindings(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingList(false);
    }
  }

  async function refreshEvaluation() {
    setEvaluationLoading(true);
    try {
      const data = await getCveEvaluationSnapshot(12, 10);
      setEvaluation(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setEvaluationLoading(false);
    }
  }

  return (
    <div className="app-shell">
      <div className="app-container">
        <section className="hero">
          <div className="hero-grid">
            <div>
              <span className="eyebrow">Multi-source CTI workbench</span>
              <h1 className="hero-title">Threat prioritization with evidence, graph context, and analyst workflow.</h1>
              <div className="hero-copy">
                Correlate CVEs, malicious URLs, and dark-web intelligence in one place. The dashboard now emphasizes decision support: what matters first, why it was prioritized, and which supporting relations changed the score.
              </div>
              <div className="hero-chips">
                <span className="hero-chip">Graph-supported context</span>
                <span className="hero-chip">Explainable dynamic scoring</span>
                <span className="hero-chip">Comparative evaluation</span>
                <span className="hero-chip">Live payload analysis</span>
              </div>
            </div>

            <div className="hero-mini-grid">
              <MiniStat
                label="System"
                value={health ? String(health.status).toUpperCase() : "LOADING"}
                note="API and scoring services"
              />
              <MiniStat
                label="Priority queue"
                value={stats.critical + stats.high}
                note="critical + high findings"
              />
              <MiniStat
                label="Graph support"
                value={evaluationSummary?.graph_supported_count ?? "-"}
                note="CVE records with graph lift"
              />
              <MiniStat
                label="Avg dynamic score"
                value={formatNumber(evaluationSummary?.avg_final_dynamic_score)}
                note="evaluation sample"
              />
            </div>
          </div>
          {error ? <div className="error-banner">{error}</div> : null}
        </section>

        <div className="stats-grid">
          <StatCard label="API status" value={health ? `${health.status}` : "loading"} tone={healthTone} />
          <StatCard label="Visible findings" value={stats.total} tone="info" />
          <StatCard label="Critical" value={stats.critical} tone="warn" />
          <StatCard label="High" value={stats.high} tone="warn" />
          <StatCard label="Medium / low" value={`${stats.medium} / ${stats.low}`} />
        </div>

        <div className="layout-grid">
          <div className="stack">
            <SectionCard
              title="Priority Queue"
              description="Browse the highest-risk findings, filter by source, and jump into the analyst workspace."
              action={<button className="button" onClick={refreshFindings}>Refresh</button>}
            >
              <div className="field-grid" style={{ marginBottom: 14 }}>
                <div className="field">
                  <label>Source filter</label>
                  <select value={source} onChange={(e) => setSource(e.target.value)}>
                    {SOURCES.map((s) => (
                      <option key={s} value={s}>
                        {s || "all sources"}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="field">
                  <label>Search</label>
                  <input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="entity id, diagnosis, source, risk level..."
                  />
                </div>
              </div>

              {loadingList ? (
                <div className="empty-state">Loading findings...</div>
              ) : filteredFindings.length === 0 ? (
                <div className="empty-state">No findings available for the current filter.</div>
              ) : (
                <div className="finding-list">
                  {filteredFindings.map((item) => {
                    const active =
                      selected?.source === item.source &&
                      selected?.entity_id === item.entity_id &&
                      !detail?.__live;

                    return (
                      <button
                        key={`${item.source}-${item.entity_id}`}
                        className={`finding-item ${active ? "active" : ""}`}
                        onClick={() => {
                          setDetail(null);
                          setSelected(item);
                        }}
                      >
                        <div className="finding-top">
                          <div className="finding-title">{item.entity_id}</div>
                          <RiskBadge level={item.risk_level} />
                        </div>
                        <div className="finding-meta">{item.source}</div>
                        <div className="finding-scoreline">
                          <span>dynamic {formatNumber(item.risk_score)}</span>
                          <span>confidence {formatNumber(item.confidence)}</span>
                        </div>
                        <div className="finding-diagnosis">{item.diagnosis}</div>
                      </button>
                    );
                  })}
                </div>
              )}
            </SectionCard>

            <SectionCard
              title="Evaluation Snapshot"
              description="Show how dynamic scoring moves beyond CVSS-only ranking and where graph support changes priority."
              action={<button className="button" onClick={refreshEvaluation}>Refresh</button>}
            >
              {evaluationLoading ? (
                <div className="empty-state">Loading comparison snapshot...</div>
              ) : !evaluationSummary ? (
                <div className="empty-state">No CVE evaluation snapshot available.</div>
              ) : (
                <div className="stack" style={{ gap: 16 }}>
                  <div className="metric-strip">
                    <MetricCard label="Records" value={evaluationSummary.record_count} />
                    <MetricCard label="Avg dynamic" value={formatNumber(evaluationSummary.avg_final_dynamic_score)} />
                    <MetricCard label="Avg lift vs CVSS" value={formatNumber(evaluationSummary.avg_lift_from_cvss_only)} />
                    <MetricCard label="Graph supported" value={evaluationSummary.graph_supported_count} />
                    <MetricCard label="Top overlap" value={`${evaluationSummary.top_overlap_cvss_vs_dynamic}/${evaluationSummary.top_k}`} />
                    <MetricCard label="Reprioritized ≥1.5" value={evaluationSummary.reprioritized_count_lift_ge_1_5} />
                  </div>

                  <div className="table-wrap">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>CVE</th>
                          <th>CVSS-only</th>
                          <th>+Corr</th>
                          <th>+Graph</th>
                          <th>Dynamic</th>
                          <th>Lift</th>
                          <th>Links</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(evaluation?.rows || []).map((row) => (
                          <tr key={row.cve_id}>
                            <td style={{ fontWeight: 800 }}>{row.cve_id}</td>
                            <td>{formatNumber(row.baseline_cvss_only_score)}</td>
                            <td>{formatNumber(row.baseline_plus_correlation)}</td>
                            <td>{formatNumber(row.baseline_plus_graph)}</td>
                            <td>
                              <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
                                <span>{formatNumber(row.final_dynamic_score)}</span>
                                <RiskBadge level={row.risk_level || "LOW"} />
                              </div>
                            </td>
                            <td style={{ fontWeight: 800, color: Number(row.lift_from_cvss_only) >= 1.5 ? "#86efac" : undefined }}>
                              {formatNumber(row.lift_from_cvss_only)}
                            </td>
                            <td>U:{row.related_urlhaus_count || 0} / D:{row.related_dread_count || 0}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </SectionCard>

            <SectionCard
              title="Live Analysis"
              description="Paste a raw object from any supported source to preview scoring, evidence, and graph relationships immediately."
            >
              <div className="field-grid">
                <div className="field">
                  <label>Analyze source</label>
                  <select value={analyzeSource} onChange={(e) => handleAnalyzeSourceChange(e.target.value)}>
                    {ANALYZE_SOURCES.map((s) => (
                      <option key={s} value={s}>
                        {s}
                      </option>
                    ))}
                  </select>
                </div>

                <div className="field">
                  <label>JSON payload</label>
                  <textarea value={analyzeText} onChange={(e) => setAnalyzeText(e.target.value)} rows={16} />
                </div>

                <div className="button-row">
                  <button className="button" onClick={handleLoadSample}>Load Sample</button>
                  <button className="ghost-button" onClick={handlePrettyFormat}>Pretty Format</button>
                  <button className="ghost-button danger-button" onClick={handleClearInput}>Clear</button>
                  <button className="secondary-button success-button" onClick={handleAnalyzeSubmit} disabled={analyzeLoading}>
                    {analyzeLoading ? "Analyzing..." : "Analyze Now"}
                  </button>
                </div>
              </div>
            </SectionCard>
          </div>

          <div className="stack">
            <SectionCard
              title={detail?.__live ? "Live Analysis Result" : "Analyst Workspace"}
              description={priorityHeadline}
              action={detail ? <button className="button" onClick={handleExportResult}>Export JSON</button> : null}
            >
              {loadingDetail ? (
                <div className="empty-state">Loading detail...</div>
              ) : !detail ? (
                <div className="empty-state">Select a finding from the queue or run a live analysis payload.</div>
              ) : (
                <div className="stack">
                  <div className="detail-hero">
                    <div className="detail-title-row">
                      <div>
                        <h2 className="detail-title">{detail.entity_id}</h2>
                        <div className="badge-row">
                          <RiskBadge level={detail.risk_level} />
                          <span className="info-chip">source {detail.source}</span>
                          <span className="info-chip">dynamic {formatNumber(detail.risk_score)}</span>
                          <span className="info-chip">confidence {formatNumber(detail.confidence)}</span>
                        </div>
                      </div>
                    </div>
                    <div className="detail-subtitle">{detail.diagnosis}</div>
                  </div>

                  <KeyValueGrid
                    items={[
                      { label: "Analyzed at", value: detail.analyzed_at || "-" },
                      { label: "Graph nodes", value: detail.graph_summary?.node_count ?? "-" },
                      { label: "Graph edges", value: detail.graph_summary?.edge_count ?? "-" },
                      { label: "Centrality score", value: detail.graph_summary?.centrality_score ?? "-" },
                    ]}
                  />

                  <div className="two-col">
                    <div className="panel">
                      <h3>Feature Breakdown</h3>
                      <pre className="pre-block">{JSON.stringify(detail.feature_breakdown, null, 2)}</pre>
                    </div>
                    <div className="panel">
                      <h3>Graph Summary</h3>
                      <pre className="pre-block">{JSON.stringify(detail.graph_summary, null, 2)}</pre>
                    </div>
                  </div>

                  <div className="two-col">
                    <div className="panel">
                      <h3>Why Prioritized</h3>
                      <pre className="pre-block">{JSON.stringify(detail.source_contributions || {}, null, 2)}</pre>
                    </div>
                    <div className="panel">
                      <h3>Counterfactuals</h3>
                      <pre className="pre-block">{JSON.stringify(detail.counterfactuals || {}, null, 2)}</pre>
                    </div>
                  </div>

                  <div className="two-col">
                    <div className="panel list-panel">
                      <h3>Explanation</h3>
                      <ul>
                        {detail.explanation.map((line, idx) => (
                          <li key={idx}>{line}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="panel list-panel">
                      <h3>Recommendations</h3>
                      <ul>
                        {detail.recommendations.map((line, idx) => (
                          <li key={idx}>{line}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </SectionCard>

            <SectionCard
              title="Relationship Graph"
              description="Inspect the surrounding evidence network and the strongest linked indicators or dark-web references."
            >
              {!detail ? (
                <div className="empty-state">No graph available yet.</div>
              ) : (
                <GraphView source={detail.source} entityId={detail.entity_id} edges={detail.graph_edges || []} />
              )}
            </SectionCard>

            <SectionCard
              title="Evidence Ledger"
              description="Review the top graph edges with confidence, provenance, and machine-readable relation labels."
            >
              {!detail || !detail.graph_edges?.length ? (
                <div className="empty-state">No graph edges available for this selection.</div>
              ) : (
                <div className="edge-grid">
                  {detail.graph_edges.slice(0, 12).map((edge, idx) => (
                    <div key={idx} className="edge-card">
                      <div className="edge-relation">{edge.relation}</div>
                      <div><strong>source:</strong> {edge.source}</div>
                      <div><strong>target:</strong> {edge.target}</div>
                      <div><strong>weight:</strong> {edge.weight}</div>
                      <div><strong>confidence:</strong> {edge.confidence ?? "-"}</div>
                      <div><strong>evidence:</strong> {edge.evidence_type || "-"}</div>
                      <div><strong>provenance:</strong> {edge.provenance || "-"}</div>
                      <div><strong>why linked:</strong> {edge.explanation || "-"}</div>
                    </div>
                  ))}
                </div>
              )}
            </SectionCard>
          </div>
        </div>
      </div>
    </div>
  );
}
