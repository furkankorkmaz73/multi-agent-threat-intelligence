import { useEffect, useMemo, useRef, useState } from "react";
import {
  analyzeInput,
  clearRuntimeApiKey,
  describeApiError,
  getAuthStatus,
  getEvaluationDiagnostics,
  getEvaluationSnapshot,
  getFindingDetail,
  getHealth,
  getRecentFindings,
  getStatusOverview,
  getTopFindings,
  searchFindings,
  setRuntimeApiKey,
} from "./api";
import FindingTable from "./components/FindingTable";
import FindingDetail from "./components/FindingDetail";
import MetricCard from "./components/MetricCard";
import JsonBlock from "./components/JsonBlock";
import { RiskBadge, StatusPill } from "./components/Badges";
import { formatNumber, formatPercent } from "./utils/format";
import {
  confidenceDistribution,
  filterAndSortFindings,
  riskDistribution,
  sourceCoverageRows,
  topTagFamilies,
  urlhausStatusDistribution,
} from "./viewModels";
import "./App.css";

const SOURCES = ["", "cve", "urlhaus", "dread"];
const ANALYZE_SOURCES = ["cve", "urlhaus", "dread"];
const TABS = [
  { id: "findings", label: "Findings" },
  { id: "evaluation", label: "Evaluation" },
  { id: "operations", label: "Operations" },
  { id: "adhoc", label: "Ad-hoc analysis" },
];

const SAMPLE_PAYLOADS = {
  cve: `{
  "_id": "CVE-DEMO-0001",
  "published": "2026-04-23T00:00:00+00:00",
  "descriptions": [{ "lang": "en", "value": "Remote code execution vulnerability in a public-facing VPN gateway." }],
  "metrics": { "cvss_metric_v31": [{ "cvss_data": { "base_score": 9.8 } }] }
}`,
  urlhaus: `{
  "url": "https://example.com/payload.exe",
  "threat": "malware_download",
  "tags": ["loader", "exe"],
  "url_status": "online"
}`,
  dread: `{
  "_id": "thread-demo-1",
  "title": "Exploit sale thread",
  "content": "Selling exploit for CVE-2026-1111 with remote code execution access",
  "category": "market"
}`,
};

function useAsyncState(initialValue) {
  const [value, setValue] = useState(initialValue);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  return { value, setValue, loading, setLoading, error, setError };
}

function useDebouncedValue(value, delayMs = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

async function settleRequest(promise) {
  try {
    return { value: await promise, error: null };
  } catch (error) {
    return { value: null, error };
  }
}

function Section({ title, description, actions, children }) {
  return (
    <section className="section-card">
      <div className="section-heading">
        <div>
          <h2>{title}</h2>
          {description ? <p>{description}</p> : null}
        </div>
        {actions ? <div className="section-actions">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}

function TabNav({ activeTab, setActiveTab }) {
  return (
    <div className="tab-nav">
      {TABS.map((tab) => (
        <button key={tab.id} className={activeTab === tab.id ? "active" : ""} onClick={() => setActiveTab(tab.id)}>
          {tab.label}
        </button>
      ))}
    </div>
  );
}

export function Alert({ error, fallbackTitle = "Request failed" }) {
  if (!error) return null;
  const detail = describeApiError(error);
  return (
    <div className="error-banner" data-kind={detail.kind}>
      <strong>{detail.title || fallbackTitle}</strong>
      <span>{detail.message}</span>
    </div>
  );
}

function BarList({ rows, emptyLabel, valueLabel, widthForRow, toneForRow }) {
  const max = Math.max(1, ...rows.map((row) => Number(row.count || 0)));
  if (!rows.length) return <p className="empty-state">{emptyLabel}</p>;

  return (
    <div className="chart-bar-list">
      {rows.map((row) => {
        const width = widthForRow ? widthForRow(row) : (Number(row.count || 0) / max) * 100;
        return (
          <div className="chart-bar-row" data-tone={toneForRow?.(row) || row.id} key={row.id || row.label}>
            <span>{row.label}</span>
            <div className="chart-track"><span style={{ width: `${Math.min(100, Math.max(0, width))}%` }} /></div>
            <strong>{valueLabel ? valueLabel(row) : row.count}</strong>
          </div>
        );
      })}
    </div>
  );
}

function ChartPanel({ title, note, children }) {
  return (
    <section className="panel-card chart-panel">
      <div className="panel-title-row">
        <div>
          <h3>{title}</h3>
          {note ? <p className="panel-subtitle">{note}</p> : null}
        </div>
      </div>
      {children}
    </section>
  );
}

export function AnalystDashboard({ findings, status, diagnostics, loading = false }) {
  const riskRows = riskDistribution(findings, diagnostics);
  const confidenceRows = confidenceDistribution(findings);
  const coverageRows = sourceCoverageRows(status, findings);
  const urlhausRows = urlhausStatusDistribution(findings);
  const tagRows = topTagFamilies(findings);
  const riskSource = diagnostics?.risk_level_distribution ? "Diagnostics sample" : "Current result set";

  return (
    <div className="dashboard-grid" aria-label="Analyst dashboard">
      <ChartPanel title="Risk distribution" note={`${riskSource}${loading ? " while refreshing" : ""}`}>
        <BarList rows={riskRows} emptyLabel="No risk levels available." />
      </ChartPanel>
      <ChartPanel title="Confidence distribution" note="Current result set">
        <BarList rows={confidenceRows} emptyLabel="No confidence scores available." toneForRow={(row) => `confidence-${row.id}`} />
      </ChartPanel>
      <ChartPanel title="Source coverage" note={status?.sources ? "Corpus coverage from status overview" : "Current result set fallback"}>
        <BarList
          rows={coverageRows}
          emptyLabel="No source coverage available."
          valueLabel={(row) => `${formatPercent(row.coverage)} (${row.analyzed}/${row.total})`}
          widthForRow={(row) => Number(row.coverage || 0) * 100}
          toneForRow={() => "coverage"}
        />
      </ChartPanel>
      <ChartPanel title="URLhaus status" note="Online/offline split from URLhaus rows">
        <BarList rows={urlhausRows} emptyLabel="No URLhaus status fields in the current rows." />
      </ChartPanel>
      <ChartPanel title="Top malware/tags" note="Families, threats, signatures, and tags">
        <BarList rows={tagRows} emptyLabel="No malware family or tag fields in the current rows." toneForRow={() => "tag"} />
      </ChartPanel>
    </div>
  );
}

function SystemNotices({ healthState, statusError, evaluationError, diagnosticsError }) {
  const notices = [];
  if (healthState.error) {
    notices.push({
      key: "health",
      tone: "bad",
      title: "API health unavailable",
      message: describeApiError(healthState.error).message,
    });
  } else if (healthState.value?.database && healthState.value.database !== "ok") {
    notices.push({
      key: "database",
      tone: "bad",
      title: "MongoDB degraded",
      message: `Database status is ${healthState.value.database}; persisted findings and status counts may be stale or unavailable.`,
    });
  }
  if (statusError) {
    const detail = describeApiError(statusError);
    notices.push({
      key: "status",
      tone: detail.kind === "unauthorized" || detail.kind === "forbidden" ? "warn" : "bad",
      title: "Status overview unavailable",
      message: `${detail.title}: ${detail.message}`,
    });
  }
  if (evaluationError || diagnosticsError) {
    const detail = describeApiError(evaluationError || diagnosticsError);
    notices.push({
      key: "evaluation",
      tone: "warn",
      title: "Evaluation diagnostics unavailable",
      message: detail.message,
    });
  }
  if (!notices.length) return null;

  return (
    <div className="notice-stack">
      {notices.map((notice) => (
        <div className="state-notice" data-tone={notice.tone} key={notice.key}>
          <strong>{notice.title}</strong>
          <span>{notice.message}</span>
        </div>
      ))}
    </div>
  );
}

function AuthPanel({ authStatus, apiKeyInput, setApiKeyInput, onApply, onClear }) {
  return (
    <div className="auth-panel">
      <div>
        <span className="metric-label">API authentication</span>
        <strong>{authStatus.configured ? `Configured from ${authStatus.source}` : "No API key configured"}</strong>
        <p>Use an analyst key for findings and an operator/admin key for status. The session key is kept in memory only.</p>
      </div>
      <form onSubmit={(event) => { event.preventDefault(); onApply(); }} className="auth-form">
        <input
          type="password"
          value={apiKeyInput}
          onChange={(event) => setApiKeyInput(event.target.value)}
          placeholder="Paste API key for this session"
          autoComplete="off"
        />
        <button className="primary-button" type="submit">Use key</button>
        <button className="secondary-button" type="button" onClick={onClear}>Clear</button>
      </form>
    </div>
  );
}

function SourceControls({ source, setSource, limit, setLimit, mode, setMode, query, setQuery, riskLevel, setRiskLevel, sortBy, setSortBy, onRefresh }) {
  return (
    <div className="control-grid">
      <label>
        <span>Mode</span>
        <select value={mode} onChange={(event) => setMode(event.target.value)}>
          <option value="top">Top risk</option>
          <option value="recent_high">Recent high risk</option>
          <option value="needs_review">Needs review</option>
          <option value="highest_confidence">Highest confidence</option>
          <option value="active_evidence">Active evidence</option>
          <option value="recent">Recent analyzed</option>
          <option value="search">Search</option>
        </select>
      </label>
      <label>
        <span>Source</span>
        <select value={source} onChange={(event) => setSource(event.target.value)}>
          {SOURCES.map((item) => <option key={item || "all"} value={item}>{item ? item.toUpperCase() : "ALL"}</option>)}
        </select>
      </label>
      <label>
        <span>Limit</span>
        <select value={limit} onChange={(event) => setLimit(Number(event.target.value))}>
          {[10, 25, 50, 100].map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </label>
      <label>
        <span>Risk</span>
        <select value={riskLevel} onChange={(event) => setRiskLevel(event.target.value)}>
          <option value="">All</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </label>
      <label>
        <span>Sort</span>
        <select value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
          <option value="risk_desc">Risk score</option>
          <option value="confidence_desc">Confidence</option>
          <option value="analyzed_desc">Analyzed time</option>
          <option value="source_asc">Source</option>
        </select>
      </label>
      {mode === "search" ? (
        <label className="wide-control">
          <span>Search query</span>
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="CVE id, product, keyword…" />
        </label>
      ) : null}
      <button className="primary-button" onClick={onRefresh}>Refresh</button>
    </div>
  );
}

function Overview({ health, status, evaluationDiagnostics }) {
  const totals = status?.totals || {};
  const sources = status?.sources || {};
  const cve = sources.cve || {};
  const dbHealthy = health?.database === "ok";

  return (
    <div className="overview-grid">
      <MetricCard label="API status" value={health?.status || "unknown"} note={dbHealthy ? "Database reachable" : "Database degraded"} tone={dbHealthy ? "good" : "bad"} />
      <MetricCard label="Analyzed findings" value={totals.analyzed ?? "-"} note={`${totals.total ?? "-"} total records`} />
      <MetricCard label="CVE coverage" value={formatPercent(cve.analysis_coverage)} note={`${cve.analyzed ?? 0}/${cve.total ?? 0}`} />
      <MetricCard label="Avg analyzed CVE risk" value={`${formatNumber(cve.avg_risk_score)} / 10`} note="Corpus-level persisted analysis" />
      <MetricCard label="Pipeline" value={status?.pipeline_version || "-"} note="Backend version" />
      <MetricCard label="Diagnostic rows" value={evaluationDiagnostics?.record_count ?? "-"} note="Sample only" />
    </div>
  );
}

export function StatusPanel({ status, error, onRefresh, health, loading = false }) {
  if (loading && !status && !error) {
    return (
      <Section title="Operational status" description="Pipeline health and source backlog from existing API status endpoints.">
        <div className="empty-state large">Loading operations status...</div>
      </Section>
    );
  }

  if (error) {
    return (
      <Section title="Operational status" description="Operator or admin role required." actions={<button className="secondary-button" onClick={onRefresh}>Retry</button>}>
        <Alert error={error} />
      </Section>
    );
  }

  const sources = status?.sources || {};
  const totals = status?.totals || {};
  return (
    <Section title="Operational status" description="Worker and persistence status exposed by the authenticated FastAPI backend." actions={<button className="secondary-button" onClick={onRefresh}>Refresh status</button>}>
      <div className="overview-grid compact-overview">
        <MetricCard label="API health" value={health?.status || "-"} note={health?.database ? `Database ${health.database}` : "Health endpoint"} tone={health?.database === "ok" ? "good" : health ? "bad" : undefined} />
        <MetricCard label="Total records" value={totals.total ?? "-"} />
        <MetricCard label="Processed" value={totals.processed ?? "-"} />
        <MetricCard label="Unprocessed" value={totals.unprocessed ?? "-"} />
        <MetricCard label="Analyzed" value={totals.analyzed ?? "-"} />
      </div>
      <div className="operations-grid">
        <div className="compact-table-shell">
          <table className="compact-table">
            <thead><tr><th>Source</th><th>Total</th><th>Processed</th><th>Unprocessed</th><th>Analyzed</th><th>Coverage</th><th>Avg risk</th></tr></thead>
            <tbody>
              {Object.entries(sources).map(([source, row]) => (
                <tr key={source}>
                  <td className="mono">{source}</td>
                  <td>{row.total}</td>
                  <td>{row.processed}</td>
                  <td>{row.unprocessed}</td>
                  <td>{row.analyzed}</td>
                  <td>{formatPercent(row.analysis_coverage)}</td>
                  <td>{formatNumber(row.avg_risk_score)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <section className="panel-card operations-side-panel">
          <div className="panel-title-row">
            <div>
              <h3>Performance metrics</h3>
              <p className="panel-subtitle">No persisted worker or benchmark metrics endpoint is available.</p>
            </div>
          </div>
          <p className="empty-state">Run-time benchmark output is available from the local benchmark script, but this UI only shows metrics returned by the API.</p>
        </section>
      </div>
    </Section>
  );
}

function EvaluationPanel({ snapshot, diagnostics, loading, error, onRefresh }) {
  const summary = snapshot?.summary;
  const rows = snapshot?.rows || [];
  const distribution = Object.entries(diagnostics?.risk_level_distribution || {});
  if (loading && !snapshot && !diagnostics) {
    return <div className="empty-state large">Loading evaluation diagnostics...</div>;
  }

  return (
    <>
      {error ? <Alert error={error} /> : null}
      {loading ? <div className="empty-state">Refreshing evaluation diagnostics...</div> : null}
      <div className="evaluation-grid">
        <section className="panel-card">
          <div className="panel-title-row">
            <div>
              <h3>Diagnostic sample</h3>
              <p className="panel-subtitle">Sample only, not full corpus.</p>
            </div>
          </div>
          <div className="kv-grid">
            <div><span>Sample dynamic avg</span><strong>{formatNumber(summary?.avg_final_dynamic_score)}</strong></div>
            <div><span>Sample CVSS-only avg</span><strong>{formatNumber(summary?.avg_cvss_only_score)}</strong></div>
            <div><span>Reprioritized</span><strong>{summary?.reprioritized_count_lift_ge_1_5 ?? "-"}</strong></div>
            <div><span>Graph supported</span><strong>{summary?.graph_supported_count ?? "-"}</strong></div>
          </div>
        </section>
        <section className="panel-card">
          <div className="panel-title-row">
            <div>
              <h3>Sample risk distribution</h3>
              <p className="panel-subtitle">Computed from diagnostics rows.</p>
            </div>
          </div>
          {distribution.length ? (
            <div className="risk-distribution">
              {distribution.map(([level, count]) => (
                <div key={level} className="distribution-row">
                  <RiskBadge level={level} />
                  <div className="distribution-track"><span style={{ width: `${Math.min(100, count)}%` }} /></div>
                  <strong>{count}</strong>
                </div>
              ))}
            </div>
          ) : <p className="empty-state">No evaluation diagnostics loaded.</p>}
        </section>
        <section className="panel-card wide-panel">
          <div className="panel-title-row">
            <h3>Top reprioritized CVEs</h3>
            {onRefresh ? <button className="secondary-button" onClick={onRefresh}>Refresh evaluation</button> : null}
          </div>
          {rows.length ? (
            <div className="compact-table-shell">
              <table className="compact-table">
                <thead><tr><th>CVE</th><th>Dynamic</th><th>CVSS baseline</th><th>Lift</th><th>Level</th></tr></thead>
                <tbody>
                  {rows.slice(0, 8).map((row) => (
                    <tr key={row.cve_id}>
                      <td className="mono">{row.cve_id}</td>
                      <td>{formatNumber(row.final_dynamic_score)}</td>
                      <td>{formatNumber(row.baseline_cvss_only_score)}</td>
                      <td>{formatNumber(row.lift_from_cvss_only)}</td>
                      <td><RiskBadge level={row.risk_level} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <p className="empty-state">No evaluation rows.</p>}
        </section>
      </div>
    </>
  );
}

function AnalyzeSandbox() {
  const [source, setSource] = useState("cve");
  const [payload, setPayload] = useState(SAMPLE_PAYLOADS.cve);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function updateSource(nextSource) {
    setSource(nextSource);
    setPayload(SAMPLE_PAYLOADS[nextSource]);
    setResult(null);
    setError("");
  }

  async function runAnalysis() {
    setLoading(true);
    setError("");
    try {
      const parsed = JSON.parse(payload);
      setResult(await analyzeInput(source, parsed));
    } catch (err) {
      setError(err.message || String(err));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Section title="Ad-hoc analyzer" description="Run one payload through the analysis engine without writing it to MongoDB.">
      <div className="sandbox-grid">
        <div className="sandbox-editor">
          <label>
            <span>Source</span>
            <select value={source} onChange={(event) => updateSource(event.target.value)}>
              {ANALYZE_SOURCES.map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}
            </select>
          </label>
          <textarea value={payload} onChange={(event) => setPayload(event.target.value)} spellCheck="false" />
          <button className="primary-button" onClick={runAnalysis} disabled={loading}>{loading ? "Analyzing…" : "Analyze payload"}</button>
          {error ? <div className="error-banner">{error}</div> : null}
        </div>
        <div className="sandbox-result">
          {result ? <JsonBlock title="Analysis result" data={result} /> : <div className="empty-state large">Run a payload to see score, confidence, and evidence output.</div>}
        </div>
      </div>
    </Section>
  );
}

export default function App() {
  const health = useAsyncState(null);
  const status = useAsyncState(null);
  const findings = useAsyncState([]);
  const detail = useAsyncState(null);
  const evaluation = useAsyncState(null);
  const diagnostics = useAsyncState(null);
  const [source, setSource] = useState("");
  const [limit, setLimit] = useState(25);
  const [mode, setMode] = useState("top");
  const [query, setQuery] = useState("");
  const [riskLevel, setRiskLevel] = useState("");
  const [sortBy, setSortBy] = useState("risk_desc");
  const [activeTab, setActiveTab] = useState("findings");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [authStatus, setAuthStatus] = useState(getAuthStatus());
  const overviewRequestId = useRef(0);
  const findingsRequestId = useRef(0);
  const detailRequestId = useRef(0);
  const evaluationRequestId = useRef(0);
  const debouncedQuery = useDebouncedValue(query);
  const effectiveQuery = mode === "search" ? debouncedQuery : "";
  const selectedKey = detail.value ? `${detail.value.source}:${detail.value.entity_id}` : "";
  const displayedFindings = useMemo(
    () => filterAndSortFindings(findings.value, { riskLevel, sortBy }),
    [findings.value, riskLevel, sortBy],
  );

  function applyApiKey() {
    setRuntimeApiKey(apiKeyInput);
    setApiKeyInput("");
    setAuthStatus(getAuthStatus());
    loadOverview();
    loadFindings();
    if (activeTab === "evaluation") loadEvaluation({ force: true });
  }

  function clearApiKey() {
    clearRuntimeApiKey();
    setApiKeyInput("");
    setAuthStatus(getAuthStatus());
    status.setValue(null);
    loadOverview();
    loadFindings();
    if (activeTab === "evaluation") loadEvaluation({ force: true });
  }

  async function loadOverview() {
    const requestId = ++overviewRequestId.current;
    health.setLoading(true);
    status.setLoading(true);
    health.setError("");
    status.setError("");

    const [healthResult, statusResult] = await Promise.all([
      settleRequest(getHealth()),
      settleRequest(getStatusOverview()),
    ]);
    if (overviewRequestId.current !== requestId) return;

    health.setError(healthResult.error || "");
    status.setError(statusResult.error || "");
    if (healthResult.value) health.setValue(healthResult.value);
    if (statusResult.value) status.setValue(statusResult.value);
    health.setLoading(false);
    status.setLoading(false);
  }

  async function loadEvaluation({ force = false } = {}) {
    if (!force && (evaluation.loading || diagnostics.loading || evaluation.value || diagnostics.value)) return;
    const requestId = ++evaluationRequestId.current;
    evaluation.setLoading(true);
    diagnostics.setLoading(true);
    evaluation.setError("");
    diagnostics.setError("");

    const [evaluationResult, diagnosticsResult] = await Promise.all([
      settleRequest(getEvaluationSnapshot({ limit: 50, topK: 10 })),
      settleRequest(getEvaluationDiagnostics({ limit: 500 })),
    ]);
    if (evaluationRequestId.current !== requestId) return;

    evaluation.setError(evaluationResult.error || "");
    diagnostics.setError(diagnosticsResult.error || "");
    if (evaluationResult.value) evaluation.setValue(evaluationResult.value);
    if (diagnosticsResult.value) diagnostics.setValue(diagnosticsResult.value);
    evaluation.setLoading(false);
    diagnostics.setLoading(false);
  }

  async function loadFindings({ searchQuery = effectiveQuery } = {}) {
    const requestId = ++findingsRequestId.current;
    findings.setLoading(true);
    findings.setError("");
    try {
      let payload;
      if (mode === "recent") {
        payload = await getRecentFindings({ source: source || "cve", limit });
      } else if (mode === "search") {
        payload = searchQuery.trim() ? await searchFindings({ source: source || "cve", query: searchQuery.trim(), limit }) : [];
      } else {
        payload = await getTopFindings({ source, limit, mode });
      }
      if (findingsRequestId.current !== requestId) return;
      findings.setValue(payload);
      if (!payload.some((item) => `${item.source}:${item.entity_id}` === selectedKey)) {
        detail.setValue(null);
        detail.setError("");
      }
    } catch (err) {
      if (findingsRequestId.current === requestId) findings.setError(err);
    } finally {
      if (findingsRequestId.current === requestId) findings.setLoading(false);
    }
  }

  async function selectFinding(finding) {
    const requestId = ++detailRequestId.current;
    detail.setLoading(true);
    detail.setError("");
    try {
      const payload = await getFindingDetail({ source: finding.source, entityId: finding.entity_id });
      if (detailRequestId.current !== requestId) return;
      detail.setValue(payload);
    } catch (err) {
      if (detailRequestId.current === requestId) detail.setError(err);
    } finally {
      if (detailRequestId.current === requestId) detail.setLoading(false);
    }
  }

  useEffect(() => { loadOverview(); }, []);
  useEffect(() => { loadFindings({ searchQuery: effectiveQuery }); }, [source, limit, mode, effectiveQuery]);
  useEffect(() => {
    if (activeTab === "evaluation") loadEvaluation();
  }, [activeTab]);
  useEffect(() => {
    if (activeTab === "operations") loadOverview();
  }, [activeTab]);

  const globalError = useMemo(() => health.error || findings.error, [health.error, findings.error]);

  return (
    <main className="app-shell">
      <header className="hero-section">
        <div>
          <StatusPill label="Threat intelligence analyst console" status="info" />
          <h1>Multi-source risk triage</h1>
          <p>Review CVE, URLhaus, and dark-web intelligence with explicit risk, confidence, evidence quality, and model diagnostics.</p>
        </div>
        <button className="secondary-button" onClick={() => { loadOverview(); loadFindings(); if (activeTab === "evaluation") loadEvaluation({ force: true }); }}>Refresh all</button>
      </header>

      <AuthPanel authStatus={authStatus} apiKeyInput={apiKeyInput} setApiKeyInput={setApiKeyInput} onApply={applyApiKey} onClear={clearApiKey} />

      <Alert error={globalError} />

      <Overview health={health.value} status={status.value} evaluationDiagnostics={diagnostics.value} />
      <SystemNotices healthState={health} statusError={status.error} evaluationError={evaluation.error} diagnosticsError={diagnostics.error} />

      <div className="workspace-grid">
        <section className="main-column">
          <TabNav activeTab={activeTab} setActiveTab={setActiveTab} />

          {activeTab === "findings" ? (
            <Section
              title="Findings"
              description="Prioritized records from persisted analysis results. Select a row to inspect evidence and scoring details."
              actions={<SourceControls source={source} setSource={setSource} limit={limit} setLimit={setLimit} mode={mode} setMode={setMode} query={query} setQuery={setQuery} riskLevel={riskLevel} setRiskLevel={setRiskLevel} sortBy={sortBy} setSortBy={setSortBy} onRefresh={loadFindings} />}
            >
              {findings.error ? (
                <Alert error={findings.error} />
              ) : (
                <>
                  <AnalystDashboard findings={displayedFindings} status={status.value} diagnostics={diagnostics.value} loading={findings.loading} />
                  {findings.loading ? <div className="empty-state large">Loading findings...</div> : <FindingTable findings={displayedFindings} selectedKey={selectedKey} onSelect={selectFinding} />}
                </>
              )}
            </Section>
          ) : null}

          {activeTab === "evaluation" ? (
            <Section title="Evaluation" description="CVE model diagnostics and reprioritization snapshot from the API. Metrics in this tab are sample-scoped unless explicitly labeled corpus-level.">
              <EvaluationPanel
                snapshot={evaluation.value}
                diagnostics={diagnostics.value}
                loading={evaluation.loading || diagnostics.loading}
                error={evaluation.error || diagnostics.error}
                onRefresh={() => loadEvaluation({ force: true })}
              />
            </Section>
          ) : null}

          {activeTab === "operations" ? <StatusPanel status={status.value} error={status.error} onRefresh={loadOverview} health={health.value} loading={status.loading || health.loading} /> : null}

          {activeTab === "adhoc" ? <AnalyzeSandbox /> : null}
        </section>

        <FindingDetail detail={detail.value} loading={detail.loading} error={detail.error} />
      </div>
    </main>
  );
}
