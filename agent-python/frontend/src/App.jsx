import { useEffect, useMemo, useState } from "react";
import {
  analyzeInput,
  getEvaluationDiagnostics,
  getEvaluationSnapshot,
  getFindingDetail,
  getHealth,
  getRecentFindings,
  getStatusOverview,
  getTopFindings,
  searchFindings,
} from "./api";
import FindingTable from "./components/FindingTable";
import FindingDetail from "./components/FindingDetail";
import MetricCard from "./components/MetricCard";
import JsonBlock from "./components/JsonBlock";
import { RiskBadge, StatusPill } from "./components/Badges";
import { formatNumber, formatPercent } from "./utils/format";
import "./App.css";

const SOURCES = ["", "cve", "urlhaus", "dread"];
const ANALYZE_SOURCES = ["cve", "urlhaus", "dread"];
const TABS = [
  { id: "findings", label: "Findings" },
  { id: "evaluation", label: "Evaluation" },
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

function SourceControls({ source, setSource, limit, setLimit, mode, setMode, query, setQuery, onRefresh }) {
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

function EvaluationPanel({ snapshot, diagnostics }) {
  const summary = snapshot?.summary;
  const rows = snapshot?.rows || [];
  return (
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
        <div className="risk-distribution">
          {Object.entries(diagnostics?.risk_level_distribution || {}).map(([level, count]) => (
            <div key={level} className="distribution-row">
              <RiskBadge level={level} />
              <div className="distribution-track"><span style={{ width: `${Math.min(100, count)}%` }} /></div>
              <strong>{count}</strong>
            </div>
          ))}
        </div>
      </section>
      <section className="panel-card wide-panel">
        <div className="panel-title-row"><h3>Top reprioritized CVEs</h3></div>
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
  const [activeTab, setActiveTab] = useState("findings");
  const selectedKey = detail.value ? `${detail.value.source}:${detail.value.entity_id}` : "";

  async function loadOverview() {
    health.setError("");
    status.setError("");
    try {
      const [healthPayload, statusPayload, evaluationPayload, diagnosticsPayload] = await Promise.all([
        getHealth(),
        getStatusOverview(),
        getEvaluationSnapshot({ limit: 50, topK: 10 }).catch(() => null),
        getEvaluationDiagnostics({ limit: 500 }).catch(() => null),
      ]);
      health.setValue(healthPayload);
      status.setValue(statusPayload);
      evaluation.setValue(evaluationPayload);
      diagnostics.setValue(diagnosticsPayload);
    } catch (err) {
      health.setError(err.message || String(err));
    }
  }

  async function loadFindings() {
    findings.setLoading(true);
    findings.setError("");
    try {
      let payload;
      if (mode === "recent") {
        payload = await getRecentFindings({ source: source || "cve", limit });
      } else if (mode === "search") {
        payload = query.trim() ? await searchFindings({ source: source || "cve", query: query.trim(), limit }) : [];
      } else {
        payload = await getTopFindings({ source, limit, mode });
      }
      findings.setValue(payload);
      if (!payload.some((item) => `${item.source}:${item.entity_id}` === selectedKey)) detail.setValue(null);
    } catch (err) {
      findings.setError(err.message || String(err));
    } finally {
      findings.setLoading(false);
    }
  }

  async function selectFinding(finding) {
    detail.setLoading(true);
    detail.setError("");
    try {
      detail.setValue(await getFindingDetail({ source: finding.source, entityId: finding.entity_id }));
    } catch (err) {
      detail.setError(err.message || String(err));
    } finally {
      detail.setLoading(false);
    }
  }

  useEffect(() => { loadOverview(); }, []);
  useEffect(() => { loadFindings(); }, [source, limit, mode]);

  const globalError = useMemo(() => health.error || status.error || findings.error || detail.error, [health.error, status.error, findings.error, detail.error]);

  return (
    <main className="app-shell">
      <header className="hero-section">
        <div>
          <StatusPill label="Threat intelligence analyst console" status="info" />
          <h1>Multi-source risk triage</h1>
          <p>Review CVE, URLhaus, and dark-web intelligence with explicit risk, confidence, evidence quality, and model diagnostics.</p>
        </div>
        <button className="secondary-button" onClick={() => { loadOverview(); loadFindings(); }}>Refresh all</button>
      </header>

      {globalError ? <div className="error-banner">{globalError}</div> : null}

      <Overview health={health.value} status={status.value} evaluationDiagnostics={diagnostics.value} />

      <div className="workspace-grid">
        <section className="main-column">
          <TabNav activeTab={activeTab} setActiveTab={setActiveTab} />

          {activeTab === "findings" ? (
            <Section
              title="Findings"
              description="Prioritized records from persisted analysis results. Select a row to inspect evidence and scoring details."
              actions={<SourceControls source={source} setSource={setSource} limit={limit} setLimit={setLimit} mode={mode} setMode={setMode} query={query} setQuery={setQuery} onRefresh={loadFindings} />}
            >
              {findings.loading ? <div className="empty-state large">Loading findings…</div> : <FindingTable findings={findings.value} selectedKey={selectedKey} onSelect={selectFinding} />}
            </Section>
          ) : null}

          {activeTab === "evaluation" ? (
            <Section title="Evaluation" description="CVE model diagnostics and reprioritization snapshot from the API. Metrics in this tab are sample-scoped unless explicitly labeled corpus-level.">
              <EvaluationPanel snapshot={evaluation.value} diagnostics={diagnostics.value} />
            </Section>
          ) : null}

          {activeTab === "adhoc" ? <AnalyzeSandbox /> : null}
        </section>

        <FindingDetail detail={detail.value} loading={detail.loading} />
      </div>
    </main>
  );
}
