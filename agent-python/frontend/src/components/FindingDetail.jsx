import { formatNumber, titleCase } from "../utils/format";
import { RiskBadge, SourceBadge } from "./Badges";
import MetricCard from "./MetricCard";
import BreakdownPanel from "./BreakdownPanel";
import JsonBlock from "./JsonBlock";
import { detailEvidenceGroups } from "../viewModels";

function ChipList({ label, values }) {
  const items = Array.isArray(values) ? values.filter(Boolean) : [];
  if (!items.length) return null;
  return (
    <div className="chip-group">
      <span className="chip-group-label">{titleCase(label)}</span>
      <div className="chip-row">
        {items.slice(0, 16).map((item) => <span className="data-chip" key={`${label}-${item}`}>{item}</span>)}
        {items.length > 16 ? <span className="data-chip muted">+{items.length - 16}</span> : null}
      </div>
    </div>
  );
}

function EvidenceQuality({ evidence = {} }) {
  const stats = evidence.urlhaus_match_stats || {};
  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>Evidence quality</h3></div>
      <div className="kv-grid">
        <div><span>CVSS</span><strong>{formatNumber(evidence.cvss_score)}</strong></div>
        <div><span>URLhaus accepted</span><strong>{stats.accepted_match_count ?? evidence.related_urlhaus_count ?? 0}</strong></div>
        <div><span>URLhaus rejected</span><strong>{stats.rejected_match_count ?? 0}</strong></div>
        <div><span>Exact CVE hits</span><strong>{stats.exact_cve_hits ?? 0}</strong></div>
        <div><span>High-signal hits</span><strong>{stats.high_signal_hits ?? 0}</strong></div>
        <div><span>Shared terms</span><strong>{Array.isArray(stats.shared_terms) ? stats.shared_terms.length : 0}</strong></div>
      </div>
      <ChipList label="shared_terms" values={stats.shared_terms} />
      <ChipList label="acceptance_reasons" values={stats.acceptance_reasons} />
    </section>
  );
}

function EvidenceDecisionList({ title, items, count }) {
  const rows = Array.isArray(items) ? items : [];
  return (
    <div className="decision-group">
      <div className="decision-title-row">
        <strong>{title}</strong>
        <span>{count ?? rows.length}</span>
      </div>
      {rows.length ? (
        <div className="decision-list">
          {rows.slice(0, 6).map((item, index) => (
            <div className="decision-item" key={`${title}-${index}`}>
              <div className="decision-item-head">
                <span>{item.url || item.title || item.id || item.entity_id || "Evidence item"}</span>
                {item.score !== undefined ? <strong>{formatNumber(item.score, 4)}</strong> : null}
              </div>
              <div className="decision-meta">
                {item.acceptance_reason ? <span>reason: {item.acceptance_reason}</span> : null}
                {item.rejection_reason ? <span>reason: {item.rejection_reason}</span> : null}
                {item.url_status ? <span>status: {item.url_status}</span> : null}
                {item.threat ? <span>threat: {item.threat}</span> : null}
              </div>
              <ChipList label="tags" values={item.tags} />
            </div>
          ))}
        </div>
      ) : <p className="empty-state">No serialized {title.toLowerCase()} items.</p>}
    </div>
  );
}

function EvidenceDecisions({ detail }) {
  const groups = detailEvidenceGroups(detail);
  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>Correlation decisions</h3></div>
      <div className="kv-grid">
        <div><span>Accepted</span><strong>{groups.counts.accepted}</strong></div>
        <div><span>Rejected</span><strong>{groups.counts.rejected}</strong></div>
        <div><span>Manual review</span><strong>{groups.counts.manualReview}</strong></div>
        <div><span>Shared terms</span><strong>{groups.sharedTerms.length}</strong></div>
      </div>
      <ChipList label="acceptance_reasons" values={groups.reasons} />
      <ChipList label="shared_terms" values={groups.sharedTerms} />
      <EvidenceDecisionList title="Accepted evidence" items={groups.accepted} count={groups.counts.accepted} />
      <EvidenceDecisionList title="Rejected evidence" items={groups.rejected} count={groups.counts.rejected} />
      <EvidenceDecisionList title="Manual-review evidence" items={groups.manualReview} count={groups.counts.manualReview} />
    </section>
  );
}

function ObjectMetrics({ title, data = {}, keys = [] }) {
  const entries = keys.map((key) => [key, data[key]]).filter(([, value]) => value !== undefined && value !== null);
  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>{title}</h3></div>
      {entries.length ? (
        <div className="kv-grid">
          {entries.map(([key, value]) => (
            <div key={key}><span>{titleCase(key)}</span><strong>{typeof value === "number" ? formatNumber(value, 4) : String(value)}</strong></div>
          ))}
        </div>
      ) : <p className="empty-state">No metrics available.</p>}
    </section>
  );
}

function DistributionPanel({ title, data = {} }) {
  const entries = Object.entries(data || {}).sort(([left], [right]) => left.localeCompare(right));
  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>{title}</h3></div>
      {entries.length ? (
        <div className="distribution-list">
          {entries.map(([key, value]) => (
            <div className="distribution-row compact" key={key}>
              <span>{titleCase(key)}</span>
              <div className="distribution-track"><span style={{ width: `${Math.min(100, Number(value || 0) * 16)}%` }} /></div>
              <strong>{value}</strong>
            </div>
          ))}
        </div>
      ) : <p className="empty-state">No distribution available.</p>}
    </section>
  );
}

function ReviewPanel({ critic = {} }) {
  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>Critic review</h3></div>
      <div className="kv-grid">
        <div><span>Status</span><strong>{critic.status || "unknown"}</strong></div>
        <div><span>Warnings</span><strong>{Array.isArray(critic.warnings) ? critic.warnings.length : 0}</strong></div>
      </div>
      {critic.summary ? <p className="panel-copy">{critic.summary}</p> : null}
      <InlineTextList title="Critic issues" items={critic.issues} />
      <InlineTextList title="Critic warnings" items={critic.warnings} />
    </section>
  );
}

function TracePanel({ title, items = [] }) {
  const rows = Array.isArray(items) ? items : [];
  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>{title}</h3></div>
      {rows.length ? (
        <ol className="trace-list">
          {rows.slice(0, 12).map((item, index) => (
            <li key={`${title}-${index}`}>
              <strong>{item.agent || item.step || item.action || item.status || `Step ${index + 1}`}</strong>
              <span>{item.action || item.status || item.summary || item.reason || ""}</span>
            </li>
          ))}
        </ol>
      ) : <p className="empty-state">No {title.toLowerCase()} available.</p>}
    </section>
  );
}

function NlpPanel({ entities = {} }) {
  const order = ["cve_ids", "cwe_ids", "products", "versions", "vuln_types", "impacts", "threat_terms", "iocs", "domains", "keywords", "salient_phrases"];
  const keys = order.filter((key) => Array.isArray(entities[key]) && entities[key].length);

  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>NLP entities</h3></div>
      {keys.length ? keys.map((key) => <ChipList key={key} label={key} values={entities[key]} />) : <p className="empty-state">No extracted entities.</p>}
    </section>
  );
}

function TextList({ title, items }) {
  const list = Array.isArray(items) ? items.filter(Boolean) : [];
  return (
    <section className="panel-card">
      <div className="panel-title-row"><h3>{title}</h3></div>
      {list.length ? (
        <ul className="text-list">
          {list.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}
        </ul>
      ) : <p className="empty-state">None.</p>}
    </section>
  );
}

function InlineTextList({ title, items }) {
  const list = Array.isArray(items) ? items.filter(Boolean) : [];
  return (
    <div className="inline-list-block">
      <strong>{title}</strong>
      {list.length ? (
        <ul className="text-list">
          {list.map((item, index) => <li key={`${title}-${index}`}>{item}</li>)}
        </ul>
      ) : <p className="empty-state">None.</p>}
    </div>
  );
}

export default function FindingDetail({ detail, loading }) {
  if (loading) {
    return <aside className="detail-pane"><div className="empty-state large">Loading finding detail…</div></aside>;
  }

  if (!detail) {
    return <aside className="detail-pane"><div className="empty-state large">Select a finding to inspect evidence, scoring, and recommendations.</div></aside>;
  }

  const evidence = detail.evidence || {};
  const confidenceBreakdown = detail.confidence_breakdown || detail.agent_outputs?.confidence_breakdown || {};

  return (
    <aside className="detail-pane">
      <div className="detail-hero">
        <div>
          <div className="detail-kicker"><SourceBadge source={detail.source} /> <RiskBadge level={detail.risk_level} /></div>
          <h2>{detail.entity_id}</h2>
          <p>{detail.diagnosis}</p>
        </div>
        <div className="detail-score-stack">
          <MetricCard label="Risk score" value={formatNumber(detail.risk_score)} />
          <MetricCard label="Confidence" value={formatNumber(detail.confidence, 3)} />
        </div>
      </div>

      <div className="detail-grid">
        <BreakdownPanel title="Primary score drivers" data={detail.feature_breakdown} type="risk" />
        <BreakdownPanel title="Confidence breakdown" data={confidenceBreakdown} type="confidence" emptyLabel="No source-specific confidence breakdown available. Re-run analysis with the latest model to generate it." />
        <EvidenceQuality evidence={evidence} />
        <EvidenceDecisions detail={detail} />
        <ObjectMetrics title="Graph summary" data={detail.graph_summary} keys={["node_count", "edge_count", "cross_source_edge_count", "centrality_score", "graph_density", "average_edge_confidence", "structural_strength"]} />
        <DistributionPanel title="Graph relations" data={detail.graph_summary?.relation_distribution} />
        <DistributionPanel title="Graph provenance" data={detail.graph_summary?.provenance_distribution} />
        <BreakdownPanel title="Source contributions" data={detail.source_contributions} />
        <BreakdownPanel title="Counterfactuals" data={detail.counterfactuals} />
        <ReviewPanel critic={detail.critic_review} />
        <TracePanel title="Execution plan" items={detail.execution_plan} />
        <TracePanel title="Orchestration trace" items={detail.orchestration_trace} />
        <NlpPanel entities={evidence.nlp_entities || {}} />
        <TextList title="Explanation" items={detail.explanation} />
        <TextList title="Recommendations" items={detail.recommendations} />
      </div>

      <JsonBlock title="Full detail payload" data={detail} />
    </aside>
  );
}
