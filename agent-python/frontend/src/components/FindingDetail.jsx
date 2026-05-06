import { formatNumber, titleCase } from "../utils/format";
import { RiskBadge, SourceBadge } from "./Badges";
import MetricCard from "./MetricCard";
import BreakdownPanel from "./BreakdownPanel";
import JsonBlock from "./JsonBlock";

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
        <NlpPanel entities={evidence.nlp_entities || {}} />
        <TextList title="Explanation" items={detail.explanation} />
        <TextList title="Recommendations" items={detail.recommendations} />
      </div>

      <JsonBlock title="Full detail payload" data={detail} />
    </aside>
  );
}
