import { compactDate, formatNumber } from "../utils/format";
import { RiskBadge, SourceBadge } from "./Badges";
import { confidenceBand, evidenceCounts } from "../viewModels";

function EvidenceMini({ finding }) {
  const summary = finding.evidence_summary || {};
  const source = String(finding.source || "").toLowerCase();
  if (source === "urlhaus") {
    return (
      <div className="evidence-mini" data-active="true">
        <span>IOC feed</span>
      </div>
    );
  }

  const { accepted, rejected, manualReview, exact, highSignal } = evidenceCounts(finding);
  const active = Boolean(summary.has_active_evidence || accepted > 0 || exact > 0 || highSignal > 0);

  return (
    <div className="evidence-mini" data-active={active ? "true" : "false"}>
      <span>UH {accepted}/{rejected}</span>
      {manualReview ? <span>Review {manualReview}</span> : null}
      {exact ? <span>Exact {exact}</span> : null}
      {highSignal ? <span>Signal {highSignal}</span> : null}
    </div>
  );
}

export default function FindingTable({ findings, selectedKey, onSelect }) {
  if (!findings?.length) {
    return <div className="empty-state large">No findings returned.</div>;
  }

  return (
    <div className="table-shell">
      <table className="findings-table">
        <thead>
          <tr>
            <th>Finding</th>
            <th>Source</th>
            <th>Risk</th>
            <th>Score</th>
            <th>CVSS</th>
            <th>Evidence</th>
            <th>Confidence</th>
            <th>Band</th>
            <th>Analyzed</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((finding) => {
            const key = `${finding.source}:${finding.entity_id}`;
            const band = confidenceBand(finding.confidence);
            const cvss = finding.cvss_score ?? finding.evidence_summary?.cvss_score;
            return (
              <tr
                key={key}
                className={selectedKey === key ? "selected-row" : ""}
                onClick={() => onSelect?.(finding)}
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") onSelect?.(finding);
                }}
              >
                <td>
                  <div className="finding-id">{finding.entity_id}</div>
                  <div className="finding-diagnosis">{finding.diagnosis || "No diagnosis available."}</div>
                </td>
                <td><SourceBadge source={finding.source} /></td>
                <td><RiskBadge level={finding.risk_level} /></td>
                <td className="mono">{formatNumber(finding.risk_score)}</td>
                <td className="mono">{cvss !== undefined && cvss !== null ? formatNumber(cvss) : "-"}</td>
                <td><EvidenceMini finding={finding} /></td>
                <td className="mono">{formatNumber(finding.confidence, 3)}</td>
                <td><span className="confidence-band" data-band={band}>{band}</span></td>
                <td>{compactDate(finding.analyzed_at)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
