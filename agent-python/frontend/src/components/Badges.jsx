export function RiskBadge({ level }) {
  const normalized = String(level || "UNKNOWN").toUpperCase();
  return <span className="risk-badge" data-level={normalized}>{normalized}</span>;
}

export function SourceBadge({ source }) {
  return <span className="source-badge">{String(source || "unknown").toUpperCase()}</span>;
}

export function StatusPill({ label, status }) {
  return <span className="status-pill" data-status={status || "neutral"}>{label}</span>;
}
