export default function MetricCard({ label, value, note, tone = "default" }) {
  return (
    <div className="metric-card" data-tone={tone}>
      <span className="metric-label">{label}</span>
      <strong className="metric-value">{value}</strong>
      {note ? <span className="metric-note">{note}</span> : null}
    </div>
  );
}
