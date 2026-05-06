import { useState } from "react";
import { formatNumber, titleCase } from "../utils/format";

const PRIMARY_RISK_KEYS = [
  "severity_score",
  "exploitability_score",
  "active_threat_score",
  "temporal_score",
  "age_penalty",
  "final_score",
];

const PRIMARY_CONFIDENCE_KEYS = [
  "base_confidence",
  "metadata_confidence",
  "entity_confidence",
  "external_evidence_confidence",
  "correlation_confidence",
  "freshness_confidence",
  "penalties",
  "final_confidence",
];

function numericEntries(data = {}) {
  return Object.entries(data || {}).filter(([, value]) => typeof value === "number" && Number.isFinite(value));
}

function barTone(value) {
  if (value < 0) return "negative";
  if (value >= 1) return "strong";
  if (value > 0) return "positive";
  return "neutral";
}

function entrySorter(preferredKeys) {
  return ([a], [b]) => {
    const ia = preferredKeys.indexOf(a);
    const ib = preferredKeys.indexOf(b);
    if (ia !== -1 && ib !== -1) return ia - ib;
    if (ia !== -1) return -1;
    if (ib !== -1) return 1;
    return a.localeCompare(b);
  };
}

export function BreakdownBar({ label, value, max }) {
  const width = max > 0 ? Math.min(100, Math.abs(value / max) * 100) : 0;
  return (
    <div className="breakdown-bar" data-tone={barTone(value)}>
      <div className="breakdown-bar-head">
        <span>{titleCase(label)}</span>
        <strong>{formatNumber(value, 3)}</strong>
      </div>
      <div className="bar-track">
        <div className="bar-fill" style={{ width: `${width}%` }} />
      </div>
    </div>
  );
}

export default function BreakdownPanel({ title, data, type = "generic", emptyLabel = "No breakdown available." }) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const preferredKeys = type === "confidence" ? PRIMARY_CONFIDENCE_KEYS : type === "risk" ? PRIMARY_RISK_KEYS : [];
  const allEntries = numericEntries(data).filter(([key]) => !["raw_confidence"].includes(key)).sort(entrySorter(preferredKeys));
  const primaryEntries = preferredKeys.length ? allEntries.filter(([key]) => preferredKeys.includes(key)) : allEntries;
  const advancedEntries = preferredKeys.length ? allEntries.filter(([key]) => !preferredKeys.includes(key)) : [];
  const visibleEntries = showAdvanced ? [...primaryEntries, ...advancedEntries] : primaryEntries;
  const max = Math.max(1, ...visibleEntries.map(([, value]) => Math.abs(value)));

  return (
    <section className="panel-card">
      <div className="panel-title-row">
        <div>
          <h3>{title}</h3>
          {type === "confidence" ? <p className="panel-subtitle">Confidence is evidence quality, not severity.</p> : null}
        </div>
      </div>
      {primaryEntries.length ? (
        <div className="breakdown-list">
          {primaryEntries.map(([key, value]) => (
            <BreakdownBar key={key} label={key} value={value} max={max} />
          ))}
        </div>
      ) : (
        <p className="empty-state">{emptyLabel}</p>
      )}
      {advancedEntries.length ? (
        <div className="advanced-breakdown">
          <button className="mini-button" onClick={() => setShowAdvanced((value) => !value)}>
            {showAdvanced ? "Hide advanced signals" : "Show advanced signals"}
          </button>
          {showAdvanced ? (
            <div className="breakdown-list advanced-list">
              {advancedEntries.map(([key, value]) => (
                <BreakdownBar key={key} label={key} value={value} max={max} />
              ))}
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
