import React from "react";

export function ScenarioCard({ preset, active, onSelect, modeLabel }) {
  return (
    <button
      type="button"
      className={`scenario-card ${active ? "is-active" : ""}`}
      onClick={() => onSelect(preset.key)}
    >
      <span className="section-label">Scenario</span>
      <strong>{preset.label}</strong>
      <p>{preset.businessReason}</p>
      <div className="scenario-meta">
        <span>{preset.outcomeLabel}</span>
        <span>{modeLabel}</span>
      </div>
    </button>
  );
}

