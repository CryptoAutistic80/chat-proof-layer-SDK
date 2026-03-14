import React from "react";

export function SdkScenarioCard({ scenario, active, onSelect }) {
  return (
    <button
      type="button"
      className={`scenario-card sdk-scenario-card ${active ? "is-active" : ""}`}
      onClick={() => onSelect(scenario.id)}
    >
      <div className="scenario-card-top">
        <span className="section-label">{scenario.lane}</span>
        <span className="scenario-role-tag">{scenario.actorRole}</span>
      </div>
      <strong>{scenario.label}</strong>
      <p>{scenario.description}</p>
      <div className="scenario-chip-row">
        <span className="scenario-chip">{scenario.packType}</span>
        <span className="scenario-chip">{scenario.steps.length} bundle steps</span>
      </div>
      <div className="scenario-meta">
        <span>{scenario.steps.map((step) => step.itemType).join(" + ")}</span>
      </div>
    </button>
  );
}
