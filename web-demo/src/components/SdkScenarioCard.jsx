import React from "react";

export function SdkScenarioCard({ scenario, active, onSelect }) {
  return (
    <button
      type="button"
      className={`scenario-card sdk-scenario-card ${active ? "is-active" : ""}`}
      onClick={() => onSelect(scenario.id)}
    >
      <span className="section-label">{scenario.lane}</span>
      <strong>{scenario.label}</strong>
      <p>{scenario.description}</p>
      <div className="scenario-meta">
        <span>{scenario.packType}</span>
        <span>{scenario.steps.map((step) => step.itemType).join(" + ")}</span>
      </div>
    </button>
  );
}
