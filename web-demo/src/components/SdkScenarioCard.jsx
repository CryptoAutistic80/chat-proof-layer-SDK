import React from "react";

export function SdkScenarioCard({ scenario, active, onSelect }) {
  const itemTypes = scenario.steps.map((step) => step.itemType);

  return (
    <button
      type="button"
      className={`scenario-card sdk-scenario-card ${active ? "is-active" : ""}`}
      onClick={() => onSelect(scenario.id)}
    >
      <div className="scenario-card-top">
        <span className="section-label">{scenario.category}</span>
        <span className="scenario-role-tag">{scenario.actorRole}</span>
      </div>
      <strong>{scenario.label}</strong>
      <p>{scenario.audienceSummary}</p>
      <div className="scenario-copy-stack">
        <div>
          <span className="scenario-copy-label">What gets recorded</span>
          <span>{itemTypes.join(" + ")}</span>
        </div>
        <div>
          <span className="scenario-copy-label">Why it helps</span>
          <span>{scenario.lawExplainer.record}</span>
        </div>
      </div>
      <div className="scenario-chip-row">
        <span className="scenario-chip">
          {scenario.packType ?? "No pack by default"}
        </span>
        <span className="scenario-chip">{scenario.codeLanguage}</span>
      </div>
    </button>
  );
}
