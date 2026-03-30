import React from "react";

export function SdkScenarioCard({ scenario, active, onSelect }) {
  return (
    <button
      type="button"
      className={`scenario-card sdk-scenario-card ${active ? "is-active" : ""}`}
      onClick={() => onSelect(scenario.id)}
    >
      <div className="scenario-card-top">
        <span className="section-label">{scenario.category}</span>
        <span className="scenario-role-tag">{scenario.codeLanguage}</span>
      </div>
      <strong>{scenario.label}</strong>
      <p>{scenario.audienceSummary}</p>
      <div className="scenario-copy-stack">
        <div>
          <span className="scenario-copy-label">Conversation proof</span>
          <span>Transcript hash + session signature</span>
        </div>
        <div>
          <span className="scenario-copy-label">Why it helps</span>
          <span>{scenario.lawExplainer.record}</span>
        </div>
      </div>
      <div className="scenario-chip-row">
        <span className="scenario-chip">{scenario.bundleFormat}</span>
        <span className="scenario-chip">{scenario.disclosureProfile}</span>
      </div>
    </button>
  );
}
