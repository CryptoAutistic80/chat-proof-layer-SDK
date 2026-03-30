import React from "react";

export function SdkLaneTabs({ scenarios, activeScenarioId, onSelect }) {
  return (
    <div className="sdk-lane-tabs" role="tablist" aria-label="Chatbot scenarios">
      {scenarios.map((scenario) => (
        <button
          key={scenario.id}
          type="button"
          role="tab"
          aria-selected={activeScenarioId === scenario.id}
          className={`sdk-lane-tab ${activeScenarioId === scenario.id ? "is-active" : ""}`}
          onClick={() => onSelect(scenario.id)}
        >
          <div className="sdk-lane-tab-top">
            <span className="section-label">Scenario</span>
            <span className="sdk-lane-count">{scenario.codeLanguage}</span>
          </div>
          <strong>{scenario.label}</strong>
          <span>{scenario.description}</span>
        </button>
      ))}
    </div>
  );
}
