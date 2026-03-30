import React from "react";
import { AssuranceOptionToggles } from "./AssuranceOptionToggles";
import { modelOptionsFor } from "../lib/presets";

function renderField(field, draft, onChange) {
  if (field.visibleWhen && !field.visibleWhen(draft)) {
    return null;
  }

  if (field.key === "model") {
    return (
      <label key={field.key} className="form-field">
        {field.label}
        <select value={draft.model} onChange={(event) => onChange(field.key, event.target.value)}>
          {modelOptionsFor(draft.provider).map((option) => (
            <option key={option} value={option}>
              {option}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (field.type === "select") {
    return (
      <label key={field.key} className="form-field">
        {field.label}
        <select value={draft[field.key] ?? ""} onChange={(event) => onChange(field.key, event.target.value)}>
          {field.options.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
    );
  }

  if (field.type === "textarea") {
    return (
      <label key={field.key} className="form-field form-field-wide stacked-field">
        {field.label}
        <textarea
          rows={field.rows ?? 4}
          value={draft[field.key] ?? ""}
          placeholder={field.placeholder}
          onChange={(event) => onChange(field.key, event.target.value)}
        />
      </label>
    );
  }

  return (
    <label key={field.key} className="form-field">
      {field.label}
      <input
        type={field.type === "password" ? "password" : "text"}
        value={draft[field.key] ?? ""}
        placeholder={field.placeholder}
        onChange={(event) => onChange(field.key, event.target.value)}
        autoComplete={field.type === "password" ? "off" : undefined}
      />
    </label>
  );
}

const FIELD_GROUPS = [
  {
    key: "connection",
    title: "Connection",
    description: "Choose where this example writes records and which credentials it uses.",
    matches: (fieldKey) => fieldKey === "serviceUrl" || fieldKey === "apiKey"
  },
  {
    key: "capture",
    title: "App inputs",
    description: "Control provider path, model, run mode, and the user message for this chat session.",
    matches: (fieldKey) =>
      fieldKey === "provider" ||
      fieldKey === "model" ||
      fieldKey === "mode" ||
      fieldKey === "providerApiKey" ||
      fieldKey === "userPrompt"
  },
  {
    key: "profile",
    title: "Workflow context",
    description: "Reuse the core assistant context across this chat scenario.",
    matches: (fieldKey) =>
      fieldKey === "systemId" || fieldKey === "intendedUse" || fieldKey === "owner"
  },
  {
    key: "evidence",
    title: "Extra records",
    description: "Any additional scenario-specific fields for this conversation flow.",
    matches: () => true
  }
];

export function ScenarioParameterForm({
  scenario,
  draft,
  liveAvailable,
  errors,
  isRunning,
  hasInteraction,
  onChange,
  onRun
}) {
  const assignedKeys = new Set();
  const groupedFields = FIELD_GROUPS.map((group) => {
    const fields = scenario.fields.filter((field) => {
      if (assignedKeys.has(field.key)) {
        return false;
      }
      if (!group.matches(field.key)) {
        return false;
      }
      assignedKeys.add(field.key);
      return true;
    });
    return { ...group, fields };
  }).filter((group) => group.fields.length > 0);

  return (
    <section className="panel scenario-form-panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Parameters</span>
          <h3>{scenario.label}</h3>
        </div>
      </div>

      <p className="section-intro">{scenario.description}</p>
      <p className="field-hint scenario-audience-note">
        {scenario.audienceSummary}
      </p>

      <div className="parameter-sections">
        {groupedFields.map((group) => (
          <section key={group.key} className="parameter-section">
            <div className="parameter-section-head">
              <strong>{group.title}</strong>
              <span>{group.description}</span>
            </div>
            <div className="form-grid scenario-form-grid">
              {group.fields.map((field) => renderField(field, draft, onChange))}
            </div>
          </section>
        ))}
      </div>

      <p className="field-hint">
        {!hasInteraction
          ? "This scenario captures a conversation proof without additional governance records."
          : draft.mode === "live"
          ? liveAvailable || draft.providerApiKey?.trim()
            ? "Live provider access is available for this chat scenario."
            : "Add a temporary provider key if the connected vault does not already have live access."
          : "Synthetic mode still runs through the vault flow so you can inspect transcript hash and session signature output."}
      </p>

      <div className="scenario-form-footer">
        <AssuranceOptionToggles
          attachTimestamp={draft.attachTimestamp}
          attachTransparency={draft.attachTransparency}
          onChange={onChange}
        />

        <div className="button-row">
          <button type="button" className="primary-cta" onClick={onRun} disabled={isRunning}>
            {isRunning ? "Running conversation..." : "Run conversation"}
          </button>
        </div>
      </div>

      {errors.workflow ? <p className="inline-error">{errors.workflow}</p> : null}
      {errors.connection ? <p className="inline-error">{errors.connection}</p> : null}
    </section>
  );
}
