import React from "react";
import { modelOptionsFor } from "../lib/presets";

function renderField(field, draft, onChange) {
  if (field.visibleWhen && !field.visibleWhen(draft)) {
    return null;
  }

  if (field.key === "model") {
    return (
      <label key={field.key}>
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
      <label key={field.key}>
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
      <label key={field.key} className="stacked-field">
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
    <label key={field.key}>
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
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Parameters</span>
          <h3>{scenario.label}</h3>
        </div>
      </div>

      <p className="section-intro">{scenario.description}</p>

      <div className="form-grid">
        {scenario.fields.map((field) => renderField(field, draft, onChange))}
      </div>

      <p className="field-hint">
        {!hasInteraction
          ? "This scenario is governance-only: the playground creates multiple evidence bundles without making a model call."
          : draft.mode === "live"
          ? liveAvailable || draft.providerApiKey?.trim()
            ? "Live provider access is available for this example."
            : "Add a temporary provider key if the connected vault does not already have live access."
          : "Synthetic mode still runs through the real vault workflow for create, verify, preview, and export."}
      </p>

      <div className="toggle-row">
        <button
          type="button"
          className={`toggle-pill ${draft.attachTimestamp ? "is-active" : ""}`}
          onClick={() => onChange("attachTimestamp", !draft.attachTimestamp)}
        >
          Timestamp
        </button>
        <button
          type="button"
          className={`toggle-pill ${draft.attachTransparency ? "is-active" : ""}`}
          onClick={() => onChange("attachTransparency", !draft.attachTransparency)}
        >
          Transparency
        </button>
      </div>

      <div className="button-row">
        <button type="button" className="primary-cta" onClick={onRun} disabled={isRunning}>
          {isRunning ? "Running workflow..." : "Run prefab example"}
        </button>
      </div>

      {errors.workflow ? <p className="inline-error">{errors.workflow}</p> : null}
      {errors.connection ? <p className="inline-error">{errors.connection}</p> : null}
    </section>
  );
}
