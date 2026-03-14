import React from "react";
import { useNavigate } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import {
  PRESETS,
  defaultTemplateName,
  isProviderLiveEnabled,
  modelOptionsFor
} from "../lib/presets";

export function AdvancedPlaygroundPage() {
  const navigate = useNavigate();
  const {
    draft,
    templateCatalog,
    vaultConfig,
    errors,
    isRefreshing,
    isRunning,
    currentPreset,
    actions
  } = useDemo();
  const selectedTemplate =
    templateCatalog?.templates?.find((template) => template.profile === draft.templateProfile) ?? null;
  const templateGroups = templateCatalog?.redaction_groups ?? [];
  const liveEnabled = isProviderLiveEnabled(vaultConfig, draft.provider);
  const usingTemporaryKey = Boolean(draft.providerApiKey?.trim());

  async function handleRun() {
    const bundleId = await actions.runWorkflow();
    navigate(`/what-happened/${bundleId}`);
  }

  return (
    <section className="page-stack">
      <section className="panel">
        <div className="panel-head">
          <div>
            <span className="section-label">Advanced Playground</span>
            <h2>Configure the full proof workflow</h2>
          </div>
          <button
            type="button"
            className="ghost-btn"
            onClick={actions.refreshVaultCapabilities}
            disabled={isRefreshing}
          >
            {isRefreshing ? "Refreshing..." : "Refresh vault"}
          </button>
        </div>

        <p className="section-intro">
          Use this view when you want the full set of controls for capture, proof, disclosure,
          and export rather than the simplified guided experience.
        </p>

        <div className="preset-grid">
          {PRESETS.map((preset) => (
            <button
              key={preset.key}
              type="button"
              className={`preset-card ${draft.presetKey === preset.key ? "is-active" : ""}`}
              onClick={() => actions.selectPreset(preset.key)}
            >
              <strong>{preset.label}</strong>
              <span>{preset.description}</span>
            </button>
          ))}
        </div>

        <div className="form-grid">
          <label>
            Vault URL
            <input
              value={draft.serviceUrl}
              onChange={(event) => actions.updateDraft("serviceUrl", event.target.value)}
            />
          </label>
          <label>
            Vault API key (auth only)
            <input
              value={draft.apiKey}
              onChange={(event) => actions.updateDraft("apiKey", event.target.value)}
              placeholder="Optional bearer token"
            />
          </label>
          <label>
            Capture mode
            <select
              value={draft.mode}
              onChange={(event) => actions.updateDraft("mode", event.target.value)}
            >
              <option value="synthetic">Synthetic demo</option>
              <option value="live">
                Live provider
              </option>
            </select>
          </label>
          <label>
            Provider
            <select
              value={draft.provider}
              onChange={(event) => actions.updateDraft("provider", event.target.value)}
            >
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
            </select>
          </label>
          <label>
            Model
            <select
              value={draft.model}
              onChange={(event) => actions.updateDraft("model", event.target.value)}
            >
              {modelOptionsFor(draft.provider).map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <label>
            Actor role
            <select
              value={draft.actorRole}
              onChange={(event) => actions.updateDraft("actorRole", event.target.value)}
            >
              <option value="provider">Provider</option>
              <option value="deployer">Deployer</option>
              <option value="integrator">Integrator</option>
            </select>
          </label>
          <label>
            System ID
            <input
              value={draft.systemId}
              onChange={(event) => actions.updateDraft("systemId", event.target.value)}
            />
          </label>
          <label>
            Bundle format
            <select
              value={draft.bundleFormat}
              onChange={(event) => actions.updateDraft("bundleFormat", event.target.value)}
            >
              <option value="disclosure">disclosure</option>
              <option value="full">full</option>
            </select>
          </label>
          <label>
            Temperature
            <input
              value={draft.temperature}
              onChange={(event) => actions.updateDraft("temperature", event.target.value)}
            />
          </label>
          <label>
            Max tokens
            <input
              value={draft.maxTokens}
              onChange={(event) => actions.updateDraft("maxTokens", event.target.value)}
            />
          </label>
          <label>
            Disclosure profile
            <select
              value={draft.templateProfile}
              onChange={(event) => {
                const profile = event.target.value;
                const template =
                  templateCatalog?.templates?.find((item) => item.profile === profile) ?? null;
                actions.updateDraft("templateProfile", profile);
                actions.updateDraft("templateName", defaultTemplateName(profile));
                actions.updateDraft(
                  "selectedGroups",
                  template?.default_redaction_groups ?? []
                );
              }}
            >
              {(templateCatalog?.templates ?? []).map((item) => (
                <option key={item.profile} value={item.profile}>
                  {item.profile}
                </option>
              ))}
            </select>
          </label>
          <label>
            Template name
            <input
              value={draft.templateName}
              onChange={(event) => actions.updateDraft("templateName", event.target.value)}
            />
          </label>
        </div>

        <p className="field-hint">
          Vault API key is only needed when the connected vault requires bearer authentication.
        </p>

        {draft.mode === "live" ? (
          <label className="stacked-field">
            Temporary provider API key
            <input
              type="password"
              value={draft.providerApiKey}
              onChange={(event) => actions.updateDraft("providerApiKey", event.target.value)}
              placeholder={
                liveEnabled
                  ? "Optional override when provider access is already configured"
                  : "Required for live runs when provider access is not already available"
              }
              autoComplete="off"
              spellCheck="false"
            />
          </label>
        ) : null}

        <label className="stacked-field">
          System prompt
          <textarea
            rows={4}
            value={draft.systemPrompt}
            onChange={(event) => actions.updateDraft("systemPrompt", event.target.value)}
          />
        </label>

        <label className="stacked-field">
          User prompt
          <textarea
            rows={5}
            value={draft.userPrompt}
            onChange={(event) => actions.updateDraft("userPrompt", event.target.value)}
          />
        </label>

        <p className="field-hint">
          {draft.mode === "live"
            ? liveEnabled && !usingTemporaryKey
              ? "Live provider access is already available for this connected vault."
              : "You can add a provider key here for a live run without changing the vault's stored configuration."
            : "Synthetic sample mode still runs through the real proof workflow for sealing, verification, disclosure, and export."}
        </p>

        <div className="toggle-row">
          <button
            type="button"
            className={`toggle-pill ${draft.attachTimestamp ? "is-active" : ""}`}
            onClick={() => actions.updateDraft("attachTimestamp", !draft.attachTimestamp)}
          >
            Timestamp
          </button>
          <button
            type="button"
            className={`toggle-pill ${draft.attachTransparency ? "is-active" : ""}`}
            onClick={() => actions.updateDraft("attachTransparency", !draft.attachTransparency)}
          >
            Transparency
          </button>
        </div>

        <div className="panel-subsection">
          <div className="panel-head compact">
            <div>
              <span className="section-label">Disclosure Template</span>
              <h3>{selectedTemplate?.description ?? currentPreset.description}</h3>
            </div>
          </div>
          <div className="group-picker">
            {templateGroups.map((group) => {
              const active = draft.selectedGroups.includes(group.name);
              return (
                <button
                  key={group.name}
                  type="button"
                  className={`group-chip ${active ? "is-active" : ""}`}
                  onClick={() =>
                    actions.updateDraft(
                      "selectedGroups",
                      active
                        ? draft.selectedGroups.filter((value) => value !== group.name)
                        : [...draft.selectedGroups, group.name]
                    )
                  }
                >
                  <strong>{group.name}</strong>
                  <span>{group.description}</span>
                </button>
              );
            })}
          </div>
        </div>

        <div className="button-row">
          <button type="button" onClick={handleRun} disabled={isRunning}>
            {isRunning ? "Running workflow..." : "Run proof workflow"}
          </button>
        </div>

        {errors.connection ? <p className="inline-error">{errors.connection}</p> : null}
        {errors.workflow ? <p className="inline-error">{errors.workflow}</p> : null}
      </section>
    </section>
  );
}
