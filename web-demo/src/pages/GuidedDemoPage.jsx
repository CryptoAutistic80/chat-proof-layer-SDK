import React, { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { ScenarioCard } from "../components/ScenarioCard";
import { PRESETS, isProviderLiveEnabled, modelOptionsFor } from "../lib/presets";
import { humanCaptureMode } from "../lib/narrative";

export function GuidedDemoPage() {
  const navigate = useNavigate();
  const {
    draft,
    currentPreset,
    vaultConfig,
    errors,
    isRunning,
    actions
  } = useDemo();
  const [showAdvanced, setShowAdvanced] = useState(false);

  const liveAvailable = isProviderLiveEnabled(vaultConfig, draft.provider);
  const scenarioModeLabel = useMemo(() => {
    if (draft.mode === "live") {
      return liveAvailable || draft.providerApiKey.trim()
        ? "Live-ready"
        : "Live with provider key";
    }
    return "Synthetic sample";
  }, [draft.mode, draft.providerApiKey, liveAvailable]);

  async function handleRun() {
    const bundleId = await actions.runWorkflow();
    navigate(`/what-happened/${bundleId}`);
  }

  return (
    <section className="page-stack">
      <section className="panel guided-hero">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Guided demo</span>
            <h1>Start with the business story, not the technical settings</h1>
          </div>
        </div>
        <p className="section-intro">
          Pick a scenario, run it, then this site will walk you through what happened, what can
          be proven, and what can be shared.
        </p>
      </section>

      <div className="scenario-grid">
        {PRESETS.map((preset) => (
          <ScenarioCard
            key={preset.key}
            preset={preset}
            active={draft.presetKey === preset.key}
            onSelect={actions.selectPreset}
            modeLabel={preset.defaultMode === "synthetic" ? "Synthetic first" : "Live if available"}
          />
        ))}
      </div>

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Scenario setup</span>
            <h2>{currentPreset.label}</h2>
          </div>
          <span className="mode-badge">{humanCaptureMode(draft.mode === "live" ? "live_provider_capture" : "synthetic_demo_capture")}</span>
        </div>

        <p className="field-hint leading-hint">{currentPreset.outcomeLabel}</p>

        <div className="guided-grid">
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
            Capture mode
            <select
              value={draft.mode}
              onChange={(event) => actions.updateDraft("mode", event.target.value)}
            >
              <option value="synthetic">Synthetic sample</option>
              <option value="live">Live provider</option>
            </select>
          </label>

          <div className="guided-note">
            <strong>{scenarioModeLabel}</strong>
            <span>
              {draft.mode === "live"
                ? liveAvailable
                  ? "This site can run directly against the selected provider."
                  : "Add a provider key below if you want this scenario to run against a live model."
                : "Synthetic mode is useful when you want to show the workflow without making a live model call."}
            </span>
          </div>
        </div>

        {draft.mode === "live" ? (
          <label className="stacked-field">
            Temporary provider API key
            <input
              type="password"
              value={draft.providerApiKey}
              onChange={(event) => actions.updateDraft("providerApiKey", event.target.value)}
              placeholder="Only needed when live provider access is not already available"
              autoComplete="off"
            />
          </label>
        ) : null}

        <label className="stacked-field">
          Prompt
          <textarea
            rows={6}
            value={draft.userPrompt}
            onChange={(event) => actions.updateDraft("userPrompt", event.target.value)}
          />
        </label>

        <div className="button-row">
          <button type="button" className="primary-cta" onClick={handleRun} disabled={isRunning}>
            {isRunning ? "Running scenario..." : "Run this scenario"}
          </button>
          <button type="button" className="secondary-cta" onClick={() => setShowAdvanced((value) => !value)}>
            {showAdvanced ? "Hide advanced options" : "Show advanced options"}
          </button>
          <button type="button" className="ghost-btn" onClick={() => navigate("/playground")}>
            Open SDK playground
          </button>
        </div>

        {showAdvanced ? (
          <section className="advanced-box">
            <div className="panel-head compact">
              <div>
                <span className="section-label">Advanced</span>
                <h3>Additional controls</h3>
              </div>
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
                System ID
                <input
                  value={draft.systemId}
                  onChange={(event) => actions.updateDraft("systemId", event.target.value)}
                />
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
                Disclosure profile
                <input
                  value={draft.templateProfile}
                  onChange={(event) => actions.updateDraft("templateProfile", event.target.value)}
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
            </div>
          </section>
        ) : null}

        {errors.workflow ? <p className="error-copy">{errors.workflow}</p> : null}
      </section>
    </section>
  );
}
