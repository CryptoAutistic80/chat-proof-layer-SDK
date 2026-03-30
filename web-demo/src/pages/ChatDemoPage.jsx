import React, { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { modelOptionsFor } from "../lib/presets";

function statusLabel(value, missingLabel = "Not configured") {
  if (value === null || value === undefined) {
    return missingLabel;
  }
  if (typeof value === "object" && Object.prototype.hasOwnProperty.call(value, "valid")) {
    return value.valid ? "Verified" : "Warning";
  }
  return String(value);
}

export function ChatDemoPage() {
  const [advancedMode, setAdvancedMode] = useState(false);
  const {
    draft,
    currentRun,
    errors,
    isRunning,
    actions
  } = useDemo();

  const proofSummary = useMemo(() => {
    if (!currentRun?.bundleId) {
      return null;
    }
    return {
      bundleId: currentRun.bundleId,
      rootHash: currentRun.createMeta?.bundle_root ?? currentRun.bundle?.integrity?.bundle_root,
      signatureStatus: statusLabel(currentRun.verifyResponse, "Unknown"),
      timestampStatus: statusLabel(currentRun.timestampVerification)
    };
  }, [currentRun]);

  return (
    <section className="page-stack">
      <section className="panel studio-hero">
        <div className="studio-hero-copy">
          <span className="section-label">Chat proof demo</span>
          <h1>Run a chat, seal it, and get proof metadata instantly</h1>
          <p className="studio-lead">
            This flow keeps defaults focused on a single conversation. Enter a prompt, run the
            conversation, and seal it to produce a proof bundle you can verify or share later.
          </p>
        </div>
        <aside className="studio-hero-side">
          <span className="section-label">Need more controls?</span>
          <p>Advanced and legacy playground controls are still available.</p>
          <Link className="text-link" to="/advanced">
            Open advanced/legacy playground
          </Link>
        </aside>
      </section>

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Step 1</span>
            <h2>Chat input and output</h2>
          </div>
        </div>

        <div className="form-grid">
          <label>
            Provider
            <select value={draft.provider} onChange={(event) => actions.updateDraft("provider", event.target.value)}>
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
            </select>
          </label>
          <label>
            Model
            <select value={draft.model} onChange={(event) => actions.updateDraft("model", event.target.value)}>
              {modelOptionsFor(draft.provider).map((option) => (
                <option key={option} value={option}>
                  {option}
                </option>
              ))}
            </select>
          </label>
          <label>
            Session / thread ID
            <input value={draft.systemId} onChange={(event) => actions.updateDraft("systemId", event.target.value)} />
          </label>
        </div>

        <button
          type="button"
          className="ghost-btn"
          onClick={() => setAdvancedMode((value) => !value)}
          style={{ marginTop: 12 }}
        >
          {advancedMode ? "Hide advanced controls" : "Show advanced controls"}
        </button>

        {advancedMode ? (
          <div className="form-grid" style={{ marginTop: 16 }}>
            <label>
              Vault URL
              <input value={draft.serviceUrl} onChange={(event) => actions.updateDraft("serviceUrl", event.target.value)} />
            </label>
            <label>
              Vault API key
              <input value={draft.apiKey} onChange={(event) => actions.updateDraft("apiKey", event.target.value)} />
            </label>
            <label>
              Capture mode
              <select value={draft.mode} onChange={(event) => actions.updateDraft("mode", event.target.value)}>
                <option value="synthetic">Synthetic demo</option>
                <option value="live">Live provider</option>
              </select>
            </label>
            <label className="form-field-wide stacked-field" style={{ gridColumn: "1 / -1" }}>
              System prompt
              <textarea
                rows={3}
                value={draft.systemPrompt}
                onChange={(event) => actions.updateDraft("systemPrompt", event.target.value)}
              />
            </label>
          </div>
        ) : null}

        <label className="stacked-field" style={{ marginTop: 14 }}>
          User message
          <textarea rows={5} value={draft.userPrompt} onChange={(event) => actions.updateDraft("userPrompt", event.target.value)} />
        </label>

        <section className="panel" style={{ marginTop: 16 }}>
          <div className="panel-head compact">
            <div>
              <span className="section-label">Model output</span>
              <h3>Latest response</h3>
            </div>
          </div>
          <p>{currentRun?.responseText ?? "Run the chat flow to generate and seal a conversation response."}</p>
        </section>
      </section>

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Step 2</span>
            <h2>Seal conversation</h2>
          </div>
        </div>
        <div className="button-row">
          <button type="button" className="primary-cta" onClick={actions.runWorkflow} disabled={isRunning}>
            {isRunning ? "Sealing conversation..." : "Seal conversation"}
          </button>
          <Link className="secondary-cta" to="/verify">
            Verify proof
          </Link>
          <Link className="secondary-cta" to="/share">
            Open share view
          </Link>
        </div>
        {errors.workflow ? <p className="inline-error">{errors.workflow}</p> : null}
        {errors.connection ? <p className="inline-error">{errors.connection}</p> : null}
      </section>

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Step 3</span>
            <h2>Immediate proof summary</h2>
          </div>
        </div>
        {!proofSummary ? (
          <p>No sealed bundle yet. Seal a conversation to populate this summary.</p>
        ) : (
          <div className="learn-card-grid">
            <article className="learn-card">
              <strong>Bundle ID</strong>
              <p>{proofSummary.bundleId}</p>
            </article>
            <article className="learn-card">
              <strong>Root hash</strong>
              <p>{proofSummary.rootHash ?? "Unavailable"}</p>
            </article>
            <article className="learn-card">
              <strong>Signature status</strong>
              <p>{proofSummary.signatureStatus}</p>
            </article>
            <article className="learn-card">
              <strong>Timestamp status</strong>
              <p>{proofSummary.timestampStatus}</p>
            </article>
          </div>
        )}
      </section>
    </section>
  );
}
