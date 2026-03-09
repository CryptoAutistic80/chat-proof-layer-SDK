import React from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { ActivityFeed } from "./ActivityFeed";
import { RunSummaryCard } from "./RunSummaryCard";

function capabilityValue(config, templates) {
  if (!config) {
    return [];
  }
  return [
    {
      label: "Vault",
      value: config.service.tls_enabled ? "HTTPS ready" : "HTTP demo mode",
      tone: config.service.tls_enabled ? "good" : "warn"
    },
    {
      label: "Auth",
      value: config.auth.enabled
        ? `Bearer · ${config.auth.principal_labels.join(", ")}`
        : "Open in local mode",
      tone: config.auth.enabled ? "accent" : "muted"
    },
    {
      label: "Timestamp",
      value: config.timestamp.enabled
        ? `${config.timestamp.provider} · ${config.timestamp.assurance ?? "standard"}`
        : "Not configured",
      tone: config.timestamp.enabled ? "good" : "warn"
    },
    {
      label: "Transparency",
      value: config.transparency.enabled ? config.transparency.provider : "Not configured",
      tone: config.transparency.enabled ? "good" : "warn"
    },
    {
      label: "Demo mode",
      value: config.demo.providers.openai.live_enabled || config.demo.providers.anthropic.live_enabled
        ? "Live + synthetic"
        : "Synthetic default · temporary key supported",
      tone:
        config.demo.providers.openai.live_enabled || config.demo.providers.anthropic.live_enabled
          ? "good"
          : "accent"
    },
    {
      label: "Disclosure",
      value: templates?.templates?.length
        ? `${templates.templates.length} templates`
        : "Templates unavailable",
      tone: templates?.templates?.length ? "accent" : "warn"
    }
  ];
}

export function AppShell() {
  const { vaultConfig, templateCatalog, currentRun, currentPreset, activityLog } = useDemo();
  const capabilityChips = capabilityValue(vaultConfig, templateCatalog);

  return (
    <div className="app-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <header className="hero">
        <div className="hero-copy">
          <span className="eyebrow">Proof Layer Investor Workflow</span>
          <h1>Run a capture, inspect the proof, then decide what to disclose and export.</h1>
          <p>
            This demo uses the real vault API surface for bundle creation, verification,
            disclosure preview, pack export, and system rollups. The playground can run a live
            provider-backed capture when the vault is configured, accept a temporary provider key
            for demo-only live runs, or fall back to a synthetic demo capture offline.
          </p>
        </div>
        <div className="hero-summary">
          <div>
            <strong>Preset</strong>
            <span>{currentPreset.label}</span>
          </div>
          <div>
            <strong>Current mode</strong>
            <span>{currentRun?.captureMode ?? "Awaiting first run"}</span>
          </div>
          <div>
            <strong>Signer</strong>
            <span>
              {vaultConfig
                ? vaultConfig.signing.ephemeral
                  ? "Ephemeral demo signer"
                  : vaultConfig.signing.key_id
                : "Connect the vault"}
            </span>
          </div>
        </div>
      </header>

      <nav className="top-nav panel">
        <NavLink to="/playground" className={({ isActive }) => `nav-tab ${isActive ? "is-active" : ""}`}>
          Playground
        </NavLink>
        <NavLink to="/results" className={({ isActive }) => `nav-tab ${isActive ? "is-active" : ""}`}>
          Results
        </NavLink>
        <NavLink
          to="/examination"
          className={({ isActive }) => `nav-tab ${isActive ? "is-active" : ""}`}
        >
          Examination
        </NavLink>
        <NavLink to="/exports" className={({ isActive }) => `nav-tab ${isActive ? "is-active" : ""}`}>
          Exports
        </NavLink>
      </nav>

      <section className="capability-strip">
        {capabilityChips.map((chip) => (
          <article key={chip.label} className={`capability-chip is-${chip.tone}`}>
            <span>{chip.label}</span>
            <strong>{chip.value}</strong>
          </article>
        ))}
      </section>

      <main className="route-grid">
        <div className="route-main">
          <Outlet />
        </div>
        <aside className="route-rail">
          <RunSummaryCard run={currentRun} preset={currentPreset} />
          <ActivityFeed activityLog={activityLog} />
        </aside>
      </main>
    </div>
  );
}
