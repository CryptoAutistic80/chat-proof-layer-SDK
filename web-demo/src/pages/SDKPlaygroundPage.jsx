import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { BundleRunList } from "../components/BundleRunList";
import { ComplianceReviewPanel } from "../components/ComplianceReviewPanel";
import { DataPanel } from "../components/DataPanel";
import { PrimaryResultSummary } from "../components/PrimaryResultSummary";
import { ScenarioParameterForm } from "../components/ScenarioParameterForm";
import { ScriptPanel } from "../components/ScriptPanel";
import { SdkLaneTabs } from "../components/SdkLaneTabs";
import { SdkScenarioCard } from "../components/SdkScenarioCard";
import { buildRunNarrativeSummary } from "../lib/narrative";
import {
  PLAYGROUND_LANES,
  listScenariosForLane
} from "../lib/sdkPlaygroundScenarios";
import { renderScenarioScript } from "../lib/sdkScriptTemplates";
import { isProviderLiveEnabled } from "../lib/presets";

export function SDKPlaygroundPage() {
  const [activeTab, setActiveTab] = useState("result");
  const {
    draft,
    currentScenario,
    currentRun,
    vaultConfig,
    errors,
    isRunning,
    actions
  } = useDemo();
  const scenarios = useMemo(
    () => listScenariosForLane(draft.lane),
    [draft.lane]
  );
  const liveAvailable = isProviderLiveEnabled(vaultConfig, draft.provider);
  const scriptSource = renderScenarioScript(currentScenario, draft);
  const scenarioRun = currentRun?.scenarioId === currentScenario.id ? currentRun : null;
  const summary = scenarioRun ? buildRunNarrativeSummary(scenarioRun, vaultConfig) : null;

  useEffect(() => {
    actions.ensurePlaygroundDraft();
  }, []);

  useEffect(() => {
    if (scenarioRun?.bundleId) {
      setActiveTab("result");
    }
  }, [scenarioRun?.bundleId]);

  return (
    <section className="page-stack">
      <section className="panel sdk-playground-hero">
        <div className="panel-head">
          <div>
            <span className="section-label">SDK Playground</span>
            <h1>Try the real SDK and CLI flows without leaving the demo</h1>
          </div>
          <Link to="/playground/advanced" className="ghost-btn">
            Open advanced controls
          </Link>
        </div>
        <p className="section-intro">
          Pick a prefab TypeScript, Python, or CLI scenario, change a few inputs, then run the
          real vault-backed workflow and inspect the evidence story on the same page.
        </p>
      </section>

      <SdkLaneTabs lanes={PLAYGROUND_LANES} activeLane={draft.lane} onSelect={actions.selectLane} />

      <div className="scenario-grid sdk-scenario-grid">
        {scenarios.map((scenario) => (
          <SdkScenarioCard
            key={scenario.id}
            scenario={scenario}
            active={scenario.id === currentScenario.id}
            onSelect={actions.selectScenario}
          />
        ))}
      </div>

      <div className="sdk-playground-grid">
        <ScenarioParameterForm
          scenario={currentScenario}
          draft={draft}
          liveAvailable={liveAvailable}
          errors={errors}
          isRunning={isRunning}
          hasInteraction={currentScenario.steps.some((step) => step.kind === "interaction")}
          onChange={actions.updateDraft}
          onRun={actions.runScenarioWorkflow}
        />
        <ScriptPanel scenario={currentScenario} scriptSource={scriptSource} />
      </div>

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">After run</span>
            <h2>Inspect the outcome without leaving the playground</h2>
          </div>
        </div>
        <div className="playground-tab-row" role="tablist" aria-label="Playground result tabs">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "result"}
            className={`toggle-pill ${activeTab === "result" ? "is-active" : ""}`}
            onClick={() => setActiveTab("result")}
          >
            Result
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "review"}
            className={`toggle-pill ${activeTab === "review" ? "is-active" : ""}`}
            onClick={() => setActiveTab("review")}
            disabled={!scenarioRun}
          >
            Compliance Review
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "deeper"}
            className={`toggle-pill ${activeTab === "deeper" ? "is-active" : ""}`}
            onClick={() => setActiveTab("deeper")}
            disabled={!scenarioRun}
          >
            Open deeper views
          </button>
        </div>
      </section>

      {!scenarioRun ? (
        <section className="panel empty-state">
          <span className="section-label">Awaiting run</span>
          <h2>No scenario results yet</h2>
          <p>Run the selected example to reveal bundle details, export status, and the evidence map.</p>
        </section>
      ) : null}

      {scenarioRun && activeTab === "result" ? (
        <>
          <PrimaryResultSummary summary={summary} run={scenarioRun} />
          <BundleRunList bundleRuns={scenarioRun.bundleRuns} />
          <section className="snapshot-grid">
            <DataPanel
              title="Pack manifest"
              subtitle={scenarioRun.packType}
              value={scenarioRun.packManifest ?? null}
              placeholder="Pack manifest appears here after export."
            />
            <DataPanel
              title="System rollup"
              subtitle={scenarioRun.systemSummary?.system_id ?? "System summary"}
              value={scenarioRun.systemSummary ?? null}
              placeholder="System summary appears here after the run."
            />
          </section>
        </>
      ) : null}

      {scenarioRun && activeTab === "review" ? (
        <ComplianceReviewPanel review={scenarioRun.review} />
      ) : null}

      {scenarioRun && activeTab === "deeper" ? (
        <section className="panel">
          <div className="panel-head compact">
            <div>
              <span className="section-label">Deeper views</span>
              <h2>Open the detailed walkthrough pages</h2>
            </div>
          </div>
          <div className="deeper-links-grid">
            <Link className="deeper-link-card" to={`/what-happened/${scenarioRun.primaryBundleId}`}>
              <strong>What Happened</strong>
              <span>Inspect the primary bundle and captured materials.</span>
            </Link>
            <Link className="deeper-link-card" to={`/what-you-can-prove/${scenarioRun.primaryBundleId}`}>
              <strong>What You Can Prove</strong>
              <span>Check verification, disclosure preview, and trust status.</span>
            </Link>
            <Link className="deeper-link-card" to={`/what-you-can-share/${scenarioRun.primaryBundleId}`}>
              <strong>What You Can Share</strong>
              <span>Open the export and pack view for the same run.</span>
            </Link>
          </div>
        </section>
      ) : null}
    </section>
  );
}
