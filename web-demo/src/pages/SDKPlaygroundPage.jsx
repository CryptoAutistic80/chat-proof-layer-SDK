import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { ActivityFeed } from "../components/ActivityFeed";
import { BundleRunList } from "../components/BundleRunList";
import { ComplianceReviewPanel } from "../components/ComplianceReviewPanel";
import { DataPanel } from "../components/DataPanel";
import { PrimaryResultSummary } from "../components/PrimaryResultSummary";
import { RunSummaryCard } from "../components/RunSummaryCard";
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
    currentPreset,
    vaultConfig,
    activityLog,
    errors,
    isRunning,
    actions
  } = useDemo();
  const selectedLane = useMemo(
    () => PLAYGROUND_LANES.find((lane) => lane.id === draft.lane) ?? PLAYGROUND_LANES[0],
    [draft.lane]
  );
  const scenarios = useMemo(
    () => listScenariosForLane(draft.lane),
    [draft.lane]
  );
  const laneCounts = useMemo(
    () =>
      Object.fromEntries(
        PLAYGROUND_LANES.map((lane) => [lane.id, listScenariosForLane(lane.id).length])
      ),
    []
  );
  const totalScenarioCount = useMemo(
    () => PLAYGROUND_LANES.reduce((count, lane) => count + (laneCounts[lane.id] ?? 0), 0),
    [laneCounts]
  );
  const liveAvailable = isProviderLiveEnabled(vaultConfig, draft.provider);
  const scriptSource = renderScenarioScript(currentScenario, draft);
  const scenarioRun = currentRun?.scenarioId === currentScenario.id ? currentRun : null;
  const summary = scenarioRun ? buildRunNarrativeSummary(scenarioRun, vaultConfig) : null;
  const evidenceShape = currentScenario.steps.map((step) => step.itemType);

  useEffect(() => {
    actions.ensurePlaygroundDraft();
  }, []);

  useEffect(() => {
    if (scenarioRun?.primaryBundleId) {
      setActiveTab("result");
    }
  }, [scenarioRun?.primaryBundleId]);

  return (
    <section className="page-stack sdk-playground-page">
      <section className="panel sdk-playground-hero">
        <div className="sdk-playground-hero-grid">
          <div className="sdk-playground-hero-copy">
            <span className="section-label">SDK Playground</span>
            <h1>Try the real SDK and CLI flows without leaving the demo</h1>
            <p className="sdk-playground-lead">
              Use the page like a controlled lab: choose a real TypeScript, Python, or CLI
              workflow, tune a bounded set of inputs, inspect the emitted example source, then
              review the resulting evidence as if you were preparing for compliance review.
            </p>
            <div className="sdk-hero-metrics">
              <div className="sdk-hero-metric">
                <strong>{PLAYGROUND_LANES.length}</strong>
                <span>language lanes</span>
              </div>
              <div className="sdk-hero-metric">
                <strong>{totalScenarioCount}</strong>
                <span>prefab workflows</span>
              </div>
              <div className="sdk-hero-metric">
                <strong>{currentScenario.steps.length}</strong>
                <span>bundles in this flow</span>
              </div>
            </div>
          </div>

          <aside className="sdk-playground-hero-rail">
            <article className="sdk-selected-card">
              <div className="sdk-selected-head">
                <span className="section-label">Selected prefab</span>
                <span className="sdk-chip">{selectedLane.label}</span>
              </div>
              <h2>{currentScenario.label}</h2>
              <p>{currentScenario.description}</p>
              <div className="sdk-chip-row">
                <span className="sdk-chip is-accent">{currentScenario.packType}</span>
                <span className="sdk-chip">{currentScenario.actorRole}</span>
                <span className="sdk-chip">{currentScenario.codeLanguage}</span>
              </div>
              <div className="sdk-evidence-stack">
                <span className="sdk-evidence-label">This run creates</span>
                <div className="sdk-evidence-list">
                  {evidenceShape.map((itemType) => (
                    <span key={itemType} className="sdk-evidence-pill">
                      {itemType}
                    </span>
                  ))}
                </div>
              </div>
            </article>

            <div className="sdk-hero-actions">
              <Link to="/docs/playground" className="secondary-cta">
                Playground docs
              </Link>
              <Link to="/playground/advanced" className="ghost-btn">
                Open advanced controls
              </Link>
            </div>
          </aside>
        </div>
      </section>

      <section className="panel sdk-selector-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Scenario selector</span>
            <h2>Pick the lane, then the exact workflow</h2>
          </div>
          <p className="selector-note">
            {selectedLane.description} Switch lanes without losing the connected vault settings.
          </p>
        </div>
        <SdkLaneTabs
          lanes={PLAYGROUND_LANES}
          activeLane={draft.lane}
          laneCounts={laneCounts}
          onSelect={actions.selectLane}
        />

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
      </section>

      <div className="sdk-overview-grid">
        <RunSummaryCard run={currentRun} preset={currentPreset} scenario={currentScenario} />
        <ActivityFeed activityLog={activityLog} />
      </div>

      <section className="sdk-workbench-shell">
        <div className="sdk-workbench-head">
          <div>
            <span className="section-label">Workbench</span>
            <h2>Tune the prefab inputs and inspect the generated source</h2>
          </div>
          <p className="section-intro">
            The left side controls the bounded input surface. The right side shows the maintained
            example template that corresponds to this workflow.
          </p>
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
      </section>

      <section className="panel sdk-results-panel">
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
          <p>
            Run the selected example to reveal bundle details, pack output, and the plain-English
            evidence review for the chosen workflow.
          </p>
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
