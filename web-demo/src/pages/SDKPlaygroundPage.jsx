import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { ActivityFeed } from "../components/ActivityFeed";
import { BundleRunList } from "../components/BundleRunList";
import { BundleVisualizer } from "../components/BundleVisualizer";
import { ComplianceReviewPanel } from "../components/ComplianceReviewPanel";
import { RecordEvidenceSection } from "../components/RecordEvidenceSection";
import { ScenarioParameterForm } from "../components/ScenarioParameterForm";
import { ScriptPanel } from "../components/ScriptPanel";
import { SdkLaneTabs } from "../components/SdkLaneTabs";
import { SdkScenarioCard } from "../components/SdkScenarioCard";
import { buildRunNarrativeSummary } from "../lib/narrative";
import { buildMerkleTree } from "../lib/clientCrypto";
import { listScenariosForLane } from "../lib/sdkPlaygroundScenarios";
import { renderScenarioScript } from "../lib/sdkScriptTemplates";
import { LEGAL_BOUNDARY } from "../lib/siteContent";
import { isProviderLiveEnabled } from "../lib/presets";

export function SDKPlaygroundPage() {
  const [activeTab, setActiveTab] = useState("recorded");
  const {
    draft,
    currentScenario,
    currentRun,
    vaultConfig,
    activityLog,
    errors,
    isRunning,
    actions
  } = useDemo();

  const scenarios = useMemo(() => listScenariosForLane(), []);
  const liveAvailable = isProviderLiveEnabled(vaultConfig, draft.provider);
  const scriptSource = renderScenarioScript(currentScenario, draft);
  const scenarioRun = currentRun?.scenarioId === currentScenario.id ? currentRun : null;
  const summary = scenarioRun ? buildRunNarrativeSummary(scenarioRun, vaultConfig) : null;
  const evidenceShape = currentScenario.steps.map((step) => step.itemType);

  useEffect(() => {
    actions.ensurePlaygroundDraft();
  }, []);

  const [playgroundTree, setPlaygroundTree] = useState(null);

  useEffect(() => {
    if (scenarioRun?.primaryBundleId) {
      setActiveTab("recorded");
    }
  }, [scenarioRun?.primaryBundleId]);

  useEffect(() => {
    if (!scenarioRun?.bundle) {
      setPlaygroundTree(null);
      return;
    }
    const bundle = scenarioRun.bundle;
    const leaves = [
      ...(bundle.items ?? []).map((i) => i.hash ?? i.commitment),
      ...(bundle.artefacts ?? []).map((a) => a.sha256 ?? a.commitment)
    ].filter(Boolean);
    if (leaves.length > 0) {
      buildMerkleTree(leaves).then(setPlaygroundTree).catch(() => setPlaygroundTree(null));
    }
  }, [scenarioRun?.bundle]);

  return (
    <section className="page-stack sdk-playground-page">
      <section className="panel studio-hero">
        <div className="studio-hero-copy">
          <span className="section-label">Advanced / legacy playground</span>
          <h1>Legacy multi-workflow studio for full configuration</h1>
          <p className="studio-lead">
            Pick a chatbot scenario, tweak a few inputs, and run the real vault-backed flow. The page then shows the conversation proof, transcript hash details, and how to inspect the resulting session record.
          </p>
        </div>
        <aside className="studio-hero-side">
          <span className="section-label">Important boundary</span>
          <p>{LEGAL_BOUNDARY}</p>
          <Link to="/advanced/legacy" className="text-link">
            Need raw vault knobs too? Open the legacy controls page.
          </Link>
        </aside>
      </section>

      {/* Quick start: one-click run with defaults */}
      {!scenarioRun && (
        <section className="panel quick-start-panel">
          <div className="quick-start-content">
            <div>
              <span className="section-label">Quick start</span>
              <h2>Run the default scenario now</h2>
              <p className="section-intro">
                Skip the configuration and run <strong>{currentScenario.label}</strong> with
                default inputs. You can always tweak settings and re-run afterward.
              </p>
            </div>
            <button
              type="button"
              className="primary-cta quick-start-btn"
              onClick={actions.runScenarioWorkflow}
              disabled={isRunning}
            >
              {isRunning ? "Running\u2026" : "Run with defaults"}
            </button>
          </div>
          {errors.workflow && <p className="inline-error">{errors.workflow}</p>}
          {errors.connection && (
            <p className="field-hint">
              Vault connection issue: {errors.connection}. Make sure proof-service is running.
            </p>
          )}
        </section>
      )}

      <section className="panel selector-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Step 1</span>
            <h2>Choose a chatbot scenario</h2>
          </div>
        </div>
        <SdkLaneTabs
          scenarios={scenarios}
          activeScenarioId={currentScenario.id}
          onSelect={actions.selectScenario}
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

      <section className="panel selected-workflow-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Selected workflow</span>
            <h2>{currentScenario.label}</h2>
          </div>
        </div>
        <div className="selected-workflow-grid">
          <div>
            <strong>What kind of app this represents</strong>
            <p>{currentScenario.audienceSummary}</p>
          </div>
          <div>
            <strong>What gets recorded</strong>
            <p>{evidenceShape.join(" + ")}</p>
          </div>
          <div>
            <strong>Why it helps with review</strong>
            <p>{currentScenario.lawExplainer.record}</p>
          </div>
        </div>
      </section>

      <section className="studio-workbench">
        <div className="studio-workbench-head">
          <div>
            <span className="section-label">Step 2</span>
            <h2>Adjust the inputs and inspect the example code</h2>
          </div>
        </div>
        <div className="studio-two-column">
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

      <section className="panel run-create-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Step 3</span>
            <h2>What this run will create</h2>
          </div>
        </div>
        <div className="sdk-evidence-list">
          {evidenceShape.map((itemType) => (
            <span key={itemType} className="sdk-evidence-pill">
              {itemType}
            </span>
          ))}
          <span className="sdk-evidence-pill is-neutral">
            {currentScenario.packType ?? "No export pack by default"}
          </span>
        </div>
      </section>

      <div className="studio-support-grid">
        <ActivityFeed activityLog={activityLog} />
      </div>

      <section className="panel results-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">After run</span>
            <h2>Review the result on this page</h2>
          </div>
        </div>
        <div className="playground-tab-row" role="tablist" aria-label="Playground result tabs">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "recorded"}
            className={`toggle-pill ${activeTab === "recorded" ? "is-active" : ""}`}
            onClick={() => setActiveTab("recorded")}
          >
            What was recorded
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "compliance"}
            className={`toggle-pill ${activeTab === "compliance" ? "is-active" : ""}`}
            onClick={() => setActiveTab("compliance")}
            disabled={!scenarioRun}
          >
            Why this helps with compliance
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "structure"}
            className={`toggle-pill ${activeTab === "structure" ? "is-active" : ""}`}
            onClick={() => setActiveTab("structure")}
            disabled={!scenarioRun}
          >
            Bundle structure
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "explore"}
            className={`toggle-pill ${activeTab === "explore" ? "is-active" : ""}`}
            onClick={() => setActiveTab("explore")}
            disabled={!scenarioRun}
          >
            Open in record explorer
          </button>
        </div>
      </section>

      {!scenarioRun ? (
        <section className="panel empty-state">
          <span className="section-label">Awaiting run</span>
          <h2>No workflow result yet</h2>
          <p>Run the selected example to create a record and see the outcome here.</p>
        </section>
      ) : null}

      {scenarioRun && activeTab === "recorded" ? (
        <>
          <RecordEvidenceSection
            title="What was recorded"
            intro={scenarioRun.recordExplainer?.captured?.body ?? currentScenario.recordExplorerIntro}
            cards={[
              {
                title: "Workflow",
                body: scenarioRun.scenarioLabel
              },
              {
                title: "Primary record",
                body: summary.summary
              },
              {
                title: "Export path",
                body: currentScenario.packType
                  ? `This workflow also prepares ${currentScenario.packType} export material.`
                  : "This workflow focuses on the main record first and does not create an export pack by default."
              }
            ]}
          />
          <BundleRunList bundleRuns={scenarioRun.bundleRuns} />
        </>
      ) : null}

      {scenarioRun && activeTab === "compliance" ? (
        <ComplianceReviewPanel review={scenarioRun.review} />
      ) : null}

      {scenarioRun && activeTab === "structure" ? (
        <section className="panel">
          <div className="panel-head compact">
            <div>
              <span className="section-label">Cryptographic structure</span>
              <h2>How this bundle is assembled</h2>
            </div>
          </div>
          <p className="section-intro" style={{ marginBottom: 18 }}>
            Each evidence item and artefact is hashed. Those leaf hashes are combined
            into a Merkle tree whose root is signed with Ed25519. Click any node to inspect it.
          </p>
          <BundleVisualizer bundle={scenarioRun.bundle} merkleTree={playgroundTree} />
        </section>
      ) : null}

      {scenarioRun && activeTab === "explore" ? (
        <section className="panel">
          <div className="panel-head compact">
            <div>
              <span className="section-label">Record explorer</span>
              <h2>Inspect the full record in one place</h2>
            </div>
          </div>
          <p className="section-intro">
            Move to the record explorer to inspect captured content, proof details, and share
            options without switching between separate walkthrough pages.
          </p>
          <Link className="primary-cta" to={`/records/${scenarioRun.primaryBundleId}?view=captured`}>
            Open record explorer
          </Link>
        </section>
      ) : null}
    </section>
  );
}
