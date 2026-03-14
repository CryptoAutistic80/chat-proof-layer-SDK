import React, { useEffect } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { BundleRunList } from "../components/BundleRunList";
import { ComplianceExplainerCard } from "../components/ComplianceExplainerCard";
import { DataPanel } from "../components/DataPanel";
import { ExportStatusCard } from "../components/ExportStatusCard";
import { RecordEvidenceSection } from "../components/RecordEvidenceSection";
import { RecordExplorerTabs } from "../components/RecordExplorerTabs";
import { RecordSummaryStrip } from "../components/RecordSummaryStrip";
import { StatusExplainCard } from "../components/StatusExplainCard";
import { TechnicalDetailsAccordion } from "../components/TechnicalDetailsAccordion";
import { buildRecordExplainer } from "../lib/complianceReview";
import { buildRunNarrativeSummary } from "../lib/narrative";

const VALID_VIEWS = new Set(["captured", "proof", "share"]);

function summarizeContext(run) {
  return [
    run?.provider ? `Provider ${run.provider}` : null,
    run?.model ? `model ${run.model}` : null,
    run?.actorRole ? `actor role ${run.actorRole}` : null
  ]
    .filter(Boolean)
    .join(", ");
}

function captureCards(run) {
  const supportTypes =
    run?.bundleRuns
      ?.flatMap((bundleRun) => bundleRun.itemTypes)
      .filter((itemType) => itemType !== "llm_interaction") ?? [];

  return [
    {
      title: "Prompt and input",
      body: run?.promptPayload
        ? "The input payload is stored so reviewers can see what the model was responding to."
        : "This example does not have a separate prompt payload attached."
    },
    {
      title: "Output or main record",
      body: run?.responseText ?? "The record shows the main captured output or evidence summary."
    },
    {
      title: "System context",
      body:
        summarizeContext(run) ||
        "Provider, model, system, and actor-role context are stored with the record when available."
    },
    {
      title: "Supporting records",
      body:
        supportTypes.length > 0
          ? `This run also stores supporting evidence: ${supportTypes.join(", ")}.`
          : "This example focuses on the main interaction record without extra governance bundles."
    }
  ];
}

function proofCards(summary, run) {
  return [
    {
      title: "Integrity",
      body: summary.integrityStatus.summary
    },
    {
      title: "Timestamp",
      body: summary.timestampStatus.summary
    },
    {
      title: "Transparency",
      body: summary.transparencyStatus.summary
    },
    {
      title: "Disclosure preview",
      body:
        run?.disclosurePreview
          ? "A preview shows what a reviewer would receive under the current sharing settings."
          : "No disclosure preview is attached for this run yet."
    }
  ];
}

function shareCards(run) {
  return [
    {
      title: "Export path",
      body: run?.packType
        ? `This run can produce a ${run.packType} package.`
        : "This example does not build an export package by default."
    },
    {
      title: "Current package state",
      body: run?.downloadInfo
        ? `A package is ready to download as ${run.downloadInfo.fileName}.`
        : run?.packSummary
          ? "A package was created, but no browser download is attached."
          : "No package has been exported from this run yet."
    },
    {
      title: "Who this is for",
      body: run?.recordExplainer?.share?.body ?? "Use this view to understand who would receive the exported evidence."
    }
  ];
}

export function RecordsExplorerPage() {
  const { bundleId } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const {
    currentRun,
    recentRuns,
    vaultConfig,
    isExporting,
    actions
  } = useDemo();
  const activeBundleId = bundleId || currentRun?.bundleId || recentRuns[0]?.bundle_id;
  const viewParam = searchParams.get("view");
  const activeView = VALID_VIEWS.has(viewParam) ? viewParam : "captured";

  useEffect(() => {
    if (activeBundleId) {
      void actions.ensureRunLoaded(activeBundleId);
    }
  }, [activeBundleId]);

  if (!activeBundleId && !currentRun) {
    return (
      <section className="panel empty-state">
        <span className="section-label">Explore records</span>
        <h2>No records yet</h2>
        <p>
          Run one playground example first, then come back here to inspect what was stored, what
          can be checked, and what could be shared.
        </p>
        <Link className="primary-cta" to="/playground">
          Open playground
        </Link>
      </section>
    );
  }

  const run = currentRun;
  const summary = buildRunNarrativeSummary(run, vaultConfig);
  const explainer = run?.recordExplainer ?? buildRecordExplainer(null, run);
  const runOptions = [];
  const seen = new Set();
  if (run?.bundleId) {
    runOptions.push({
      bundleId: run.bundleId,
      label: `${run.scenarioLabel ?? "Current run"} · ${run.bundleId}`
    });
    seen.add(run.bundleId);
  }
  for (const item of recentRuns) {
    if (!seen.has(item.bundle_id)) {
      runOptions.push({
        bundleId: item.bundle_id,
        label: item.bundle_id
      });
      seen.add(item.bundle_id);
    }
  }

  function handleViewChange(nextView) {
    const nextParams = new URLSearchParams(searchParams);
    nextParams.set("view", nextView);
    setSearchParams(nextParams);
  }

  function handleRunSelect(nextBundleId) {
    navigate(`/records/${nextBundleId}?view=${activeView}`);
  }

  return (
    <section className="page-stack records-page">
      <RecordSummaryStrip
        run={run}
        summary={summary}
        runOptions={runOptions}
        onSelectRun={handleRunSelect}
      />

      <section className="panel records-tabs-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Explorer</span>
            <h2>{explainer.intro}</h2>
          </div>
        </div>
        <RecordExplorerTabs activeView={activeView} onChange={handleViewChange} />
      </section>

      {activeView === "captured" ? (
        <>
          <RecordEvidenceSection
            title={explainer.captured.title}
            intro={explainer.captured.body}
            cards={captureCards(run)}
          />
          <BundleRunList bundleRuns={run?.bundleRuns ?? []} />
          <ComplianceExplainerCard explainer={explainer.captured.lawExplainer} />
          <section className="panel">
            <div className="panel-head compact">
              <div>
                <span className="section-label">Technical details</span>
                <h2>Raw payloads and bundle contents</h2>
              </div>
            </div>
            <TechnicalDetailsAccordion title="Prompt JSON" subtitle="prompt.json">
              <DataPanel
                title="Prompt JSON"
                subtitle="prompt.json"
                value={run?.promptPayload ?? null}
                placeholder="Prompt JSON appears here when attached."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="Response JSON" subtitle="response.json">
              <DataPanel
                title="Response JSON"
                subtitle="response.json"
                value={run?.responsePayload ?? null}
                placeholder="Response JSON appears here when attached."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="Trace JSON" subtitle="trace.json">
              <DataPanel
                title="Trace JSON"
                subtitle="trace.json"
                value={run?.tracePayload ?? null}
                placeholder="Trace JSON appears here when attached."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="Full sealed record" subtitle={run?.bundleId}>
              <DataPanel
                title="Sealed record"
                subtitle={run?.bundleId ?? "bundle"}
                value={run?.bundle ?? null}
                placeholder="Bundle JSON appears here when a record is loaded."
              />
            </TechnicalDetailsAccordion>
          </section>
        </>
      ) : null}

      {activeView === "proof" ? (
        <>
          <RecordEvidenceSection
            title={explainer.proof.title}
            intro={explainer.proof.body}
            cards={proofCards(summary, run)}
          />
          <section className="panel">
            <div className="status-stack three-up">
              <StatusExplainCard status={summary.integrityStatus} />
              <StatusExplainCard status={summary.timestampStatus} />
              <StatusExplainCard status={summary.transparencyStatus} />
            </div>
          </section>
          <ComplianceExplainerCard explainer={explainer.proof.lawExplainer} />
          <section className="panel">
            <div className="panel-head compact">
              <div>
                <span className="section-label">Technical details</span>
                <h2>Verification and disclosure payloads</h2>
              </div>
            </div>
            <TechnicalDetailsAccordion title="Integrity payload" subtitle="verify">
              <DataPanel
                title="Integrity payload"
                subtitle="verify"
                value={run?.verifyResponse ?? null}
                placeholder="Verification payload appears here."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="Timestamp payload" subtitle="timestamp">
              <DataPanel
                title="Timestamp payload"
                subtitle="timestamp"
                value={run?.timestampVerification ?? null}
                placeholder="Timestamp verification payload appears here."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="Transparency payload" subtitle="receipt">
              <DataPanel
                title="Transparency payload"
                subtitle="receipt"
                value={run?.receiptVerification ?? null}
                placeholder="Transparency verification payload appears here."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="Disclosure preview" subtitle="preview">
              <DataPanel
                title="Disclosure preview"
                subtitle={run?.disclosurePreview?.policy_name ?? "Preview"}
                value={run?.disclosurePreview ?? null}
                placeholder="Disclosure preview appears here when available."
              />
            </TechnicalDetailsAccordion>
          </section>
        </>
      ) : null}

      {activeView === "share" ? (
        <>
          <RecordEvidenceSection
            title={explainer.share.title}
            intro={explainer.share.body}
            cards={shareCards(run)}
          />
          {run?.packType ? (
            <ExportStatusCard run={run} onExport={actions.exportCurrentRun} isExporting={isExporting} />
          ) : (
            <section className="panel">
              <div className="panel-head compact">
                <div>
                  <span className="section-label">Export status</span>
                  <h2>No pack is created by default</h2>
                </div>
              </div>
              <p className="section-intro">
                This example teaches capture first. If your real workflow needs controlled sharing,
                you would add a disclosure or export step around the same record path later.
              </p>
            </section>
          )}
          <ComplianceExplainerCard explainer={explainer.share.lawExplainer} />
          <section className="panel">
            <div className="panel-head compact">
              <div>
                <span className="section-label">Technical details</span>
                <h2>Package contents and system rollup</h2>
              </div>
            </div>
            <TechnicalDetailsAccordion title="Share package summary" subtitle={run?.packType ?? "No pack"}>
              <DataPanel
                title="Share package summary"
                subtitle={run?.packType ?? "No pack"}
                value={run?.packSummary ?? null}
                placeholder="Package summary appears here after export."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="Share package manifest" subtitle="manifest">
              <DataPanel
                title="Share package manifest"
                subtitle={run?.packSummary?.pack_id ?? "Manifest"}
                value={run?.packManifest ?? null}
                placeholder="Package manifest appears here after export."
              />
            </TechnicalDetailsAccordion>
            <TechnicalDetailsAccordion title="System rollup" subtitle={run?.systemSummary?.system_id ?? "system"}>
              <DataPanel
                title="System rollup"
                subtitle={run?.systemSummary?.system_id ?? "System summary"}
                value={run?.systemSummary ?? null}
                placeholder="System rollup appears here when the run is loaded."
              />
            </TechnicalDetailsAccordion>
          </section>
        </>
      ) : null}
    </section>
  );
}
