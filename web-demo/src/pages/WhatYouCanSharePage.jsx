import React, { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { DataPanel } from "../components/DataPanel";
import { ExportStatusCard } from "../components/ExportStatusCard";
import { StatusExplainCard } from "../components/StatusExplainCard";
import { buildRunNarrativeSummary } from "../lib/narrative";

export function WhatYouCanSharePage() {
  const { bundleId } = useParams();
  const { currentRun, recentRuns, vaultConfig, actions, isExporting } = useDemo();
  const activeBundleId = bundleId || currentRun?.bundleId || recentRuns[0]?.bundle_id;

  useEffect(() => {
    if (activeBundleId) {
      void actions.ensureRunLoaded(activeBundleId);
    }
  }, [activeBundleId]);

  if (!activeBundleId && !currentRun) {
    return (
      <section className="panel empty-state">
        <span className="section-label">What you can share</span>
        <h2>No share package target yet</h2>
        <p>Run a scenario first, then review what can be exported and shared from here.</p>
      </section>
    );
  }

  const run = currentRun;
  const summary = buildRunNarrativeSummary(run, vaultConfig);

  return (
    <section className="page-stack inspection-page share-page">
      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">What you can share</span>
            <h2>How this proof record leaves the system</h2>
          </div>
        </div>
        <div className="status-stack">
          <StatusExplainCard status={summary.disclosureStatus} />
          <StatusExplainCard status={summary.exportStatus} />
          <StatusExplainCard status={summary.completenessStatus} />
        </div>
      </section>

      <ExportStatusCard run={run} onExport={actions.exportCurrentRun} isExporting={isExporting} />

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Details</span>
            <h2>Share package contents and system rollup</h2>
          </div>
        </div>
        <div className="snapshot-grid snapshot-grid-triple">
          <DataPanel
            title="Share package summary"
            subtitle={run?.packType ?? "Share package"}
            value={run?.packSummary ?? null}
            placeholder="Share package summary appears after export."
          />
          <DataPanel
            title="Share package manifest"
            subtitle={run?.packSummary?.pack_id ?? "Manifest"}
            value={run?.packManifest ?? null}
            placeholder="Share package manifest appears after export."
          />
          <DataPanel
            title="System rollup"
            subtitle={run?.systemSummary?.system_id ?? "System summary"}
            value={run?.systemSummary ?? null}
            placeholder="System rollup appears when the run is loaded."
          />
        </div>
      </section>
    </section>
  );
}
