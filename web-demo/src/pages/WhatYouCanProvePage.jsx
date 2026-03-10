import React, { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { DataPanel } from "../components/DataPanel";
import { DisclosureStatusCard } from "../components/DisclosureStatusCard";
import { StatusExplainCard } from "../components/StatusExplainCard";
import { buildRunNarrativeSummary } from "../lib/narrative";

export function WhatYouCanProvePage() {
  const { bundleId } = useParams();
  const { currentRun, recentRuns, vaultConfig, actions, isPreviewing } = useDemo();
  const activeBundleId = bundleId || currentRun?.bundleId || recentRuns[0]?.bundle_id;

  useEffect(() => {
    if (activeBundleId) {
      void actions.ensureRunLoaded(activeBundleId);
    }
  }, [activeBundleId]);

  if (!activeBundleId && !currentRun) {
    return (
      <section className="panel empty-state">
        <span className="section-label">What you can prove</span>
        <h2>No proof record selected</h2>
        <p>Run a scenario first, then inspect the proof and disclosure story here.</p>
      </section>
    );
  }

  const run = currentRun;
  const summary = buildRunNarrativeSummary(run, vaultConfig);

  return (
    <section className="page-stack">
      <section className="panel">
        <div className="panel-head">
          <div>
            <span className="section-label">What you can prove</span>
            <h2>What a reviewer can independently confirm</h2>
          </div>
          <button
            type="button"
            className="ghost-btn"
            onClick={() => actions.previewCurrentRun()}
            disabled={!run?.bundleId || isPreviewing}
          >
            {isPreviewing ? "Refreshing..." : "Refresh disclosure preview"}
          </button>
        </div>
        <div className="status-stack three-up">
          <StatusExplainCard status={summary.integrityStatus} />
          <StatusExplainCard status={summary.timestampStatus} />
          <StatusExplainCard status={summary.transparencyStatus} />
        </div>
      </section>

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">What this means</span>
            <h2>Trust story for this proof record</h2>
          </div>
        </div>
        <p className="narrative-copy">
          {summary.integrityStatus.summary} {summary.timestampStatus.summary}{" "}
          {summary.transparencyStatus.summary}
        </p>
      </section>

      <DisclosureStatusCard run={run} />

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Details</span>
            <h2>Raw verification and disclosure payloads</h2>
          </div>
        </div>
        <div className="snapshot-grid">
          <DataPanel
            title="Proof record JSON"
            subtitle={run?.bundle?.integrity?.bundle_root_algorithm ?? "Bundle"}
            value={run?.bundle ?? null}
            placeholder="Proof record JSON appears here."
          />
          <DataPanel
            title="Integrity payload"
            subtitle="verify"
            value={run?.verifyResponse ?? null}
            placeholder="Verification payload appears here."
          />
          <DataPanel
            title="Timestamp payload"
            subtitle="timestamp"
            value={run?.timestampVerification ?? null}
            placeholder="Timestamp payload appears here."
          />
          <DataPanel
            title="Transparency payload"
            subtitle="receipt"
            value={run?.receiptVerification ?? null}
            placeholder="Transparency payload appears here."
          />
          <DataPanel
            title="Disclosure preview"
            subtitle={run?.disclosurePreview?.policy_name ?? "Preview"}
            value={run?.disclosurePreview ?? null}
            placeholder="Disclosure preview appears here."
          />
          <DataPanel
            title="Trace payload"
            subtitle="trace.json"
            value={run?.tracePayload ?? null}
            placeholder="Trace JSON appears here."
          />
        </div>
      </section>
    </section>
  );
}
