import React, { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { DataPanel } from "../components/DataPanel";
import { RecentRunsRail } from "../components/RecentRunsRail";

export function ResultsPage() {
  const { bundleId } = useParams();
  const { currentRun, recentRuns, actions } = useDemo();
  const activeBundleId = bundleId || currentRun?.bundleId || recentRuns[0]?.bundle_id;

  useEffect(() => {
    if (activeBundleId) {
      void actions.ensureRunLoaded(activeBundleId);
    }
  }, [activeBundleId]);

  if (!activeBundleId && !currentRun) {
    return (
      <section className="panel empty-state">
        <span className="section-label">Results</span>
        <h2>No runs yet</h2>
        <p>Use the playground to create a bundle, then inspect the results here.</p>
      </section>
    );
  }

  const run = currentRun;

  return (
    <section className="page-stack">
      <section className="panel">
        <div className="panel-head">
          <div>
            <span className="section-label">Results</span>
            <h2>Current run</h2>
          </div>
          <span className="mode-badge">{run?.captureMode ?? "loading"}</span>
        </div>
        <div className="response-card">
          <h3>Response content</h3>
          <pre>{run?.responseText ?? "Loading captured response..."}</pre>
        </div>
        <div className="summary-grid">
          <div className="summary-card">
            <strong>Bundle identity</strong>
            <span>{run?.bundleId ?? "Loading..."}</span>
          </div>
          <div className="summary-card">
            <strong>Model</strong>
            <span>{run ? `${run.provider}:${run.model}` : "Loading..."}</span>
          </div>
          <div className="summary-card">
            <strong>Actor role</strong>
            <span>{run?.actorRole ?? "Loading..."}</span>
          </div>
          <div className="summary-card">
            <strong>Workflow outcome</strong>
            <span>
              {run?.verifyResponse?.valid
                ? "Verified bundle with current vault signer"
                : run?.verifyResponse?.message ?? "Loading verification"}
            </span>
          </div>
        </div>
      </section>

      <RecentRunsRail runs={recentRuns} />

      <section className="snapshot-grid">
        <DataPanel
          title="Bundle overview"
          subtitle={run?.bundleId ?? "Awaiting bundle"}
          value={
            run
              ? {
                  bundle_id: run.bundleId,
                  created_at: run.createMeta?.created_at ?? run.bundle?.created_at,
                  bundle_root: run.createMeta?.bundle_root ?? run.bundle?.integrity?.bundle_root,
                  response_source: run.captureMode,
                  pack_type: run.packType,
                  disclosure_profile: run.disclosureProfile
                }
              : null
          }
          placeholder="Bundle metadata appears here after a run is selected."
        />
        <DataPanel
          title="Prompt payload"
          subtitle="Captured prompt request"
          value={run?.promptPayload ?? null}
          placeholder="Prompt JSON will appear here."
        />
        <DataPanel
          title="Response payload"
          subtitle="Captured provider response"
          value={run?.responsePayload ?? null}
          placeholder="Response JSON will appear here."
        />
      </section>
    </section>
  );
}
