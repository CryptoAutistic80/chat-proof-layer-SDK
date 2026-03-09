import React, { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { AssuranceStatusCard } from "../components/AssuranceStatusCard";
import { DataPanel } from "../components/DataPanel";
import { DisclosureStatusCard } from "../components/DisclosureStatusCard";

export function ExaminationPage() {
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
        <span className="section-label">Examination</span>
        <h2>No bundle selected</h2>
        <p>Run a workflow first, then inspect trust checks and disclosure decisions here.</p>
      </section>
    );
  }

  const run = currentRun;

  return (
    <section className="page-stack">
      <div className="page-actions">
        <button
          type="button"
          className="ghost-btn"
          onClick={() => actions.previewCurrentRun()}
          disabled={!run?.bundleId || isPreviewing}
        >
          {isPreviewing ? "Refreshing preview..." : "Refresh disclosure preview"}
        </button>
      </div>

      <div className="summary-grid examination-grid">
        <AssuranceStatusCard run={run} vaultConfig={vaultConfig} />
        <DisclosureStatusCard run={run} />
      </div>

      <section className="snapshot-grid">
        <DataPanel
          title="Bundle JSON"
          subtitle={run?.bundle?.integrity?.bundle_root_algorithm ?? "Bundle"}
          value={run?.bundle ?? null}
          placeholder="Bundle JSON will appear here."
        />
        <DataPanel
          title="Assurance payloads"
          subtitle="verify, timestamp, receipt"
          value={{
            verify: run?.verifyResponse ?? null,
            timestamp: run?.timestampVerification ?? null,
            receipt: run?.receiptVerification ?? null
          }}
          placeholder="Assurance payloads will appear here."
        />
        <DataPanel
          title="Disclosure preview"
          subtitle={run?.disclosurePreview?.policy_name ?? "Preview"}
          value={run?.disclosurePreview ?? null}
          placeholder="Preview the selected disclosure profile here."
        />
        <DataPanel
          title="Trace payload"
          subtitle="Raw capture trace"
          value={run?.tracePayload ?? null}
          placeholder="Trace JSON will appear here."
        />
      </section>
    </section>
  );
}
