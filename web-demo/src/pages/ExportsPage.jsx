import React, { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { DataPanel } from "../components/DataPanel";
import { ExportStatusCard } from "../components/ExportStatusCard";
import { RecentRunsRail } from "../components/RecentRunsRail";

export function ExportsPage() {
  const { bundleId } = useParams();
  const { currentRun, recentRuns, actions, isExporting } = useDemo();
  const activeBundleId = bundleId || currentRun?.bundleId || recentRuns[0]?.bundle_id;

  useEffect(() => {
    if (activeBundleId) {
      void actions.ensureRunLoaded(activeBundleId);
    }
  }, [activeBundleId]);

  if (!activeBundleId && !currentRun) {
    return (
      <section className="panel empty-state">
        <span className="section-label">Exports</span>
        <h2>No export target yet</h2>
        <p>Run a workflow first, then review pack assembly and downloads here.</p>
      </section>
    );
  }

  const run = currentRun;

  return (
    <section className="page-stack">
      <ExportStatusCard run={run} onExport={actions.exportCurrentRun} isExporting={isExporting} />
      <RecentRunsRail runs={recentRuns} />
      <section className="snapshot-grid">
        <DataPanel
          title="Pack manifest"
          subtitle={run?.packSummary?.pack_id ?? "Pack manifest"}
          value={run?.packManifest ?? null}
          placeholder="Pack manifest appears here after export."
        />
        <DataPanel
          title="Pack summary"
          subtitle={run?.packType ?? "Pack"}
          value={run?.packSummary ?? null}
          placeholder="Pack summary appears here after export."
        />
        <DataPanel
          title="System summary"
          subtitle={run?.systemSummary?.system_id ?? "System summary"}
          value={run?.systemSummary ?? null}
          placeholder="System rollup appears here once the bundle is loaded."
        />
      </section>
    </section>
  );
}
