import React, { useEffect } from "react";
import { useParams } from "react-router-dom";
import { useDemo } from "../app/DemoContext";
import { DataPanel } from "../components/DataPanel";
import { PrimaryResultSummary } from "../components/PrimaryResultSummary";
import { RecentRunsRail } from "../components/RecentRunsRail";
import { buildRunNarrativeSummary } from "../lib/narrative";

export function WhatHappenedPage() {
  const { bundleId } = useParams();
  const { currentRun, recentRuns, vaultConfig, actions } = useDemo();
  const activeBundleId = bundleId || currentRun?.bundleId || recentRuns[0]?.bundle_id;

  useEffect(() => {
    if (activeBundleId) {
      void actions.ensureRunLoaded(activeBundleId);
    }
  }, [activeBundleId]);

  if (!activeBundleId && !currentRun) {
    return (
      <section className="panel empty-state">
        <span className="section-label">What happened</span>
        <h2>No runs yet</h2>
        <p>Start with the guided demo to create a proof record and explain what happened.</p>
      </section>
    );
  }

  const run = currentRun;
  const summary = buildRunNarrativeSummary(run, vaultConfig);

  return (
    <section className="page-stack">
      <PrimaryResultSummary summary={summary} run={run} />

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Response content</span>
            <h2>What the AI returned</h2>
          </div>
        </div>
        <div className="response-card">
          <pre>{run?.responseText ?? "Loading captured response..."}</pre>
        </div>
      </section>

      <section className="snapshot-grid">
        <DataPanel
          title="Proof record summary"
          subtitle="Proof record (bundle)"
          value={
            run
              ? {
                  proof_record_id: run.bundleId,
                  created_at: run.createMeta?.created_at ?? run.bundle?.created_at,
                  bundle_root: run.createMeta?.bundle_root ?? run.bundle?.integrity?.bundle_root,
                  capture_mode: run.captureMode,
                  scenario: summary.scenario
                }
              : null
          }
          placeholder="Proof record metadata appears here after a run is selected."
        />
        <DataPanel
          title="Captured materials"
          subtitle="Prompt, response, and trace"
          value={
            run
              ? {
                  prompt: run.promptPayload,
                  response: run.responsePayload,
                  trace: run.tracePayload
                }
              : null
          }
          placeholder="Captured materials appear here after a run is selected."
        />
      </section>

      <RecentRunsRail runs={recentRuns} />

      <section className="panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Details</span>
            <h2>Technical payloads</h2>
          </div>
        </div>
        <div className="snapshot-grid">
          <DataPanel
            title="Prompt payload"
            subtitle="prompt.json"
            value={run?.promptPayload ?? null}
            placeholder="Prompt JSON appears here."
          />
          <DataPanel
            title="Response payload"
            subtitle="response.json"
            value={run?.responsePayload ?? null}
            placeholder="Response JSON appears here."
          />
        </div>
      </section>
    </section>
  );
}

