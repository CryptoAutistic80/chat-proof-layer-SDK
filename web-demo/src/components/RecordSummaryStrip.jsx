import React from "react";
import { humanCaptureMode } from "../lib/narrative";

export function RecordSummaryStrip({ run, summary, runOptions, onSelectRun }) {
  return (
    <section className="panel record-summary-strip">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Explore records</span>
          <h1>{summary.headline}</h1>
        </div>
        <label className="record-selector">
          <span>Selected record</span>
          <select value={run?.bundleId ?? ""} onChange={(event) => onSelectRun(event.target.value)}>
            {runOptions.map((option) => (
              <option key={option.bundleId} value={option.bundleId}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </div>
      <p className="narrative-copy">{summary.summary}</p>
      <div className="summary-grid record-facts-grid">
        <div className="summary-card">
          <strong>Workflow</strong>
          <span>{run?.scenarioLabel ?? "Loaded record"}</span>
        </div>
        <div className="summary-card">
          <strong>System</strong>
          <span>{run?.bundle?.subject?.system_id ?? run?.systemSummary?.system_id ?? "Unknown"}</span>
        </div>
        <div className="summary-card">
          <strong>Actor role</strong>
          <span>{run?.actorRole ?? "Unknown"}</span>
        </div>
        <div className="summary-card">
          <strong>Capture mode</strong>
          <span>{humanCaptureMode(run?.captureMode)}</span>
        </div>
        <div className="summary-card">
          <strong>Bundle count</strong>
          <span>{run?.bundleRuns?.length ?? 0}</span>
        </div>
      </div>
    </section>
  );
}
