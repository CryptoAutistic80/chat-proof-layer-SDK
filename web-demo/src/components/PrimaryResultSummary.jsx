import React from "react";

export function PrimaryResultSummary({ summary, run }) {
  return (
    <section className="panel narrative-panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Business summary</span>
          <h2>{summary.headline}</h2>
        </div>
      </div>
      <p className="narrative-copy">{summary.summary}</p>
      <div className="summary-grid business-summary-grid">
        <div className="summary-card">
          <strong>Scenario</strong>
          <span>{summary.scenario}</span>
        </div>
        <div className="summary-card">
          <strong>Capture mode</strong>
          <span>{summary.mode}</span>
        </div>
        <div className="summary-card">
          <strong>Proof record</strong>
          <span>{summary.proofRecord}</span>
        </div>
        <div className="summary-card">
          <strong>Model</strong>
          <span>{run ? `${run.provider}:${run.model}` : "Awaiting run"}</span>
        </div>
      </div>
    </section>
  );
}

