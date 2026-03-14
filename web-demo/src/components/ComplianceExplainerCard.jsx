import React from "react";

export function ComplianceExplainerCard({ explainer }) {
  return (
    <section className="panel compliance-explainer-card">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Why this matters for EU AI Act review</span>
          <h2>Plain-English compliance context</h2>
        </div>
      </div>
      <div className="explanation-stack">
        <div>
          <strong>What the law usually expects</strong>
          <p>{explainer.expectation}</p>
        </div>
        <div>
          <strong>What Proof Layer helps you record</strong>
          <p>{explainer.record}</p>
        </div>
        <div>
          <strong>What your team still has to do outside this tool</strong>
          <p>{explainer.outsideTool}</p>
        </div>
      </div>
    </section>
  );
}
