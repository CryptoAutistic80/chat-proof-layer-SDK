import React from "react";

export function ComplianceReviewPanel({ review }) {
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Why this helps with compliance</span>
          <h3>{review.title}</h3>
        </div>
      </div>

      <p className="narrative-copy">{review.summary}</p>

      <div className="review-grid">
        <section className="review-card">
          <h4>What was captured</h4>
          <ul className="review-list">
            {review.capturedNow.map((entry) => (
              <li key={entry.bundleId}>
                <strong>{entry.label}</strong>
                <span>{entry.bundleId}</span>
                <p>{entry.itemTypes.join(" + ")}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className="review-card">
          <h4>What the law usually expects</h4>
          <p>{review.lawExplainer.expectation}</p>
          <h4>What Proof Layer helps you record</h4>
          <p>{review.lawExplainer.record}</p>
          <h4>What your team still has to do outside this tool</h4>
          <p>{review.lawExplainer.outsideTool}</p>
        </section>

        <section className="review-card">
          <h4>Readiness check</h4>
          <p>
            <strong>{review.readiness.profile ?? "No readiness profile attached"}</strong>
          </p>
          <p>
            {review.readiness.summary}
          </p>
          <p>
            {review.readiness.passCount} pass · {review.readiness.warnCount} warn ·{" "}
            {review.readiness.failCount} fail
          </p>
          {review.readiness.topMissingFields.length > 0 ? (
            <>
              <h4>Top missing fields</h4>
              <ul className="review-list compact">
                {review.readiness.topMissingFields.map((entry) => (
                  <li key={entry}>{entry}</li>
                ))}
              </ul>
            </>
          ) : null}
          <h4>Share or export status</h4>
          <p>
            <strong>{review.supportsPack.packType}</strong>
          </p>
          <p>{review.supportsPack.bundleCount} record(s) are in the current run.</p>
          <p>{review.supportsPack.exportState}</p>
          <h4>Common next evidence</h4>
          <ul className="review-list compact">
            {review.commonNextEvidence.map((entry) => (
              <li key={entry}>{entry}</li>
            ))}
          </ul>
        </section>
      </div>
    </section>
  );
}
