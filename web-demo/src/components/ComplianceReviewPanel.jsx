import React from "react";

function ReadinessSection({ title, readiness }) {
  return (
    <>
      <h4>{title}</h4>
      <p>
        <strong>{readiness.profile ?? "No readiness profile attached"}</strong>
      </p>
      <p>{readiness.summary}</p>
      <p>
        {readiness.passCount} pass · {readiness.warnCount} warn ·{" "}
        {readiness.failCount} fail
      </p>
      {readiness.topMissingFields.length > 0 ? (
        <>
          <h4>Top missing fields</h4>
          <ul className="review-list compact">
            {readiness.topMissingFields.map((entry) => (
              <li key={entry}>{entry}</li>
            ))}
          </ul>
        </>
      ) : null}
    </>
  );
}

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
          <ReadinessSection
            title="Workflow readiness check"
            readiness={review.readiness}
          />
          {review.packReadiness ? (
            <ReadinessSection
              title="Exported pack readiness"
              readiness={review.packReadiness}
            />
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
