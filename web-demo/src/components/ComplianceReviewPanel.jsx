import React from "react";

export function ComplianceReviewPanel({ review }) {
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Compliance review</span>
          <h3>{review.title}</h3>
        </div>
      </div>

      <p className="narrative-copy">{review.summary}</p>

      <div className="review-grid">
        <section className="review-card">
          <h4>Captured now</h4>
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
          <h4>Supports this pack</h4>
          <p>
            <strong>{review.supportsPack.packType}</strong>
          </p>
          <p>{review.supportsPack.bundleCount} bundle(s) currently support the export.</p>
          <p>{review.supportsPack.exportState}</p>
        </section>

        <section className="review-card">
          <h4>Still missing for a fuller review</h4>
          <ul className="review-list compact">
            {review.missingEvidence.map((entry) => (
              <li key={entry}>{entry}</li>
            ))}
          </ul>
        </section>
      </div>
    </section>
  );
}
