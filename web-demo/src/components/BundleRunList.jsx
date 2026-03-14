import React from "react";

function statusTone(valid, pendingValue) {
  if (valid === true) {
    return "good";
  }
  if (valid === false) {
    return "warn";
  }
  return pendingValue;
}

export function BundleRunList({ bundleRuns }) {
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Captured now</span>
          <h3>Bundle-by-bundle view</h3>
        </div>
      </div>

      <div className="bundle-run-list">
        {bundleRuns.map((bundleRun) => (
          <article key={bundleRun.bundleId} className="bundle-run-card">
            <div className="bundle-run-head">
              <div>
                <strong>{bundleRun.label}</strong>
                <span>{bundleRun.bundleId}</span>
              </div>
              <span className={`status-pill is-${bundleRun.bundleRole === "primary" ? "accent" : "muted"}`}>
                {bundleRun.bundleRole}
              </span>
            </div>
            <p>{bundleRun.summary}</p>
            <div className="bundle-run-meta">
              <span>{bundleRun.itemTypes.join(" + ")}</span>
              <span className={`status-pill is-${statusTone(bundleRun.verifyResponse?.valid, "muted")}`}>
                integrity
              </span>
              <span
                className={`status-pill is-${statusTone(
                  bundleRun.timestampVerification?.valid,
                  "muted"
                )}`}
              >
                timestamp
              </span>
              <span
                className={`status-pill is-${statusTone(
                  bundleRun.receiptVerification?.valid,
                  "muted"
                )}`}
              >
                transparency
              </span>
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
