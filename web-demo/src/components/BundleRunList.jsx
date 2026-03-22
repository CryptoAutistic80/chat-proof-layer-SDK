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

function badgeForIntegrity(bundleRun) {
  return {
    label: "Integrity",
    detail: bundleRun.verifyResponse?.valid ? "Verified" : "Needs attention",
    tone: statusTone(bundleRun.verifyResponse?.valid, "muted"),
  };
}

function badgeForOptionalCheck(label, verification) {
  if (verification?.valid === true) {
    return { label, detail: "Attached", tone: "good" };
  }
  if (verification?.valid === false) {
    return { label, detail: "Failed", tone: "warn" };
  }
  return { label, detail: "Not added", tone: "muted" };
}

function badgeForTransparency(bundleRun) {
  if (bundleRun.receiptVerification?.valid === true) {
    return { label: "Transparency", detail: "Attached", tone: "good" };
  }
  if (bundleRun.receiptVerification?.valid === false) {
    return { label: "Transparency", detail: "Failed", tone: "warn" };
  }
  if (
    bundleRun.transparencyRequested &&
    bundleRun.timestampVerification?.valid === false
  ) {
    return { label: "Transparency", detail: "Skipped", tone: "muted" };
  }
  return { label: "Transparency", detail: "Not added", tone: "muted" };
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
              <span
                className={`bundle-role-pill is-${bundleRun.bundleRole === "primary" ? "accent" : "muted"}`}
              >
                {bundleRun.bundleRole}
              </span>
            </div>
            <p>{bundleRun.summary}</p>
            <div className="bundle-run-meta">
              <span>{bundleRun.itemTypes.join(" + ")}</span>
              {[
                badgeForIntegrity(bundleRun),
                badgeForOptionalCheck("Timestamp", bundleRun.timestampVerification),
                badgeForTransparency(bundleRun),
              ].map((badge) => (
                <span key={badge.label} className={`bundle-check is-${badge.tone}`}>
                  <strong>{badge.label}</strong>
                  <span>{badge.detail}</span>
                </span>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}
