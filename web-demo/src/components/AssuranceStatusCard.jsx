import React from "react";

function statusTone(valid, configured = true) {
  if (!configured) {
    return "muted";
  }
  if (valid === true) {
    return "good";
  }
  if (valid === false) {
    return "warn";
  }
  return "muted";
}

export function AssuranceStatusCard({ run, vaultConfig }) {
  const timestampConfigured = Boolean(vaultConfig?.timestamp?.enabled);
  const receiptConfigured = Boolean(vaultConfig?.transparency?.enabled);

  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Assurance</span>
          <h2>Trust checks</h2>
        </div>
      </div>
      <div className="status-stack">
        <article className={`status-card is-${statusTone(run?.verifyResponse?.valid, true)}`}>
          <strong>Bundle verification</strong>
          <p>
            {run?.verifyResponse?.valid
              ? "Verified: bundle signature and artefacts match the connected vault signer key."
              : run?.verifyResponse?.message || "Verification will run after the bundle is sealed."}
          </p>
        </article>
        <article
          className={`status-card is-${statusTone(
            run?.timestampVerification?.valid,
            timestampConfigured
          )}`}
        >
          <strong>RFC 3161 timestamp</strong>
          <p>
            {timestampConfigured
              ? run?.timestampVerification?.valid
                ? "Verified: the timestamp token matches the current bundle root."
                : run?.timestampVerification?.message || "Requested, but not yet attached."
              : "Not configured on this vault."}
          </p>
        </article>
        <article
          className={`status-card is-${statusTone(
            run?.receiptVerification?.valid,
            receiptConfigured
          )}`}
        >
          <strong>Transparency receipt</strong>
          <p>
            {receiptConfigured
              ? run?.receiptVerification?.valid
                ? "Verified: the transparency receipt matches the current bundle."
                : run?.receiptVerification?.message || "Requested, but not yet attached."
              : "Not configured on this vault."}
          </p>
        </article>
      </div>
    </section>
  );
}
