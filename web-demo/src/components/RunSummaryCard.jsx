import React from "react";

export function RunSummaryCard({ run, preset }) {
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Current Run</span>
          <h2>{preset.label}</h2>
        </div>
      </div>
      <div className="hero-summary run-summary-card">
        <div>
          <strong>Capture mode</strong>
          <span>{run?.captureMode ?? "Awaiting first run"}</span>
        </div>
        <div>
          <strong>Pack type</strong>
          <span>{run?.packType ?? preset.packType}</span>
        </div>
        <div>
          <strong>Disclosure profile</strong>
          <span>{run?.disclosureProfile ?? preset.disclosureProfile}</span>
        </div>
        <div>
          <strong>Bundle</strong>
          <span>{run?.bundleId ?? "Not sealed yet"}</span>
        </div>
      </div>
    </section>
  );
}
