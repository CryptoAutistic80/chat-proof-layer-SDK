import React from "react";
import { humanCaptureMode } from "../lib/narrative";

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
          <span>{humanCaptureMode(run?.captureMode)}</span>
        </div>
        <div>
          <strong>Scenario outcome</strong>
          <span>{preset.outcomeLabel}</span>
        </div>
        <div>
          <strong>Sharing profile</strong>
          <span>{run?.disclosureProfile ?? preset.disclosureProfile}</span>
        </div>
        <div>
          <strong>Proof record</strong>
          <span>{run?.bundleId ?? "Not sealed yet"}</span>
        </div>
      </div>
    </section>
  );
}
