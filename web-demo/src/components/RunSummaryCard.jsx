import React from "react";
import { humanCaptureMode } from "../lib/narrative";

export function RunSummaryCard({ run, preset, scenario }) {
  const title = run?.scenarioLabel ?? scenario?.label ?? preset.label;
  const outcomeLabel = run?.scenarioOutcomeLabel ?? scenario?.description ?? preset.outcomeLabel;
  const disclosureProfile =
    run?.disclosureProfile ?? scenario?.disclosureProfile ?? preset.disclosureProfile;

  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Current Run</span>
          <h2>{title}</h2>
        </div>
      </div>
      <div className="hero-summary run-summary-card">
        <div>
          <strong>Capture mode</strong>
          <span>{humanCaptureMode(run?.captureMode)}</span>
        </div>
        <div>
          <strong>Scenario outcome</strong>
          <span>{outcomeLabel}</span>
        </div>
        <div>
          <strong>Sharing profile</strong>
          <span>{disclosureProfile}</span>
        </div>
        <div>
          <strong>Conversation proof</strong>
          <span>{run?.bundleId ?? "Not sealed yet"}</span>
        </div>
      </div>
    </section>
  );
}
