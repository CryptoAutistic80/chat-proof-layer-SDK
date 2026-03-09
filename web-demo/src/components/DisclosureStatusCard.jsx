import React from "react";

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

export function DisclosureStatusCard({ run }) {
  const preview = run?.disclosurePreview;
  const itemCount = arrayValue(preview?.disclosed_item_indices).length;
  const artefactCount = arrayValue(preview?.disclosed_artefact_names).length;

  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Disclosure</span>
          <h2>Policy outcome</h2>
        </div>
      </div>
      <div className="status-stack">
        <article className={`status-card is-${preview ? "accent" : "muted"}`}>
          <strong>{preview?.policy_name ?? "No preview yet"}</strong>
          <p>
            {preview
              ? itemCount > 0 || artefactCount > 0
                ? `${itemCount} items and ${artefactCount} artefacts survive the current disclosure profile.`
                : "No disclosure output for this profile on the current run."
              : "Run or reload a bundle to inspect disclosure decisions."}
          </p>
        </article>
      </div>
    </section>
  );
}
