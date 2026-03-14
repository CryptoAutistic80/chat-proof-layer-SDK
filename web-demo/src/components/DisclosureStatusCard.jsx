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
          <h2>What could be shared</h2>
        </div>
      </div>
      <div className="status-stack">
        <article className={`status-card is-${preview ? "accent" : "muted"}`}>
          <strong>{preview?.policy_name ?? "No preview yet"}</strong>
          <p>
            {preview
              ? itemCount > 0 || artefactCount > 0
                ? `${itemCount} items and ${artefactCount} artefacts are included under the selected sharing profile.`
                : "This sharing profile does not reveal any content for this proof record."
              : "Run or reload a bundle to inspect disclosure decisions."}
          </p>
        </article>
      </div>
    </section>
  );
}
