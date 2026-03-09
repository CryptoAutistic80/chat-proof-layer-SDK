import React from "react";
import { formatBytes } from "../lib/vaultApi";

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

export function ExportStatusCard({ run, onExport, isExporting }) {
  const preview = run?.disclosurePreview;
  const hasDisclosureOutput =
    arrayValue(preview?.disclosed_item_indices).length > 0 ||
    arrayValue(preview?.disclosed_artefact_names).length > 0;
  const canExport = run && (run.bundleFormat === "full" || hasDisclosureOutput);

  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Exports</span>
          <h2>Pack assembly</h2>
        </div>
        <button
          type="button"
          className="ghost-btn"
          onClick={onExport}
          disabled={!canExport || isExporting}
        >
          {isExporting ? "Exporting..." : "Export pack"}
        </button>
      </div>
      <div className="status-stack">
        <article className={`status-card is-${canExport ? "good" : "warn"}`}>
          <strong>{run?.packSummary?.pack_id ?? "No pack exported yet"}</strong>
          <p>
            {canExport
              ? run?.downloadInfo
                ? `${run.bundleFormat} pack ready · ${formatBytes(run.downloadInfo.size)}`
                : `This run is eligible for ${run.bundleFormat} export.`
              : "No disclosure pack to export for this run with the selected profile."}
          </p>
        </article>
      </div>
      {run?.downloadInfo ? (
        <a className="download-link" href={run.downloadInfo.url} download={run.downloadInfo.fileName}>
          Download {run.downloadInfo.fileName}
        </a>
      ) : null}
    </section>
  );
}
