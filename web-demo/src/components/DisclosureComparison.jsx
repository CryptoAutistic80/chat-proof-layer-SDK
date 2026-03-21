import React, { useState } from "react";
import { DISCLOSURE_PROFILES } from "../lib/sampleBundle";

/**
 * Side-by-side disclosure profile comparison.
 * Shows what different audiences (auditor, customer, public) would see
 * from the same sealed bundle.
 *
 * Props:
 *   bundle   - the full bundle with items and artefacts
 *   compact  - smaller variant for embedding
 */
export function DisclosureComparison({ bundle, compact }) {
  const [activeProfile, setActiveProfile] = useState(null);
  const profiles = Object.entries(DISCLOSURE_PROFILES);

  if (!bundle) return null;

  return (
    <div className={`disclosure-container ${compact ? "disclosure-compact" : ""}`}>
      {!compact && (
        <div className="disclosure-header">
          <span className="section-label">Selective disclosure</span>
          <h3>Same record, different audiences</h3>
          <p className="disclosure-lead">
            Proof Layer lets you share different views of the same sealed evidence.
            The cryptographic proof still holds for each disclosed subset.
          </p>
        </div>
      )}

      <div className="disclosure-profiles">
        {profiles.map(([key, profile]) => (
          <button
            key={key}
            type="button"
            className={`disclosure-profile-tab ${activeProfile === key ? "is-active" : ""}`}
            onClick={() => setActiveProfile((prev) => (prev === key ? null : key))}
          >
            <strong>{profile.label}</strong>
            <span>{profile.description}</span>
            <div className="disclosure-counts">
              <span className={`status-pill is-${profile.visibleItems.length > 0 ? "good" : "muted"}`}>
                {profile.visibleItems.length} of {bundle.items?.length ?? 0} items
              </span>
              <span className={`status-pill is-${profile.visibleArtefacts.length > 0 ? "good" : "muted"}`}>
                {profile.visibleArtefacts.length} of {bundle.artefacts?.length ?? 0} artefacts
              </span>
            </div>
          </button>
        ))}
      </div>

      {/* Side-by-side comparison grid */}
      <div className="disclosure-grid">
        {profiles.map(([key, profile]) => (
          <div
            key={key}
            className={`disclosure-column ${activeProfile === key ? "disclosure-column-active" : ""}`}
          >
            <div className="disclosure-column-head">
              <strong>{profile.label}</strong>
            </div>
            <div className="disclosure-column-body">
              {/* Items */}
              {(bundle.items ?? []).map((item, i) => {
                const visible = profile.visibleItems.includes(i);
                return (
                  <div
                    key={`item-${i}`}
                    className={`disclosure-item ${visible ? "disclosure-item-visible" : "disclosure-item-redacted"}`}
                  >
                    <div className="disclosure-item-head">
                      <span className="disclosure-item-type">{item.type}</span>
                      <span className={`status-pill is-${visible ? "good" : "muted"}`}>
                        {visible ? "disclosed" : "redacted"}
                      </span>
                    </div>
                    {visible ? (
                      <div className="disclosure-item-fields">
                        {Object.entries(item.data ?? {}).map(([field, value]) => {
                          const redacted = profile.redactedFields.includes(field);
                          return (
                            <div key={field} className="disclosure-field">
                              <span className="disclosure-field-name">{field}</span>
                              <span className={`disclosure-field-value ${redacted ? "disclosure-field-redacted" : ""}`}>
                                {redacted
                                  ? "\u2588\u2588\u2588\u2588 REDACTED \u2588\u2588\u2588\u2588"
                                  : typeof value === "string"
                                    ? value.length > 80
                                      ? value.slice(0, 80) + "\u2026"
                                      : value
                                    : JSON.stringify(value)}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    ) : (
                      <div className="disclosure-item-hidden">
                        <span>Evidence sealed but not disclosed to this audience.</span>
                        <span className="disclosure-item-proof-note">
                          Proof of existence is still verifiable.
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}

              {/* Artefacts */}
              {(bundle.artefacts ?? []).map((artefact, i) => {
                const visible = profile.visibleArtefacts.includes(i);
                return (
                  <div
                    key={`art-${i}`}
                    className={`disclosure-item ${visible ? "disclosure-item-visible" : "disclosure-item-redacted"}`}
                  >
                    <div className="disclosure-item-head">
                      <span className="disclosure-item-type">{artefact.name}</span>
                      <span className={`status-pill is-${visible ? "good" : "muted"}`}>
                        {visible ? "disclosed" : "withheld"}
                      </span>
                    </div>
                  </div>
                );
              })}

              {/* Proof footer */}
              <div className="disclosure-proof-footer">
                <span className="status-pill is-good">proof valid</span>
                <span className="disclosure-proof-note">
                  Merkle inclusion proof verifies even with redacted content
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
