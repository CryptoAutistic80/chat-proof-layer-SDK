import React from "react";

function AssuranceOptionCard({ label, description, enabled, onToggle }) {
  return (
    <button
      type="button"
      className={`assurance-option-card ${enabled ? "is-enabled" : "is-disabled"}`}
      onClick={onToggle}
      aria-pressed={enabled}
    >
      <span className="assurance-option-eyebrow">{enabled ? "On" : "Off"}</span>
      <strong>{label}</strong>
      <span>{description}</span>
    </button>
  );
}

export function AssuranceOptionToggles({
  attachTimestamp,
  attachTransparency,
  onChange,
}) {
  return (
    <div className="assurance-option-grid" aria-label="Extra proof options">
      <AssuranceOptionCard
        label="Add timestamp proof"
        description="Ask the vault to attach a trusted time record after sealing."
        enabled={attachTimestamp}
        onToggle={() => onChange("attachTimestamp", !attachTimestamp)}
      />
      <AssuranceOptionCard
        label="Add transparency log"
        description="Anchor the proof in an outside log after timestamping."
        enabled={attachTransparency}
        onToggle={() => onChange("attachTransparency", !attachTransparency)}
      />
    </div>
  );
}
