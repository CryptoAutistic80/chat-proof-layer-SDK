import React from "react";

const VIEWS = [
  { id: "captured", label: "Captured" },
  { id: "proof", label: "Proof" },
  { id: "share", label: "Share" }
];

export function RecordExplorerTabs({ activeView, onChange }) {
  return (
    <div className="record-tabs" role="tablist" aria-label="Record explorer tabs">
      {VIEWS.map((view) => (
        <button
          key={view.id}
          type="button"
          role="tab"
          aria-selected={activeView === view.id}
          className={`toggle-pill ${activeView === view.id ? "is-active" : ""}`}
          onClick={() => onChange(view.id)}
        >
          {view.label}
        </button>
      ))}
    </div>
  );
}
