import React from "react";

export function SdkLaneTabs({ lanes, activeLane, onSelect }) {
  return (
    <div className="sdk-lane-tabs" role="tablist" aria-label="SDK lanes">
      {lanes.map((lane) => (
        <button
          key={lane.id}
          type="button"
          role="tab"
          aria-selected={activeLane === lane.id}
          className={`sdk-lane-tab ${activeLane === lane.id ? "is-active" : ""}`}
          onClick={() => onSelect(lane.id)}
        >
          <span className="section-label">{lane.eyebrow}</span>
          <strong>{lane.label}</strong>
          <span>{lane.description}</span>
        </button>
      ))}
    </div>
  );
}
