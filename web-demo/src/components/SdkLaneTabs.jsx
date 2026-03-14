import React from "react";

export function SdkLaneTabs({ lanes, activeLane, laneCounts = {}, onSelect }) {
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
          <div className="sdk-lane-tab-top">
            <span className="section-label">{lane.eyebrow}</span>
            <span className="sdk-lane-count">{laneCounts[lane.id] ?? 0} examples</span>
          </div>
          <strong>{lane.label}</strong>
          <span>{lane.description}</span>
        </button>
      ))}
    </div>
  );
}
