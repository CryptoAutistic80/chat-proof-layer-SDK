import React from "react";

function ActivityRow({ entry }) {
  return (
    <li className={`activity-row is-${entry.tone}`}>
      <div>
        <strong>{entry.title}</strong>
        <span>{entry.detail}</span>
      </div>
      <time>{entry.time}</time>
    </li>
  );
}

export function ActivityFeed({ activityLog }) {
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Activity</span>
          <h2>Recent actions</h2>
        </div>
      </div>
      <ul className="activity-list">
        {activityLog.length > 0 ? (
          activityLog.map((entry, index) => (
            <ActivityRow key={`${entry.time}-${index}`} entry={entry} />
          ))
        ) : (
          <li className="activity-empty">Run the workflow to populate this audit-style feed.</li>
        )}
      </ul>
    </section>
  );
}
