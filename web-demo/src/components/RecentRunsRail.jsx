import React from "react";
import { NavLink } from "react-router-dom";

export function RecentRunsRail({ runs }) {
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Recent runs</span>
          <h2>Current system</h2>
        </div>
      </div>
      {runs.length === 0 ? (
        <p className="empty-copy">Seal a bundle to populate recent runs for this system.</p>
      ) : (
        <ul className="recent-runs">
          {runs.map((run) => (
            <li key={run.bundle_id}>
              <div>
                <strong>{run.bundle_id}</strong>
                <span>{run.actor_role} · {run.assurance_level}</span>
              </div>
              <div className="recent-run-links">
                <NavLink to={`/results/${run.bundle_id}`}>Results</NavLink>
                <NavLink to={`/examination/${run.bundle_id}`}>Examination</NavLink>
                <NavLink to={`/exports/${run.bundle_id}`}>Exports</NavLink>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
