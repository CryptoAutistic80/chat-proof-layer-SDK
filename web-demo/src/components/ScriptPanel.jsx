import React from "react";

export function ScriptPanel({ scenario, scriptSource }) {
  return (
    <section className="panel script-panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Script</span>
          <h3>Prefab example source</h3>
        </div>
        <span className="code-source">{scenario.sourceRef}</span>
      </div>
      <pre className="script-block">
        <code>{scriptSource}</code>
      </pre>
    </section>
  );
}
