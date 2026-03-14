import React from "react";

export function ScriptPanel({ scenario, scriptSource }) {
  return (
    <section className="panel script-panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Script</span>
          <h3>Prefab example source</h3>
        </div>
        <div className="script-panel-meta">
          <span className="script-language">{scenario.codeLanguage}</span>
          <span className="code-source">{scenario.sourceRef}</span>
        </div>
      </div>
      <p className="field-hint script-note">
        Read-only generated from the maintained example template for this workflow so the code and
        the resulting evidence stay in sync.
      </p>
      <pre className="script-block">
        <code>{scriptSource}</code>
      </pre>
    </section>
  );
}
