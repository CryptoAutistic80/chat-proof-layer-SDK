import React from "react";

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

export function DataPanel({ title, subtitle, value, placeholder, className = "", preClassName = "" }) {
  return (
    <section className={`data-panel ${className}`.trim()}>
      <div className="data-panel-head">
        <h3>{title}</h3>
        {subtitle ? <span>{subtitle}</span> : null}
      </div>
      <pre className={preClassName}>{value !== null && value !== undefined ? prettyJson(value) : placeholder}</pre>
    </section>
  );
}
