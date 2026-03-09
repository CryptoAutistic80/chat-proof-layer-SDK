import React from "react";

function prettyJson(value) {
  return JSON.stringify(value, null, 2);
}

export function DataPanel({ title, subtitle, value, placeholder }) {
  return (
    <section className="data-panel">
      <div className="data-panel-head">
        <h3>{title}</h3>
        {subtitle ? <span>{subtitle}</span> : null}
      </div>
      <pre>{value !== null && value !== undefined ? prettyJson(value) : placeholder}</pre>
    </section>
  );
}
