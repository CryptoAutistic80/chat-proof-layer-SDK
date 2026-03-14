import React from "react";

export function StatusExplainCard({ status }) {
  return (
    <article className={`status-card is-${status.tone}`}>
      <strong>{status.title}</strong>
      <p>{status.summary}</p>
    </article>
  );
}

