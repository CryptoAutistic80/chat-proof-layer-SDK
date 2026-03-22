import React from "react";
import { buildRunNarrativeSummary } from "../lib/narrative";

export function AssuranceStatusCard({ run, vaultConfig }) {
  const summary = buildRunNarrativeSummary(run, vaultConfig);
  const cards = [
    { key: "integrity", label: "Integrity check", status: summary.integrityStatus },
    { key: "timestamp", label: "Timestamp status", status: summary.timestampStatus },
    {
      key: "transparency",
      label: "Transparency status",
      status: summary.transparencyStatus,
    },
  ];

  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Assurance</span>
          <h2>What a reviewer can verify</h2>
        </div>
      </div>
      <div className="status-stack">
        {cards.map((card) => (
          <article key={card.key} className={`status-card is-${card.status.tone}`}>
            <strong>{card.label}</strong>
            <p>
              <strong>{card.status.title}.</strong> {card.status.summary}
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}
