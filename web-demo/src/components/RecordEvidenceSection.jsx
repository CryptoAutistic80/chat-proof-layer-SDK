import React from "react";

export function RecordEvidenceSection({ title, intro, cards }) {
  return (
    <section className="panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Record view</span>
          <h2>{title}</h2>
        </div>
      </div>
      <p className="section-intro">{intro}</p>
      <div className="learn-card-grid record-evidence-grid">
        {cards.map((card) => (
          <article key={card.title} className="learn-card">
            <strong>{card.title}</strong>
            <p>{card.body}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
