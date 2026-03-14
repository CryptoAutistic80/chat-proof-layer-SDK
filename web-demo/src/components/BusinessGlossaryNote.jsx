import React from "react";
import { GLOSSARY } from "../lib/glossary";

export function BusinessGlossaryNote() {
  return (
    <section className="panel glossary-panel">
      <div className="panel-head compact">
        <div>
          <span className="section-label">Glossary</span>
          <h2>Business labels vs technical labels</h2>
        </div>
      </div>
      <div className="glossary-grid">
        {GLOSSARY.map((term) => (
          <article key={term.technicalLabel} className="glossary-card">
            <strong>{term.businessLabel}</strong>
            <span>{term.technicalLabel}</span>
            <p>{term.explanation}</p>
          </article>
        ))}
      </div>
    </section>
  );
}
