import React from "react";
import { UseCaseCard } from "../components/site/UseCaseCard";
import { USE_CASES } from "../lib/siteContent";

export function UseCasesPage() {
  return (
    <section className="page-stack">
      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Use cases</span>
            <h1>Where a proof record helps in the real world</h1>
          </div>
        </div>
        <p className="section-intro">
          Each scenario starts with the same idea: capture one AI run, seal it, explain what can
          be proven later, and control what gets shared.
        </p>
      </section>

      <div className="use-cases-grid">
        {USE_CASES.map((useCase) => (
          <UseCaseCard key={useCase.slug} useCase={useCase} />
        ))}
      </div>
    </section>
  );
}

