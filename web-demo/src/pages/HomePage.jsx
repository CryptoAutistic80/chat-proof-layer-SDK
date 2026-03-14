import React from "react";
import { Link } from "react-router-dom";
import { BusinessGlossaryNote } from "../components/BusinessGlossaryNote";
import { FeatureSteps } from "../components/site/FeatureSteps";
import { HeroSection } from "../components/site/HeroSection";
import { UseCaseCard } from "../components/site/UseCaseCard";
import { FEATURE_STEPS, HOME_HERO, TRUST_STATEMENTS, USE_CASES, WHY_POINTS } from "../lib/siteContent";

export function HomePage() {
  return (
    <section className="page-stack">
      <HeroSection hero={HOME_HERO} />

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Why this exists</span>
            <h2>AI businesses need evidence, not just logs</h2>
          </div>
        </div>
        <div className="why-grid">
          {WHY_POINTS.map((point) => (
            <article key={point} className="feature-note">
              <p>{point}</p>
            </article>
          ))}
        </div>
      </section>

      <FeatureSteps items={FEATURE_STEPS} />

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Use cases</span>
            <h2>Start from a business question</h2>
          </div>
          <Link className="secondary-cta" to="/use-cases">
            View all use cases
          </Link>
        </div>
        <div className="use-cases-grid">
          {USE_CASES.slice(0, 4).map((useCase) => (
            <UseCaseCard key={useCase.slug} useCase={useCase} />
          ))}
        </div>
      </section>

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Trust statement</span>
            <h2>What this is not</h2>
          </div>
        </div>
        <div className="trust-grid">
          {TRUST_STATEMENTS.map((item) => (
            <article key={item} className="trust-card">
              <strong>{item}</strong>
            </article>
          ))}
        </div>
      </section>

      <BusinessGlossaryNote />
    </section>
  );
}

