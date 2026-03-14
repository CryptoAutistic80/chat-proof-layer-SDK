import React from "react";
import { Link } from "react-router-dom";
import { BusinessGlossaryNote } from "../components/BusinessGlossaryNote";
import { FeatureSteps } from "../components/site/FeatureSteps";
import { FEATURE_STEPS, PRODUCT_SECTIONS } from "../lib/siteContent";

export function ProductPage() {
  return (
    <section className="page-stack">
      <section className="panel section-panel">
        <div className="panel-head">
          <div>
            <span className="section-label">Product</span>
            <h1>One product surface for capture, proof, review, and sharing</h1>
          </div>
          <Link className="primary-cta" to="/guided">
            Try guided demo
          </Link>
        </div>
        <div className="product-grid">
          {PRODUCT_SECTIONS.map((section) => (
            <article key={section.title} className="feature-note">
              <strong>{section.title}</strong>
              <p>{section.body}</p>
            </article>
          ))}
        </div>
      </section>

      <FeatureSteps items={FEATURE_STEPS} />
      <BusinessGlossaryNote />
    </section>
  );
}

