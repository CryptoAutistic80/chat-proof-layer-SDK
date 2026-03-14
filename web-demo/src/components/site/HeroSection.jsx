import React from "react";
import { Link } from "react-router-dom";

export function HeroSection({ hero }) {
  return (
    <section className="hero hero-landing">
      <div className="hero-copy panel">
        <span className="eyebrow">{hero.eyebrow}</span>
        <h1>{hero.title}</h1>
        <p>{hero.summary}</p>
        <div className="cta-row">
          <Link className="primary-cta" to={hero.primaryCta.to}>
            {hero.primaryCta.label}
          </Link>
          <Link className="secondary-cta" to={hero.secondaryCta.to}>
            {hero.secondaryCta.label}
          </Link>
        </div>
      </div>
      <div className="hero-summary hero-landing-summary">
        <div>
          <strong>For</strong>
          <span>Business owners, operators, compliance teams, and technical evaluators.</span>
        </div>
        <div>
          <strong>What it creates</strong>
          <span>One proof record per run, with controlled disclosure and export options.</span>
        </div>
        <div>
          <strong>What it avoids</strong>
          <span>Ordinary logs, screenshots, and unstructured evidence dumps.</span>
        </div>
      </div>
    </section>
  );
}

