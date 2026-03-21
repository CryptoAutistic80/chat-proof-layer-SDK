import React from "react";
import { Link } from "react-router-dom";
import { HeroDemo } from "../components/HeroDemo";
import {
  AI_ACT_EXPECTATIONS,
  COMMON_WORKFLOWS,
  LEARN_HERO,
  LEGAL_BOUNDARY,
  LIMITS,
  RECORDED_ITEMS,
  WORKFLOW_STEPS
} from "../lib/siteContent";

export function HomePage() {
  return (
    <section className="page-stack learn-page">
      <section className="panel learn-hero">
        <div className="learn-hero-copy">
          <span className="section-label">{LEARN_HERO.eyebrow}</span>
          <h1>{LEARN_HERO.title}</h1>
          <p className="learn-lead">{LEARN_HERO.summary}</p>
          <div className="cta-row">
            <Link className="primary-cta" to={LEARN_HERO.primaryCta.to}>
              {LEARN_HERO.primaryCta.label}
            </Link>
            <Link className="secondary-cta" to={LEARN_HERO.secondaryCta.to}>
              {LEARN_HERO.secondaryCta.label}
            </Link>
            <Link className="secondary-cta" to="/verify">
              Try the tamper playground
            </Link>
          </div>
        </div>
        <aside className="learn-hero-side">
          <span className="section-label">Boundary</span>
          <p>{LEGAL_BOUNDARY}</p>
        </aside>
      </section>

      {/* Interactive hero demo — runs entirely in the browser */}
      <section className="panel section-panel hero-demo-section">
        <HeroDemo />
      </section>

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">EU AI Act in practice</span>
            <h2>What most teams need in plain English</h2>
          </div>
        </div>
        <div className="learn-card-grid">
          {AI_ACT_EXPECTATIONS.map((item) => (
            <article key={item.title} className="learn-card">
              <strong>{item.title}</strong>
              <p>{item.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Workflow fit</span>
            <h2>Where Proof Layer fits in an AI workflow</h2>
          </div>
        </div>
        <ol className="workflow-steps">
          {WORKFLOW_STEPS.map((step, index) => (
            <li key={step.title} className="workflow-step">
              <span className="workflow-step-number">0{index + 1}</span>
              <div>
                <strong>{step.title}</strong>
                <p>{step.body}</p>
              </div>
            </li>
          ))}
        </ol>
      </section>

      <div className="learn-split-grid">
        <section className="panel section-panel">
          <div className="panel-head compact">
            <div>
              <span className="section-label">What gets recorded</span>
              <h2>Evidence you can inspect later</h2>
            </div>
          </div>
          <ul className="plain-list">
            {RECORDED_ITEMS.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>

        <section className="panel section-panel">
          <div className="panel-head compact">
            <div>
              <span className="section-label">What it does not do</span>
              <h2>Important limits</h2>
            </div>
          </div>
          <ul className="plain-list">
            {LIMITS.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        </section>
      </div>

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Common developer workflows</span>
            <h2>What you can try in the playground</h2>
          </div>
          <Link className="secondary-cta" to="/playground">
            Open playground
          </Link>
        </div>
        <div className="learn-card-grid">
          {COMMON_WORKFLOWS.map((workflow) => (
            <article key={workflow.slug} className="learn-card">
              <strong>{workflow.title}</strong>
              <p>{workflow.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="panel legal-boundary-panel">
        <span className="section-label">Important note</span>
        <p>{LEGAL_BOUNDARY}</p>
      </section>
    </section>
  );
}
