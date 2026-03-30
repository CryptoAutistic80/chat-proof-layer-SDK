import React from "react";
import { Link } from "react-router-dom";
import { LEGAL_BOUNDARY } from "../lib/siteContent";

export function HomePage() {
  return (
    <section className="page-stack learn-page">
      <section className="panel learn-hero">
        <div className="learn-hero-copy">
          <span className="section-label">Chatbot proof flows</span>
          <h1>Prove each conversation without slowing down your app team</h1>
          <p className="learn-lead">
            Run a chatbot interaction, seal it into a cryptographic bundle, then verify or selectively
            share the evidence later.
          </p>
          <div className="cta-row">
            <Link className="primary-cta" to="/chat-demo">
              Start chat demo
            </Link>
            <Link className="secondary-cta" to="/verify">
              Verify a proof
            </Link>
            <Link className="secondary-cta" to="/share">
              Share/export view
            </Link>
          </div>
        </div>
        <aside className="learn-hero-side">
          <span className="section-label">Boundary</span>
          <p>{LEGAL_BOUNDARY}</p>
        </aside>
      </section>

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">1 · What gets proven for each conversation</span>
            <h2>Each sealed run gets immutable conversation evidence</h2>
          </div>
        </div>
        <ul className="plain-list">
          <li>Prompt + response context bound to the same bundle root.</li>
          <li>Provider/model/session metadata for audit replay.</li>
          <li>Signature verification status and optional timestamp/transparency checks.</li>
        </ul>
      </section>

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">2 · How to verify later</span>
            <h2>Open verification tools anytime after sealing</h2>
          </div>
        </div>
        <p className="section-intro">
          Use the verify flow to inspect integrity, timestamp, and tamper-evidence details. You can
          validate immediately after sealing or revisit old bundle IDs from the records explorer.
        </p>
        <Link className="secondary-cta" to="/verify">
          Go to verification
        </Link>
      </section>

      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">3 · What can be selectively shared</span>
            <h2>Disclose only what each audience needs</h2>
          </div>
        </div>
        <p className="section-intro">
          Export a disclosure/share package and review exactly what items and artefacts are included.
          Keep the full record internal while sharing only the required subset.
        </p>
        <div className="cta-row">
          <Link className="secondary-cta" to="/share">
            Open share/export view
          </Link>
          <Link className="secondary-cta" to="/advanced">
            Advanced/legacy playground
          </Link>
        </div>
      </section>
    </section>
  );
}
