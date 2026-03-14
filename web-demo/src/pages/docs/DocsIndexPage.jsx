import React from "react";
import { Link } from "react-router-dom";
import { DOC_SECTIONS, DOC_PAGES } from "../../lib/docsContent";

export function DocsIndexPage() {
  return (
    <section className="page-stack">
      <section className="panel section-panel">
        <div className="panel-head compact">
          <div>
            <span className="section-label">Docs</span>
            <h1>Start with the path that fits your role</h1>
          </div>
        </div>
        <p className="section-intro">
          These docs explain the product, the guided demo, and the operational setup without
          assuming deep proof-system knowledge up front.
        </p>
      </section>

      <div className="docs-index-grid">
        {DOC_SECTIONS.map((group) => (
          <article key={group.key} className="panel docs-index-card">
            <span className="section-label">{group.label}</span>
            <h2>{group.label}</h2>
            <div className="docs-index-links">
              {group.pages.map((slug) => (
                <Link key={slug} to={`/docs/${slug}`} className="text-link">
                  {DOC_PAGES[slug].title}
                </Link>
              ))}
            </div>
          </article>
        ))}
      </div>
    </section>
  );
}

