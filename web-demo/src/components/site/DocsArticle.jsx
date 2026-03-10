import React from "react";
import { Link } from "react-router-dom";

export function DocsArticle({ page, previous, next }) {
  return (
    <article className="docs-article panel">
      <div className="docs-meta">
        <span className="section-label">Docs</span>
        <span className="audience-tag">{page.audience.join(" · ")}</span>
      </div>
      <h1>{page.title}</h1>
      <p className="docs-intro">{page.intro}</p>
      <div className="docs-stack">
        {page.blocks.map((block) => (
          <section key={block.heading} className="docs-block">
            <h2>{block.heading}</h2>
            {block.body.map((paragraph) => (
              <p key={paragraph}>{paragraph}</p>
            ))}
          </section>
        ))}
      </div>
      <footer className="docs-footer-nav">
        {previous ? <Link to={`/docs/${previous.slug}`}>← {previous.title}</Link> : <span />}
        {next ? <Link to={`/docs/${next.slug}`}>{next.title} →</Link> : null}
      </footer>
    </article>
  );
}

