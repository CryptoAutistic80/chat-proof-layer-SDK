import React from "react";
import { NavLink } from "react-router-dom";
import { DOC_PAGES, DOC_SECTIONS } from "../../lib/docsContent";

export function DocsSidebar() {
  return (
    <aside className="docs-sidebar">
      <span className="section-label">Docs</span>
      <h2>Documentation</h2>
      <div className="docs-sidebar-groups">
        {DOC_SECTIONS.map((group) => (
          <section key={group.key}>
            <strong>{group.label}</strong>
            <div className="docs-sidebar-links">
              {group.pages.map((slug) => (
                <NavLink
                  key={slug}
                  to={`/docs/${slug}`}
                  className={({ isActive }) => `docs-link ${isActive ? "is-active" : ""}`}
                >
                  {DOC_PAGES[slug].title}
                </NavLink>
              ))}
            </div>
          </section>
        ))}
      </div>
    </aside>
  );
}

