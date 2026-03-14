import React from "react";

export function TechnicalDetailsAccordion({ title, subtitle, children, defaultOpen = false }) {
  return (
    <details className="technical-accordion" open={defaultOpen}>
      <summary>
        <span>{title}</span>
        {subtitle ? <small>{subtitle}</small> : null}
      </summary>
      <div className="technical-accordion-body">{children}</div>
    </details>
  );
}
