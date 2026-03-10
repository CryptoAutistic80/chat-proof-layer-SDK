import React from "react";

export function FeatureSteps({ items }) {
  return (
    <section className="feature-steps">
      {items.map((item, index) => (
        <article key={item.title} className="feature-step panel">
          <span className="step-index">0{index + 1}</span>
          <h2>{item.title}</h2>
          <p>{item.body}</p>
        </article>
      ))}
    </section>
  );
}

