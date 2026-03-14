import React from "react";
import { Link } from "react-router-dom";

export function UseCaseCard({ useCase }) {
  return (
    <article className="use-case-card panel">
      <span className="section-label">Use case</span>
      <h2>{useCase.title}</h2>
      <p>{useCase.problem}</p>
      <dl className="use-case-details">
        <div>
          <dt>Capture</dt>
          <dd>{useCase.capture}</dd>
        </div>
        <div>
          <dt>Prove</dt>
          <dd>{useCase.prove}</dd>
        </div>
        <div>
          <dt>Share</dt>
          <dd>{useCase.share}</dd>
        </div>
      </dl>
      <Link className="text-link" to={useCase.ctaTo}>
        {useCase.ctaLabel}
      </Link>
    </article>
  );
}

