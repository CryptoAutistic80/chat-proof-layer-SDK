import React from "react";
import { getDocNeighbors, getDocPage } from "../../lib/docsContent";
import { DocsArticle } from "../../components/site/DocsArticle";

export function DocsContentPage({ slug }) {
  const page = getDocPage(slug);
  const neighbors = getDocNeighbors(slug);
  const previous = neighbors.previous
    ? { slug: neighbors.previous, title: getDocPage(neighbors.previous).title }
    : null;
  const next = neighbors.next ? { slug: neighbors.next, title: getDocPage(neighbors.next).title } : null;

  return <DocsArticle page={page} previous={previous} next={next} />;
}
