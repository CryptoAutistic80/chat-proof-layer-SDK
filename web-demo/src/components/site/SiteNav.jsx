import React from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useDemo } from "../../app/DemoContext";
import { humanCaptureMode } from "../../lib/narrative";

function linkClass(active) {
  return `site-nav-link ${active ? "is-active" : ""}`;
}

function isDemoRoute(pathname) {
  return (
    pathname.startsWith("/guided") ||
    pathname.startsWith("/what-happened") ||
    pathname.startsWith("/what-you-can-prove") ||
    pathname.startsWith("/what-you-can-share") ||
    pathname.startsWith("/playground") ||
    pathname.startsWith("/results") ||
    pathname.startsWith("/examination") ||
    pathname.startsWith("/exports")
  );
}

export function SiteNav() {
  const location = useLocation();
  const { currentRun } = useDemo();
  const pathname = location.pathname;
  const demoBundleSuffix = currentRun?.bundleId ? `/${currentRun.bundleId}` : "";

  return (
    <header className="site-header">
      <NavLink to="/" className="site-brand">
        <span className="site-brand-mark">PL</span>
        <span className="site-brand-copy">
          <strong>Proof Layer</strong>
          <span>AI proof records for real-world review</span>
        </span>
      </NavLink>

      <nav className="site-nav" aria-label="Primary">
        <NavLink to="/product" className={linkClass(pathname === "/" || pathname.startsWith("/product"))}>
          Product
        </NavLink>
        <NavLink to="/use-cases" className={linkClass(pathname.startsWith("/use-cases"))}>
          Use Cases
        </NavLink>
        <NavLink
          to="/guided"
          className={linkClass(
            pathname.startsWith("/guided") ||
              pathname.startsWith("/what-happened") ||
              pathname.startsWith("/what-you-can-prove") ||
              pathname.startsWith("/what-you-can-share")
          )}
        >
          Guided Demo
        </NavLink>
        <NavLink to="/playground" className={linkClass(pathname.startsWith("/playground"))}>
          Playground
        </NavLink>
        <NavLink to="/docs" className={linkClass(pathname.startsWith("/docs"))}>
          Docs
        </NavLink>
      </nav>

      <div className="site-nav-status">
        <span className="status-kicker">Capture mode</span>
        <strong>{humanCaptureMode(currentRun?.captureMode)}</strong>
      </div>

      {isDemoRoute(pathname) ? (
        <nav className="demo-subnav" aria-label="Demo">
          <NavLink to="/guided" className={linkClass(pathname.startsWith("/guided"))}>
            Guided Demo
          </NavLink>
          <NavLink
            to={`/what-happened${demoBundleSuffix}`}
            className={linkClass(pathname.startsWith("/what-happened") || pathname.startsWith("/results"))}
          >
            What Happened
          </NavLink>
          <NavLink
            to={`/what-you-can-prove${demoBundleSuffix}`}
            className={linkClass(
              pathname.startsWith("/what-you-can-prove") || pathname.startsWith("/examination")
            )}
          >
            What You Can Prove
          </NavLink>
          <NavLink
            to={`/what-you-can-share${demoBundleSuffix}`}
            className={linkClass(
              pathname.startsWith("/what-you-can-share") || pathname.startsWith("/exports")
            )}
          >
            What You Can Share
          </NavLink>
          <NavLink to="/playground" className={linkClass(pathname.startsWith("/playground"))}>
            SDK Playground
          </NavLink>
        </nav>
      ) : null}
    </header>
  );
}
