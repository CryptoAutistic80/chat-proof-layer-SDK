import React from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useDemo } from "../../app/DemoContext";
import { humanCaptureMode } from "../../lib/narrative";

function linkClass(active) {
  return `site-nav-link ${active ? "is-active" : ""}`;
}

export function SiteNav() {
  const location = useLocation();
  const { currentRun } = useDemo();
  const pathname = location.pathname;
  const statusLabel = currentRun?.bundleId ? humanCaptureMode(currentRun.captureMode) : "Ready to run";

  return (
    <header className="site-header">
      <NavLink to="/" className="site-brand">
        <span className="site-brand-mark">PL</span>
        <span className="site-brand-copy">
          <strong>Proof Layer</strong>
          <span>Plain-English EU AI Act evidence demo for developers</span>
        </span>
      </NavLink>

      <nav className="site-nav" aria-label="Primary">
        <NavLink to="/" end className={linkClass(pathname === "/")}>
          Home
        </NavLink>
        <NavLink to="/chat-demo" className={linkClass(pathname === "/chat-demo")}>
          Chat demo
        </NavLink>
        <NavLink to="/verify" className={linkClass(pathname === "/verify")}>
          Verify
        </NavLink>
        <NavLink to="/share" className={linkClass(pathname === "/share" || pathname.startsWith("/records"))}>
          Share
        </NavLink>
        <NavLink to="/advanced" className={linkClass(pathname.startsWith("/advanced"))}>
          Advanced/legacy
        </NavLink>
      </nav>

      <div className="site-nav-status">
        <span className="status-kicker">Demo status</span>
        <strong>{statusLabel}</strong>
      </div>
    </header>
  );
}
