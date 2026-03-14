import React from "react";
import { Outlet } from "react-router-dom";
import { SiteNav } from "./SiteNav";

export function SiteShell() {
  return (
    <div className="site-shell">
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />
      <SiteNav />
      <main className="site-main">
        <Outlet />
      </main>
      <footer className="site-footer">
        <div>
          <strong>Proof Layer</strong>
          <span>Capture, inspect, verify, and share AI evidence records.</span>
        </div>
        <span>Developer playground for understanding EU AI Act evidence workflows in plain English.</span>
      </footer>
    </div>
  );
}
