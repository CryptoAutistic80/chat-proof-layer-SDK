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
          <span>Capture, seal, verify, and share AI proof records.</span>
        </div>
        <span>Supports both live provider runs and presentation-safe sample runs.</span>
      </footer>
    </div>
  );
}
