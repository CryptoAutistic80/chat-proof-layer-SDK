import React from "react";
import { Outlet } from "react-router-dom";
import { DocsSidebar } from "./DocsSidebar";

export function DocsShell() {
  return (
    <div className="docs-layout">
      <DocsSidebar />
      <div className="docs-main">
        <Outlet />
      </div>
    </div>
  );
}

