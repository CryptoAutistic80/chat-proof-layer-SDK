import React from "react";
import { Outlet } from "react-router-dom";

export function DemoShell() {
  return (
    <div className="demo-main demo-main-studio">
      <Outlet />
    </div>
  );
}
