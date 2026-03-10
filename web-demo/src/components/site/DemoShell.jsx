import React from "react";
import { Outlet } from "react-router-dom";
import { useDemo } from "../../app/DemoContext";
import { ActivityFeed } from "../ActivityFeed";
import { RunSummaryCard } from "../RunSummaryCard";

export function DemoShell() {
  const { currentRun, currentPreset, activityLog } = useDemo();

  return (
    <div className="demo-layout">
      <div className="demo-main">
        <Outlet />
      </div>
      <aside className="demo-rail">
        <RunSummaryCard run={currentRun} preset={currentPreset} />
        <ActivityFeed activityLog={activityLog} />
      </aside>
    </div>
  );
}

