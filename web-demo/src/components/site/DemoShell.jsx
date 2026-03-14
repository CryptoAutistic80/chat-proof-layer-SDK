import React from "react";
import { Outlet } from "react-router-dom";
import { useLocation } from "react-router-dom";
import { useDemo } from "../../app/DemoContext";
import { ActivityFeed } from "../ActivityFeed";
import { RunSummaryCard } from "../RunSummaryCard";

export function DemoShell() {
  const location = useLocation();
  const { currentRun, currentPreset, currentScenario, activityLog } = useDemo();
  const useScenarioSummary = location.pathname === "/playground";
  const useIntegratedPlayground = location.pathname === "/playground";

  if (useIntegratedPlayground) {
    return (
      <div className="demo-main demo-main-playground">
        <Outlet />
      </div>
    );
  }

  return (
    <div className="demo-layout">
      <div className="demo-main">
        <Outlet />
      </div>
      <aside className="demo-rail">
        <RunSummaryCard
          run={currentRun}
          preset={currentPreset}
          scenario={useScenarioSummary ? currentScenario : null}
        />
        <ActivityFeed activityLog={activityLog} />
      </aside>
    </div>
  );
}
