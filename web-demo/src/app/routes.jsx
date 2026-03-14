import React from "react";
import { Navigate, Route, Routes, useParams } from "react-router-dom";
import { SiteShell } from "../components/site/SiteShell";
import { DemoShell } from "../components/site/DemoShell";
import { HomePage } from "../pages/HomePage";
import { SDKPlaygroundPage } from "../pages/SDKPlaygroundPage";
import { AdvancedPlaygroundPage } from "../pages/AdvancedPlaygroundPage";
import { RecordsExplorerPage } from "../pages/RecordsExplorerPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<SiteShell />}>
        <Route path="/" element={<HomePage />} />

        <Route element={<DemoShell />}>
          <Route path="/playground" element={<SDKPlaygroundPage />} />
          <Route path="/playground/advanced" element={<AdvancedPlaygroundPage />} />
          <Route path="/records" element={<RecordsExplorerPage />} />
          <Route path="/records/:bundleId" element={<RecordsExplorerPage />} />
        </Route>

        <Route path="/guided" element={<Navigate to="/playground" replace />} />
        <Route path="/product" element={<Navigate to="/" replace />} />
        <Route path="/use-cases" element={<Navigate to="/" replace />} />
        <Route path="/docs" element={<Navigate to="/" replace />} />
        <Route path="/docs/*" element={<Navigate to="/" replace />} />

        <Route path="/results" element={<Navigate to="/records?view=captured" replace />} />
        <Route path="/results/:bundleId" element={<LegacyRecordsRedirect view="captured" />} />
        <Route path="/examination" element={<Navigate to="/records?view=proof" replace />} />
        <Route path="/examination/:bundleId" element={<LegacyRecordsRedirect view="proof" />} />
        <Route path="/exports" element={<Navigate to="/records?view=share" replace />} />
        <Route path="/exports/:bundleId" element={<LegacyRecordsRedirect view="share" />} />

        <Route path="/what-happened" element={<Navigate to="/records?view=captured" replace />} />
        <Route path="/what-happened/:bundleId" element={<LegacyRecordsRedirect view="captured" />} />
        <Route path="/what-you-can-prove" element={<Navigate to="/records?view=proof" replace />} />
        <Route path="/what-you-can-prove/:bundleId" element={<LegacyRecordsRedirect view="proof" />} />
        <Route path="/what-you-can-share" element={<Navigate to="/records?view=share" replace />} />
        <Route path="/what-you-can-share/:bundleId" element={<LegacyRecordsRedirect view="share" />} />
      </Route>
    </Routes>
  );
}

function LegacyRecordsRedirect({ view }) {
  const { bundleId } = useParams();
  return <Navigate to={bundleId ? `/records/${bundleId}?view=${view}` : `/records?view=${view}`} replace />;
}
