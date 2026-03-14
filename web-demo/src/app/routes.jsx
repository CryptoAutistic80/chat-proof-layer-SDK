import React from "react";
import { Navigate, Route, Routes, useParams } from "react-router-dom";
import { SiteShell } from "../components/site/SiteShell";
import { DemoShell } from "../components/site/DemoShell";
import { DocsShell } from "../components/site/DocsShell";
import { HomePage } from "../pages/HomePage";
import { ProductPage } from "../pages/ProductPage";
import { UseCasesPage } from "../pages/UseCasesPage";
import { GuidedDemoPage } from "../pages/GuidedDemoPage";
import { SDKPlaygroundPage } from "../pages/SDKPlaygroundPage";
import { AdvancedPlaygroundPage } from "../pages/AdvancedPlaygroundPage";
import { WhatHappenedPage } from "../pages/WhatHappenedPage";
import { WhatYouCanProvePage } from "../pages/WhatYouCanProvePage";
import { WhatYouCanSharePage } from "../pages/WhatYouCanSharePage";
import { DocsIndexPage } from "../pages/docs/DocsIndexPage";
import { DocsContentPage } from "../pages/docs/DocsContentPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route element={<SiteShell />}>
        <Route path="/" element={<HomePage />} />
        <Route path="/product" element={<ProductPage />} />
        <Route path="/use-cases" element={<UseCasesPage />} />

        <Route element={<DemoShell />}>
          <Route path="/guided" element={<GuidedDemoPage />} />
          <Route path="/playground" element={<SDKPlaygroundPage />} />
          <Route path="/playground/advanced" element={<AdvancedPlaygroundPage />} />
          <Route path="/what-happened" element={<WhatHappenedPage />} />
          <Route path="/what-happened/:bundleId" element={<WhatHappenedPage />} />
          <Route path="/what-you-can-prove" element={<WhatYouCanProvePage />} />
          <Route path="/what-you-can-prove/:bundleId" element={<WhatYouCanProvePage />} />
          <Route path="/what-you-can-share" element={<WhatYouCanSharePage />} />
          <Route path="/what-you-can-share/:bundleId" element={<WhatYouCanSharePage />} />
        </Route>

        <Route element={<DocsShell />}>
          <Route path="/docs" element={<DocsIndexPage />} />
          <Route
            path="/docs/what-is-proof-layer"
            element={<DocsContentPage slug="what-is-proof-layer" />}
          />
          <Route path="/docs/how-it-works" element={<DocsContentPage slug="how-it-works" />} />
          <Route path="/docs/guided-demo" element={<DocsContentPage slug="guided-demo" />} />
          <Route path="/docs/playground" element={<DocsContentPage slug="playground" />} />
          <Route path="/docs/typescript-sdk" element={<DocsContentPage slug="typescript-sdk" />} />
          <Route path="/docs/python-sdk" element={<DocsContentPage slug="python-sdk" />} />
          <Route path="/docs/vault-setup" element={<DocsContentPage slug="vault-setup" />} />
          <Route
            path="/docs/backup-and-restore"
            element={<DocsContentPage slug="backup-and-restore" />}
          />
          <Route path="/docs/faq" element={<DocsContentPage slug="faq" />} />
        </Route>

        <Route path="/results" element={<Navigate to="/what-happened" replace />} />
        <Route
          path="/results/:bundleId"
          element={<RouteRedirect prefix="/what-happened" />}
        />
        <Route path="/examination" element={<Navigate to="/what-you-can-prove" replace />} />
        <Route
          path="/examination/:bundleId"
          element={<RouteRedirect prefix="/what-you-can-prove" />}
        />
        <Route path="/exports" element={<Navigate to="/what-you-can-share" replace />} />
        <Route
          path="/exports/:bundleId"
          element={<RouteRedirect prefix="/what-you-can-share" />}
        />
      </Route>
    </Routes>
  );
}

function RouteRedirect({ prefix }) {
  const { bundleId } = useParams();
  return <Navigate to={`${prefix}/${bundleId}`} replace />;
}
