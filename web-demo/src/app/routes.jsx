import React from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "../components/AppShell";
import { ExaminationPage } from "../pages/ExaminationPage";
import { ExportsPage } from "../pages/ExportsPage";
import { PlaygroundPage } from "../pages/PlaygroundPage";
import { ResultsPage } from "../pages/ResultsPage";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<Navigate to="/playground" replace />} />
      <Route element={<AppShell />}>
        <Route path="/playground" element={<PlaygroundPage />} />
        <Route path="/results" element={<ResultsPage />} />
        <Route path="/results/:bundleId" element={<ResultsPage />} />
        <Route path="/examination" element={<ExaminationPage />} />
        <Route path="/examination/:bundleId" element={<ExaminationPage />} />
        <Route path="/exports" element={<ExportsPage />} />
        <Route path="/exports/:bundleId" element={<ExportsPage />} />
      </Route>
    </Routes>
  );
}
