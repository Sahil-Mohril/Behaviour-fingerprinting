import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import "./index.css";
import { Layout } from "./components/Layout";
import { LiveProvider } from "./lib/store";
import ReplayPage from "./pages/Replay";
import OverviewPage from "./pages/Overview";
import FingerprintsPage from "./pages/Fingerprints";
import AlertsPage from "./pages/Alerts";
import RulesPage from "./pages/Rules";
import EvaluationPage from "./pages/Evaluation";
import SettingsPage from "./pages/Settings";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <LiveProvider>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            <Route index element={<ReplayPage />} />
            <Route path="overview" element={<OverviewPage />} />
            <Route path="fingerprints" element={<FingerprintsPage />} />
            <Route path="fingerprints/:id" element={<FingerprintsPage />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="rules" element={<RulesPage />} />
            <Route path="evaluation" element={<EvaluationPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </LiveProvider>
  </React.StrictMode>,
);
