import React, { useState, useEffect } from "react";
import { Navbar } from "./components/Navbar";
import { Sidebar } from "./components/Sidebar";
import { DashboardView } from "./components/DashboardView";
import { GenerateView } from "./components/GenerateView";
import { SBOMRepositoryView } from "./components/SBOMRepositoryView";
import { ScanAuditView } from "./components/ScanAuditView";
import { DiffVisualizerView } from "./components/DiffVisualizerView";
import { RemediationGuidanceView } from "./components/RemediationGuidanceView";
import { DashboardStats, SBOM, ScanResult } from "./types";
import { api } from "./services/api";

export const App: React.FC = () => {
  const [activeView, setActiveView] = useState<string>("dashboard");
  const [darkMode, setDarkMode] = useState<boolean>(() => {
    const saved = localStorage.getItem("sbomguard_theme");
    return saved !== null ? saved === "dark" : true;
  });
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [sboms, setSboms] = useState<SBOM[]>([]);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [targetSbomId, setTargetSbomId] = useState<string | undefined>(undefined);

  // Sync dark mode class with root html and localStorage
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add("dark");
      localStorage.setItem("sbomguard_theme", "dark");
    } else {
      document.documentElement.classList.remove("dark");
      localStorage.setItem("sbomguard_theme", "light");
    }
  }, [darkMode]);

  // Initial data loading
  useEffect(() => {
    refreshAllData();
  }, []);

  const refreshAllData = async () => {
    setIsRefreshing(true);
    try {
      const [statsData, sbomsData, scansData] = await Promise.allSettled([
        api.getDashboardStats(),
        api.listSBOMs(),
        api.listScans(),
      ]);

      if (statsData.status === "fulfilled") setStats(statsData.value);
      if (sbomsData.status === "fulfilled") setSboms(sbomsData.value);
      if (scansData.status === "fulfilled") setScans(scansData.value);
    } catch (err) {
      console.error("Failed to fetch initial telemetry:", err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleNavigateToScan = (sbomId: string) => {
    setTargetSbomId(sbomId);
    setActiveView("scan");
  };

  const handleNavigateToDiff = (sbomA: string) => {
    setActiveView("diff");
  };

  const handleNavigateToRemediation = (scanId: string) => {
    setActiveView("remediation");
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-[#07090E] text-slate-800 dark:text-slate-100 flex flex-col relative selection:bg-cyan-500 selection:text-black transition-colors duration-200">
      {/* Background ambient lighting */}
      <div className="ambient-glow-1" />
      <div className="ambient-glow-2" />

      {/* Top Navbar */}
      <Navbar
        darkMode={darkMode}
        setDarkMode={setDarkMode}
        activeView={activeView}
        onRefresh={refreshAllData}
        isRefreshing={isRefreshing}
      />

      {/* Main Workspace layout */}
      <div className="flex-1 flex w-full relative z-10">
        <Sidebar activeView={activeView} setActiveView={setActiveView} />

        <main className="flex-1 p-6 lg:p-8 max-w-7xl mx-auto overflow-y-auto">
          {activeView === "dashboard" && (
            <DashboardView stats={stats} onNavigate={setActiveView} />
          )}

          {activeView === "generate" && (
            <GenerateView
              onSuccess={() => refreshAllData()}
              onNavigateToScan={handleNavigateToScan}
            />
          )}

          {activeView === "sboms" && (
            <SBOMRepositoryView
              sboms={sboms}
              onRefresh={refreshAllData}
              onNavigateToScan={handleNavigateToScan}
              onNavigateToDiff={handleNavigateToDiff}
            />
          )}

          {activeView === "scan" && (
            <ScanAuditView
              sboms={sboms}
              scans={scans}
              onScanCompleted={() => refreshAllData()}
              onNavigateToRemediation={handleNavigateToRemediation}
              targetSbomId={targetSbomId}
            />
          )}

          {activeView === "diff" && <DiffVisualizerView sboms={sboms} />}

          {activeView === "remediation" && (
            <RemediationGuidanceView scans={scans} />
          )}
        </main>
      </div>
    </div>
  );
};
