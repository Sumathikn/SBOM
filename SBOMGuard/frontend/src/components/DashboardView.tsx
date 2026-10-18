import React from "react";
import {
  ShieldAlert,
  Boxes,
  FileCheck2,
  TrendingDown,
  ArrowUpRight,
  PieChart,
  Activity,
  Layers,
  Flame,
  Download,
} from "lucide-react";
import { DashboardStats } from "../types";

interface DashboardProps {
  stats: DashboardStats | null;
  onNavigate: (view: string) => void;
}

export const DashboardView: React.FC<DashboardProps> = ({ stats, onNavigate }) => {
  if (!stats) {
    return (
      <div className="text-center py-20 text-slate-400 font-mono text-sm animate-pulse">
        Loading real-time security telemetry from PostgreSQL...
      </div>
    );
  }

  const exportReport = (format: "json" | "csv") => {
    let content = "";
    let mime = "";
    let filename = `sbomguard-telemetry-${new Date().toISOString().slice(0, 10)}`;

    if (format === "json") {
      content = JSON.stringify(stats, null, 2);
      mime = "application/json";
      filename += ".json";
    } else {
      content =
        "Metric,Value\n" +
        `Total SBOMs,${stats.total_sboms}\n` +
        `Total Dependencies,${stats.total_components}\n` +
        `Total Scans,${stats.total_scans}\n` +
        `Total Vulnerabilities,${stats.total_vulnerabilities}\n` +
        `Critical,${stats.critical_vulns}\n` +
        `High,${stats.high_vulns}\n` +
        `Medium,${stats.medium_vulns}\n` +
        `Low,${stats.low_vulns}\n` +
        `Average Risk Score,${stats.avg_risk_score}\n`;
      mime = "text/csv";
      filename += ".csv";
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
  };

  const totalDeps = (stats.dependency_ratio.direct || 0) + (stats.dependency_ratio.transitive || 0);
  const directPct = totalDeps > 0 ? Math.round((stats.dependency_ratio.direct / totalDeps) * 100) : 50;

  return (
    <div className="space-y-6">
      {/* Subheader & Export Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white">
            Supply Chain Security Analytics
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time vulnerability correlation, threat intelligence, and dependency governance.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => exportReport("csv")}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-slate-300 hover:text-white transition"
          >
            <Download className="w-3.5 h-3.5" />
            CSV Export
          </button>
          <button
            onClick={() => exportReport("json")}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-cyan-400 hover:border-cyan-500/50 transition"
          >
            <Download className="w-3.5 h-3.5" />
            JSON Telemetry
          </button>
        </div>
      </div>

      {/* Top Telemetry KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total SBOMs */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Cataloged SBOMs</span>
            <div className="p-2 rounded-xl bg-cyan-950/60 border border-cyan-800/50 text-cyan-400">
              <FileCheck2 className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-white font-mono">{stats.total_sboms}</span>
            <span className="text-[10px] font-semibold text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/40">
              Active Repos
            </span>
          </div>
        </div>

        {/* Total Components */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Dependencies Monitored</span>
            <div className="p-2 rounded-xl bg-blue-950/60 border border-blue-800/50 text-blue-400">
              <Boxes className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-white font-mono">{stats.total_components}</span>
            <span className="text-[10px] font-semibold text-blue-400 bg-blue-950/50 px-2 py-0.5 rounded border border-blue-800/40">
              Direct &amp; Transitive
            </span>
          </div>
        </div>

        {/* Total Vulnerabilities */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Known CVEs &amp; GHSA</span>
            <div className="p-2 rounded-xl bg-rose-950/60 border border-rose-800/50 text-rose-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-rose-400 font-mono">{stats.total_vulnerabilities}</span>
            <span className="text-[10px] font-semibold text-rose-400 bg-rose-950/50 px-2 py-0.5 rounded border border-rose-800/40">
              {stats.critical_vulns} Critical
            </span>
          </div>
        </div>

        {/* Composite Risk Score */}
        <div className="glass-card p-5 rounded-2xl border border-slate-800 space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-slate-400">Avg Risk Exposure</span>
            <div className="p-2 rounded-xl bg-amber-950/60 border border-amber-800/50 text-amber-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="flex items-baseline justify-between">
            <span className="text-2xl font-bold text-amber-400 font-mono">
              {stats.avg_risk_score} <span className="text-xs text-slate-500 font-normal">/ 100</span>
            </span>
            <span className="text-[10px] font-semibold text-amber-400 bg-amber-950/50 px-2 py-0.5 rounded border border-amber-800/40">
              Weighted EPSS
            </span>
          </div>
        </div>
      </div>

      {/* Main Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Severity Distribution Chart Tile */}
        <div className="lg:col-span-8 glass-card rounded-2xl p-6 border border-slate-800 space-y-5">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Vulnerability Severity Distribution
            </h3>
            <span className="text-xs text-slate-400 font-mono">
              Total Identified: {stats.total_vulnerabilities}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-900/60 space-y-1">
              <div className="text-[10px] font-bold text-rose-400 uppercase tracking-wider">CRITICAL</div>
              <div className="text-2xl font-extrabold text-rose-300 font-mono">{stats.critical_vulns}</div>
              <div className="text-[11px] text-slate-400">CVSS 9.0 - 10.0</div>
            </div>

            <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-900/60 space-y-1">
              <div className="text-[10px] font-bold text-amber-400 uppercase tracking-wider">HIGH</div>
              <div className="text-2xl font-extrabold text-amber-300 font-mono">{stats.high_vulns}</div>
              <div className="text-[11px] text-slate-400">CVSS 7.0 - 8.9</div>
            </div>

            <div className="p-4 rounded-xl bg-yellow-950/40 border border-yellow-900/60 space-y-1">
              <div className="text-[10px] font-bold text-yellow-400 uppercase tracking-wider">MEDIUM</div>
              <div className="text-2xl font-extrabold text-yellow-300 font-mono">{stats.medium_vulns}</div>
              <div className="text-[11px] text-slate-400">CVSS 4.0 - 6.9</div>
            </div>

            <div className="p-4 rounded-xl bg-blue-950/40 border border-blue-900/60 space-y-1">
              <div className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">LOW</div>
              <div className="text-2xl font-extrabold text-blue-300 font-mono">{stats.low_vulns}</div>
              <div className="text-[11px] text-slate-400">CVSS 0.1 - 3.9</div>
            </div>
          </div>

          {/* Progress Bar Visualization */}
          <div className="space-y-1.5 pt-2">
            <div className="h-3 w-full rounded-full bg-slate-900 overflow-hidden flex">
              <div
                style={{ width: `${stats.total_vulnerabilities > 0 ? (stats.critical_vulns / stats.total_vulnerabilities) * 100 : 0}%` }}
                className="bg-rose-500 h-full"
                title="Critical"
              />
              <div
                style={{ width: `${stats.total_vulnerabilities > 0 ? (stats.high_vulns / stats.total_vulnerabilities) * 100 : 0}%` }}
                className="bg-amber-500 h-full"
                title="High"
              />
              <div
                style={{ width: `${stats.total_vulnerabilities > 0 ? (stats.medium_vulns / stats.total_vulnerabilities) * 100 : 0}%` }}
                className="bg-yellow-500 h-full"
                title="Medium"
              />
              <div
                style={{ width: `${stats.total_vulnerabilities > 0 ? (stats.low_vulns / stats.total_vulnerabilities) * 100 : 0}%` }}
                className="bg-blue-500 h-full"
                title="Low"
              />
            </div>
          </div>
        </div>

        {/* Ecosystem & Dependency Ratio Tile */}
        <div className="lg:col-span-4 glass-card rounded-2xl p-6 border border-slate-800 space-y-5">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Layers className="w-4 h-4 text-purple-400" />
            Supply Chain Structure
          </h3>

          {/* Direct vs Transitive Gauge */}
          <div className="space-y-2">
            <div className="flex justify-between text-xs">
              <span className="text-slate-400">Direct ({stats.dependency_ratio.direct})</span>
              <span className="text-slate-400">Transitive ({stats.dependency_ratio.transitive})</span>
            </div>
            <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden flex">
              <div style={{ width: `${directPct}%` }} className="bg-cyan-500 h-full" />
              <div style={{ width: `${100 - directPct}%` }} className="bg-purple-500 h-full" />
            </div>
          </div>

          {/* Ecosystems List */}
          <div className="space-y-2.5 pt-2 border-t border-slate-800">
            <span className="text-xs font-semibold text-slate-400 block">Package Registries</span>
            {Object.entries(stats.ecosystem_distribution).map(([eco, count], idx) => (
              <div key={idx} className="flex items-center justify-between text-xs font-mono">
                <span className="capitalize text-slate-300">{eco}</span>
                <span className="font-bold text-cyan-400">{count} packages</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Top Vulnerable Components & Quick Action to Remediation */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-500" />
            Highest Priority Vulnerable Dependencies
          </h3>
          <button
            onClick={() => onNavigate("remediation")}
            className="text-xs text-purple-400 hover:text-purple-300 flex items-center gap-1 font-semibold"
          >
            Open Remediation Center <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-mono text-[10px]">
              <tr>
                <th className="py-2.5 px-4">Component</th>
                <th className="py-2.5 px-4">Vulnerability Count</th>
                <th className="py-2.5 px-4">Max CVSS Score</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {stats.top_vulnerable_components.length > 0 ? (
                stats.top_vulnerable_components.map((c, i) => (
                  <tr key={i} className="hover:bg-slate-800/40">
                    <td className="py-3 px-4 font-bold text-white">{c.affected_component}</td>
                    <td className="py-3 px-4 text-rose-400 font-bold">{c.vuln_count} CVEs</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 font-bold">
                        {c.max_cvss}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => onNavigate("remediation")}
                        className="px-3 py-1 rounded-lg bg-purple-950/80 hover:bg-purple-900 border border-purple-800 text-purple-300 text-[11px] font-semibold transition"
                      >
                        Remediate
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={4} className="text-center py-6 text-slate-500">
                    No vulnerable components recorded.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
