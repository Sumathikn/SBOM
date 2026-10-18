import React, { useState } from "react";
import {
  ShieldAlert,
  Play,
  AlertTriangle,
  Flame,
  CheckCircle2,
  Download,
  Filter,
  Wrench,
  Search,
} from "lucide-react";
import { SBOM, ScanResult } from "../types";
import { api } from "../services/api";

interface ScanAuditProps {
  sboms: SBOM[];
  scans: ScanResult[];
  onScanCompleted: (newScan: ScanResult) => void;
  onNavigateToRemediation: (scanId: string) => void;
  targetSbomId?: string;
}

export const ScanAuditView: React.FC<ScanAuditProps> = ({
  sboms,
  scans,
  onScanCompleted,
  onNavigateToRemediation,
  targetSbomId,
}) => {
  const [selectedSbomId, setSelectedSbomId] = useState<string>(targetSbomId || sboms[0]?.id || "");
  const [activeScan, setActiveScan] = useState<ScanResult | null>(scans[0] || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [searchTerm, setSearchTerm] = useState("");

  const handleTriggerScan = async () => {
    if (!selectedSbomId) {
      setError("Please select an SBOM to scan.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.scanSBOM(selectedSbomId);
      setActiveScan(res);
      onScanCompleted(res);
    } catch (err: any) {
      setError(err.message || "Scan failed.");
    } finally {
      setLoading(false);
    }
  };

  // Flatten all vulnerabilities from risk assessments for table
  const allVulns = activeScan
    ? (activeScan.risk_assessments || []).flatMap((ra: any) => ra.vulnerabilities || [])
    : [];

  const filteredVulns = allVulns.filter((v: any) => {
    const matchesSev = severityFilter === "all" || v.severity === severityFilter;
    const matchesSearch =
      (v.id || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (v.affected_component || "").toLowerCase().includes(searchTerm.toLowerCase()) ||
      (v.title || "").toLowerCase().includes(searchTerm.toLowerCase());
    return matchesSev && matchesSearch;
  });

  const exportSarif = () => {
    if (!activeScan) return;
    // Construct standard SARIF 2.1.0 output
    const sarif = {
      $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "SBOMGuard",
              version: "2.0.0",
              rules: allVulns.map((v) => ({
                id: v.id,
                name: v.title || v.id,
                shortDescription: { text: v.title || v.id },
                fullDescription: { text: v.description || "" },
                defaultConfiguration: {
                  level: v.severity === "critical" || v.severity === "high" ? "error" : "warning",
                },
                properties: {
                  cvss_score: v.cvss_score,
                  epss_score: v.epss_score,
                  in_kev: v.in_kev,
                },
              })),
            },
          },
          results: allVulns.map((v) => ({
            ruleId: v.id,
            level: v.severity === "critical" || v.severity === "high" ? "error" : "warning",
            message: {
              text: `Vulnerability ${v.id} (${v.severity.toUpperCase()}) affects ${v.affected_component}. Fixed in: ${v.fixed_version || "N/A"}`,
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: activeScan.sbom_name || "SBOM" },
                },
              },
            ],
          })),
        },
      ],
    };

    const blob = new Blob([JSON.stringify(sarif, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sbomguard-sarif-${activeScan.id.slice(0, 8)}.sarif`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-500" />
            Vulnerability Correlation &amp; Threat Audit
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Asynchronous correlation with OSV batch querying, NVD CVE database, CISA KEV catalog, and EPSS exploitability ratings.
          </p>
        </div>

        {activeScan && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => onNavigateToRemediation(activeScan.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-purple-950/80 border border-purple-800 text-xs text-purple-300 hover:bg-purple-900 transition"
            >
              <Wrench className="w-3.5 h-3.5" />
              Remediation Plan
            </button>
            <button
              onClick={exportSarif}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-xs text-cyan-400 hover:border-cyan-500 transition"
              title="Export SARIF 2.1.0 for GitHub Code Scanning"
            >
              <Download className="w-3.5 h-3.5" />
              Export SARIF 2.1.0
            </button>
          </div>
        )}
      </div>

      {/* Launcher Bar */}
      <div className="glass-card p-4 rounded-2xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <label className="text-xs font-semibold text-slate-300">Target SBOM:</label>
          <select
            value={selectedSbomId}
            onChange={(e) => setSelectedSbomId(e.target.value)}
            className="bg-slate-900 text-sm text-slate-100 rounded-xl px-3.5 py-2 border border-slate-700 focus:outline-none focus:border-rose-500"
          >
            {sboms.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name} ({s.component_count} components)
              </option>
            ))}
          </select>
        </div>

        <button
          onClick={handleTriggerScan}
          disabled={loading || !selectedSbomId}
          className="flex items-center gap-2 px-5 py-2 rounded-xl bg-gradient-to-r from-rose-600 to-red-600 text-white font-semibold text-xs hover:from-rose-500 hover:to-red-500 transition shadow-lg shadow-rose-600/20 disabled:opacity-50"
        >
          <Play className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Scanning Databases..." : "Run Vulnerability Scan"}
        </button>

        {error && (
          <div className="w-full p-3 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Active Scan Telemetry Header */}
      {activeScan && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
            <div className="glass-card p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Total Findings</span>
              <span className="text-xl font-bold text-white font-mono">{activeScan.total_vulnerabilities}</span>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] text-rose-400 uppercase tracking-wider block">Critical Severity</span>
              <span className="text-xl font-bold text-rose-400 font-mono">{activeScan.critical_count}</span>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] text-amber-400 uppercase tracking-wider block">High Severity</span>
              <span className="text-xl font-bold text-amber-400 font-mono">{activeScan.high_count}</span>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] text-yellow-400 uppercase tracking-wider block">Medium Severity</span>
              <span className="text-xl font-bold text-yellow-400 font-mono">{activeScan.medium_count}</span>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-800">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Composite Risk</span>
              <span className="text-xl font-bold text-cyan-400 font-mono">
                {activeScan.overall_risk_score} / 100
              </span>
            </div>
          </div>

          {/* Search & Filters */}
          <div className="glass-card p-4 rounded-2xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
              <input
                type="text"
                placeholder="Search by CVE-ID, package name, or title..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-slate-900 text-xs text-white pl-9 pr-4 py-2 rounded-xl border border-slate-700"
              />
            </div>

            <div className="flex items-center gap-1.5 text-xs">
              <span className="text-slate-400">Severity:</span>
              {(["all", "critical", "high", "medium", "low"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={`px-2.5 py-1 rounded-lg uppercase tracking-wider text-[10px] font-bold transition ${
                    severityFilter === s
                      ? "bg-slate-700 text-white"
                      : "bg-slate-900 text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>

          {/* Vulnerabilities Table */}
          <div className="glass-card rounded-2xl overflow-hidden border border-slate-800">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-sans">
                <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Advisory ID</th>
                    <th className="py-3 px-4">Affected Component</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">CVSS Base</th>
                    <th className="py-3 px-4">EPSS Exploit</th>
                    <th className="py-3 px-4">Fixed Version</th>
                    <th className="py-3 px-4">Intelligence Feed</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 font-mono">
                  {filteredVulns.length > 0 ? (
                    filteredVulns.map((v, i) => (
                      <tr key={i} className="hover:bg-slate-800/30 transition">
                        <td className="py-3 px-4 font-bold text-white flex items-center gap-1.5">
                          {v.in_kev && <Flame className="w-3.5 h-3.5 text-rose-500 shrink-0" />}
                          <span>{v.id}</span>
                        </td>
                        <td className="py-3 px-4 text-slate-200">{v.affected_component}</td>
                        <td className="py-3 px-4">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                              v.severity === "critical"
                                ? "bg-rose-950 text-rose-400 border border-rose-800"
                                : v.severity === "high"
                                ? "bg-amber-950 text-amber-400 border border-amber-800"
                                : v.severity === "medium"
                                ? "bg-yellow-950 text-yellow-400 border border-yellow-800"
                                : "bg-blue-950 text-blue-400 border border-blue-800"
                            }`}
                          >
                            {v.severity}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-bold text-slate-200">{v.cvss_score}</td>
                        <td className="py-3 px-4 text-slate-300">
                          {v.epss_score ? `${(v.epss_score * 100).toFixed(1)}%` : "0.0%"}
                        </td>
                        <td className="py-3 px-4">
                          {v.fixed_version ? (
                            <span className="text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/50">
                              {v.fixed_version}
                            </span>
                          ) : (
                            <span className="text-slate-500 italic">None announced</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-400 uppercase text-[10px]">
                          {v.source || "OSV"}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={7} className="text-center py-8 text-slate-500 font-sans">
                        No vulnerabilities found matching current filters.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
