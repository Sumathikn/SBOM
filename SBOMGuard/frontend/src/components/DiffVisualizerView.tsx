import React, { useState } from "react";
import {
  GitCompare,
  ArrowRight,
  PlusCircle,
  MinusCircle,
  AlertTriangle,
  CheckCircle2,
  ListTree,
  Columns,
  History,
  Download,
  ShieldAlert,
} from "lucide-react";
import { SBOM, SBOMDiff, VersionChange } from "../types";
import { api } from "../services/api";

interface DiffProps {
  sboms: SBOM[];
}

export const DiffVisualizerView: React.FC<DiffProps> = ({ sboms }) => {
  const [sbomAId, setSbomAId] = useState<string>(sboms[0]?.id || "");
  const [sbomBId, setSbomBId] = useState<string>(sboms[1]?.id || sboms[0]?.id || "");
  const [diffResult, setDiffResult] = useState<SBOMDiff | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<"side-by-side" | "tree" | "timeline">("side-by-side");
  const [filterType, setFilterType] = useState<"all" | "major" | "minor" | "patch">("all");

  const handleRunDiff = async () => {
    if (!sbomAId || !sbomBId) {
      setError("Please select both a Base and Target SBOM to compare.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.compareSBOMs(sbomAId, sbomBId);
      setDiffResult(res);
    } catch (err: any) {
      setError(err.message || "Failed to compare SBOMs.");
    } finally {
      setLoading(false);
    }
  };

  const filteredChanges = diffResult?.version_changes.filter((c) => {
    if (filterType === "all") return true;
    return c.drift_type === filterType;
  });

  const exportDiffJson = () => {
    if (!diffResult) return;
    const blob = new Blob([JSON.stringify(diffResult, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `sbom-diff-${diffResult.sbom_a.name}-vs-${diffResult.sbom_b.name}.json`;
    a.click();
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <GitCompare className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
            Interactive SBOM Diff &amp; Version Drift Visualizer
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Detect dependency drift, breaking SemVer changes, and supply chain alterations between software releases.
          </p>
        </div>

        {diffResult && (
          <button
            onClick={exportDiffJson}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-xs text-slate-700 dark:text-slate-200 hover:text-cyan-600 dark:hover:text-cyan-400 shadow-sm dark:shadow-none transition cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            Export Diff Report
          </button>
        )}
      </div>

      {/* Selectors Bar */}
      <div className="glass-card p-5 rounded-2xl border border-slate-200/90 dark:border-slate-800 space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
          {/* Base SBOM Selection */}
          <div className="md:col-span-5 space-y-1.5">
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Base Release (SBOM A)</label>
            <select
              value={sbomAId}
              onChange={(e) => setSbomAId(e.target.value)}
              className="w-full bg-white dark:bg-slate-900/90 text-sm text-slate-900 dark:text-slate-100 rounded-xl px-3.5 py-2.5 border border-slate-200 dark:border-slate-700 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">-- Select Base SBOM --</option>
              {sboms.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} (v{s.version} • {s.component_count} comps • {s.format})
                </option>
              ))}
            </select>
          </div>

          <div className="md:col-span-2 flex justify-center pt-5">
            <div className="w-9 h-9 rounded-full bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-center text-cyan-600 dark:text-cyan-400">
              <ArrowRight className="w-4 h-4" />
            </div>
          </div>

          {/* Target SBOM Selection */}
          <div className="md:col-span-5 space-y-1.5">
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Target Release (SBOM B)</label>
            <select
              value={sbomBId}
              onChange={(e) => setSbomBId(e.target.value)}
              className="w-full bg-white dark:bg-slate-900/90 text-sm text-slate-900 dark:text-slate-100 rounded-xl px-3.5 py-2.5 border border-slate-200 dark:border-slate-700 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="">-- Select Target SBOM --</option>
              {sboms.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} (v{s.version} • {s.component_count} comps • {s.format})
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex justify-end pt-2">
          <button
            onClick={handleRunDiff}
            disabled={loading || !sbomAId || !sbomBId}
            className="flex items-center gap-2 px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold text-sm hover:from-cyan-400 hover:to-blue-500 transition shadow-lg shadow-cyan-500/20 disabled:opacity-50 cursor-pointer"
          >
            <GitCompare className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            {loading ? "Computing Drift Matrix..." : "Analyze Version Drift"}
          </button>
        </div>

        {error && (
          <div className="p-3 rounded-lg bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800/80 text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-rose-500 dark:text-rose-400 shrink-0" />
            <span>{error}</span>
          </div>
        )}
      </div>

      {/* Diff Results Container */}
      {diffResult && (
        <div className="space-y-6">
          {/* Telemetry Stat Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <div className="glass-card p-3.5 rounded-xl border border-slate-200/90 dark:border-slate-800">
              <span className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1">Added Packages</span>
              <div className="flex items-center gap-1.5">
                <PlusCircle className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
                <span className="text-xl font-bold text-emerald-600 dark:text-emerald-400">+{diffResult.stats.added_count}</span>
              </div>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-200/90 dark:border-slate-800">
              <span className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1">Removed Packages</span>
              <div className="flex items-center gap-1.5">
                <MinusCircle className="w-4 h-4 text-rose-500 dark:text-rose-400" />
                <span className="text-xl font-bold text-rose-600 dark:text-rose-400">-{diffResult.stats.removed_count}</span>
              </div>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-200/90 dark:border-slate-800">
              <span className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1">Version Drifts</span>
              <div className="flex items-center gap-1.5">
                <GitCompare className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                <span className="text-xl font-bold text-cyan-600 dark:text-cyan-400">{diffResult.stats.modified_count}</span>
              </div>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-200/90 dark:border-slate-800">
              <span className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1 font-semibold">Major (Breaking)</span>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
                <span className="text-xl font-bold text-rose-600 dark:text-rose-400">{diffResult.stats.major_drift_count}</span>
              </div>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-200/90 dark:border-slate-800">
              <span className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1 font-semibold">Minor (Features)</span>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
                <span className="text-xl font-bold text-amber-600 dark:text-amber-400">{diffResult.stats.minor_drift_count}</span>
              </div>
            </div>

            <div className="glass-card p-3.5 rounded-xl border border-slate-200/90 dark:border-slate-800">
              <span className="text-[11px] text-slate-500 dark:text-slate-400 block mb-1 font-semibold">Patch (Bugfixes)</span>
              <div className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
                <span className="text-xl font-bold text-emerald-600 dark:text-emerald-400">{diffResult.stats.patch_drift_count}</span>
              </div>
            </div>
          </div>

          {/* View Mode Toolbar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
            <div className="flex items-center gap-1.5 bg-slate-100 dark:bg-slate-900/90 p-1 rounded-xl border border-slate-200 dark:border-slate-800">
              <button
                onClick={() => setViewMode("side-by-side")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                  viewMode === "side-by-side"
                    ? "bg-cyan-100 text-cyan-800 dark:bg-cyan-500/20 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-500/30 font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
                }`}
              >
                <Columns className="w-3.5 h-3.5" />
                Side-by-Side
              </button>
              <button
                onClick={() => setViewMode("tree")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                  viewMode === "tree"
                    ? "bg-cyan-100 text-cyan-800 dark:bg-cyan-500/20 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-500/30 font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
                }`}
              >
                <ListTree className="w-3.5 h-3.5" />
                Tree Hierarchy
              </button>
              <button
                onClick={() => setViewMode("timeline")}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition cursor-pointer ${
                  viewMode === "timeline"
                    ? "bg-cyan-100 text-cyan-800 dark:bg-cyan-500/20 dark:text-cyan-400 border border-cyan-300 dark:border-cyan-500/30 font-semibold"
                    : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200"
                }`}
              >
                <History className="w-3.5 h-3.5" />
                Drift Timeline
              </button>
            </div>

            {/* Filter Pills */}
            <div className="flex items-center gap-1 text-xs">
              <span className="text-slate-500 mr-1">Filter Drift:</span>
              {(["all", "major", "minor", "patch"] as const).map((t) => (
                <button
                  key={t}
                  onClick={() => setFilterType(t)}
                  className={`px-2.5 py-1 rounded-lg uppercase tracking-wider text-[10px] font-semibold transition cursor-pointer ${
                    filterType === t
                      ? "bg-slate-800 text-white dark:bg-slate-700 dark:text-white"
                      : "bg-slate-100 text-slate-600 hover:bg-slate-200 dark:bg-slate-900 dark:text-slate-400 dark:hover:bg-slate-800"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>

          {/* 1. Side-by-Side View */}
          {viewMode === "side-by-side" && (
            <div className="space-y-6">
              {/* Version Changes Table */}
              <div className="glass-card rounded-2xl overflow-hidden border border-slate-200/90 dark:border-slate-800">
                <div className="px-5 py-3.5 bg-slate-50 dark:bg-slate-900/60 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-900 dark:text-slate-200 flex items-center gap-2">
                    <GitCompare className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                    Component Version Drift ({filteredChanges?.length || 0})
                  </h3>
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    Showing direct &amp; transitive dependencies
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-100 dark:bg-slate-950/80 text-slate-600 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800/80 font-mono text-[10px]">
                      <tr>
                        <th className="py-3 px-4">Dependency</th>
                        <th className="py-3 px-4">Ecosystem</th>
                        <th className="py-3 px-4">Type</th>
                        <th className="py-3 px-4">Base Version (A)</th>
                        <th className="py-3 px-4">Target Version (B)</th>
                        <th className="py-3 px-4">SemVer Drift</th>
                        <th className="py-3 px-4">Breaking Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono">
                      {filteredChanges && filteredChanges.length > 0 ? (
                        filteredChanges.map((vc, i) => (
                          <tr key={i} className="hover:bg-slate-50 dark:hover:bg-slate-800/40 transition">
                            <td className="py-3 px-4 font-semibold text-slate-900 dark:text-white">{vc.name}</td>
                            <td className="py-3 px-4 text-slate-500 dark:text-slate-400 capitalize">{vc.ecosystem || "n/a"}</td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] ${
                                  vc.is_direct
                                    ? "bg-cyan-100 text-cyan-800 border border-cyan-300 dark:bg-cyan-950/60 dark:text-cyan-400 dark:border-cyan-800/50"
                                    : "bg-slate-100 text-slate-600 dark:bg-slate-900 dark:text-slate-400"
                                }`}
                              >
                                {vc.is_direct ? "DIRECT" : "TRANSITIVE"}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-slate-600 dark:text-slate-400">v{vc.version_a}</td>
                            <td className="py-3 px-4 font-bold text-slate-900 dark:text-slate-200">v{vc.version_b}</td>
                            <td className="py-3 px-4">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                                  vc.drift_type === "major"
                                    ? "bg-rose-100 text-rose-800 border border-rose-300 dark:bg-rose-950 dark:text-rose-400 dark:border-rose-800"
                                    : vc.drift_type === "minor"
                                    ? "bg-amber-100 text-amber-800 border border-amber-300 dark:bg-amber-950 dark:text-amber-400 dark:border-amber-800"
                                    : "bg-emerald-100 text-emerald-800 border border-emerald-300 dark:bg-emerald-950 dark:text-emerald-400 dark:border-emerald-800"
                                }`}
                              >
                                {vc.drift_type}
                              </span>
                            </td>
                            <td className="py-3 px-4 text-[11px] font-sans">
                              {vc.drift_type === "major" ? (
                                <span className="text-rose-600 dark:text-rose-400 font-semibold">High Potential Breakage</span>
                              ) : vc.drift_type === "minor" ? (
                                <span className="text-amber-600 dark:text-amber-400">New API Features</span>
                              ) : (
                                <span className="text-emerald-600 dark:text-emerald-400">Safe Bugfix</span>
                              )}
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={7} className="text-center py-8 text-slate-500 font-sans">
                            No component version differences found matching current filters.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Added & Removed Split */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Added */}
                <div className="glass-card rounded-2xl p-5 border border-slate-200/90 dark:border-slate-800 space-y-3">
                  <h4 className="text-sm font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-2">
                    <PlusCircle className="w-4 h-4" />
                    Newly Introduced Dependencies ({diffResult.added_components.length})
                  </h4>
                  {diffResult.added_components.length > 0 ? (
                    <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                      {diffResult.added_components.map((c, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 text-xs font-mono"
                        >
                          <span className="font-semibold text-slate-900 dark:text-white">{c.name}</span>
                          <span className="text-emerald-700 bg-emerald-100 dark:text-emerald-400 dark:bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-300 dark:border-emerald-800/50">
                            v{c.version}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 italic">No new packages introduced.</p>
                  )}
                </div>

                {/* Removed */}
                <div className="glass-card rounded-2xl p-5 border border-slate-200/90 dark:border-slate-800 space-y-3">
                  <h4 className="text-sm font-semibold text-rose-600 dark:text-rose-400 flex items-center gap-2">
                    <MinusCircle className="w-4 h-4" />
                    Removed Dependencies ({diffResult.removed_components.length})
                  </h4>
                  {diffResult.removed_components.length > 0 ? (
                    <div className="space-y-2 max-h-60 overflow-y-auto pr-1">
                      {diffResult.removed_components.map((c, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between p-2.5 rounded-xl bg-slate-50 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800/80 text-xs font-mono"
                        >
                          <span className="font-semibold text-slate-700 dark:text-slate-300">{c.name}</span>
                          <span className="text-rose-700 bg-rose-100 dark:text-rose-400 dark:bg-rose-950/50 px-2 py-0.5 rounded border border-rose-300 dark:border-rose-800/50">
                            v{c.version}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 italic">No packages removed.</p>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* 2. Hierarchical Tree View */}
          {viewMode === "tree" && (
            <div className="glass-card rounded-2xl p-6 border border-slate-200/90 dark:border-slate-800 space-y-6">
              <div>
                <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                  <ListTree className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                  Hierarchical Dependency Drift Tree
                </h3>
                <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                  Visualizing root direct dependencies vs deep transitive version alterations.
                </p>
              </div>

              {/* Direct Tree */}
              <div className="space-y-3">
                <div className="text-xs font-bold uppercase tracking-wider text-cyan-600 dark:text-cyan-400 flex items-center gap-2">
                  <span>ROOT / DIRECT DEPENDENCIES ({diffResult.direct_drift.length})</span>
                </div>
                <div className="space-y-2 pl-4 border-l-2 border-cyan-400 dark:border-cyan-800/40">
                  {diffResult.direct_drift.map((item, i) => (
                    <div
                      key={i}
                      className="p-3 rounded-xl bg-slate-50 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs font-mono"
                    >
                      <div className="flex items-center gap-3">
                        <span className="text-cyan-600 dark:text-cyan-400 font-bold">├── {item.name}</span>
                        <span className="text-slate-500 dark:text-slate-400 text-[11px]">{item.purl_after || item.ecosystem}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 dark:text-slate-400">v{item.version_before}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                        <span className="text-slate-900 dark:text-white font-bold">v{item.version_after}</span>
                        <span
                          className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                            item.drift_type === "major"
                              ? "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-400"
                              : "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-400"
                          }`}
                        >
                          {item.drift_type}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Transitive Tree */}
              <div className="space-y-3 pt-4">
                <div className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-2">
                  <span>TRANSITIVE / SUB-DEPENDENCIES ({diffResult.transitive_drift.length})</span>
                </div>
                <div className="space-y-2 pl-4 border-l-2 border-slate-300 dark:border-slate-800">
                  {diffResult.transitive_drift.map((item, i) => (
                    <div
                      key={i}
                      className="p-2.5 rounded-xl bg-slate-50 dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800/70 flex items-center justify-between text-xs font-mono"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-slate-600 dark:text-slate-400">└── {item.name}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 dark:text-slate-400">v{item.version_before}</span>
                        <ArrowRight className="w-3.5 h-3.5 text-slate-400" />
                        <span className="text-slate-800 dark:text-slate-200 font-bold">v{item.version_after}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-200 text-slate-700 dark:bg-slate-800 dark:text-slate-300">
                          {item.drift_type}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* 3. Timeline View */}
          {viewMode === "timeline" && (
            <div className="glass-card rounded-2xl p-6 border border-slate-200/90 dark:border-slate-800 space-y-6">
              <h3 className="text-sm font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                <History className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                Release Progression Timeline
              </h3>

              <div className="relative pl-8 space-y-8 before:absolute before:left-3.5 before:top-3 before:bottom-3 before:w-0.5 before:bg-slate-300 dark:before:bg-slate-800">
                {/* Point A */}
                <div className="relative">
                  <div className="absolute -left-[27px] top-1 w-4 h-4 rounded-full bg-white dark:bg-slate-800 border-2 border-cyan-500" />
                  <div className="p-4 rounded-xl bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-cyan-600 dark:text-cyan-400">BASE RELEASE: {diffResult.sbom_a.name}</span>
                      <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                        {new Date(diffResult.sbom_a.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-300">
                      Version: {diffResult.sbom_a.version} • Components: {diffResult.sbom_a.component_count}
                    </p>
                  </div>
                </div>

                {/* Point B */}
                <div className="relative">
                  <div className="absolute -left-[27px] top-1 w-4 h-4 rounded-full bg-cyan-500 border-2 border-white" />
                  <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-cyan-400/60 dark:border-cyan-800/60 space-y-1 shadow-sm dark:shadow-none">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-900 dark:text-white">TARGET RELEASE: {diffResult.sbom_b.name}</span>
                      <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
                        {new Date(diffResult.sbom_b.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-xs text-slate-600 dark:text-slate-300">
                      Version: {diffResult.sbom_b.version} • Components: {diffResult.sbom_b.component_count}
                    </p>
                    <div className="pt-2 text-xs text-cyan-700 dark:text-cyan-300 font-mono">
                      Delta: {diffResult.summary}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
