import React, { useState } from "react";
import {
  Boxes,
  FileCheck2,
  Trash2,
  Download,
  Search,
  ExternalLink,
  ShieldAlert,
  GitCompare,
} from "lucide-react";
import { SBOM } from "../types";
import { api } from "../services/api";

interface SBOMRepositoryProps {
  sboms: SBOM[];
  onRefresh: () => void;
  onNavigateToScan: (sbomId: string) => void;
  onNavigateToDiff: (sbomA: string) => void;
}

export const SBOMRepositoryView: React.FC<SBOMRepositoryProps> = ({
  sboms,
  onRefresh,
  onNavigateToScan,
  onNavigateToDiff,
}) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [selectedFormat, setSelectedFormat] = useState<"all" | "cyclonedx" | "spdx">("all");
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const filtered = sboms.filter((s) => {
    const matchesSearch =
      s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (s.source_file && s.source_file.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchesFormat = selectedFormat === "all" || s.format.toLowerCase() === selectedFormat;
    return matchesSearch && matchesFormat;
  });

  const handleDelete = async (id: string) => {
    if (!confirm("Are you sure you want to permanently delete this SBOM artifact?")) return;
    setDeletingId(id);
    try {
      await api.deleteSBOM(id);
      onRefresh();
    } catch (err) {
      alert("Failed to delete SBOM: " + err);
    } finally {
      setDeletingId(null);
    }
  };

  const downloadJson = async (id: string, name: string) => {
    try {
      const data = await api.getSBOM(id);
      const blob = new Blob([JSON.stringify(data.raw_document || data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${name.toLowerCase().replace(/\s+/g, "-")}-sbom.json`;
      a.click();
    } catch (err) {
      alert("Failed to download SBOM JSON: " + err);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
            <Boxes className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
            Software Bill of Materials Repository
          </h2>
          <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
            Persisted PostgreSQL software manifests with high-cardinality PURL indexes and quality scores.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-slate-500 dark:text-slate-400">
            Total Cataloged: <strong className="text-slate-900 dark:text-white">{sboms.length}</strong>
          </span>
        </div>
      </div>

      {/* Search & Filter Toolbar */}
      <div className="glass-card p-4 rounded-2xl border border-slate-200/90 dark:border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search SBOMs by name or source manifest..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-white dark:bg-slate-900 text-xs text-slate-900 dark:text-white pl-9 pr-4 py-2 rounded-xl border border-slate-200 dark:border-slate-700 focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 dark:text-slate-400">Format:</span>
          {(["all", "cyclonedx", "spdx"] as const).map((fmt) => (
            <button
              key={fmt}
              onClick={() => setSelectedFormat(fmt)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium uppercase transition cursor-pointer ${
                selectedFormat === fmt
                  ? "bg-cyan-100 text-cyan-800 border border-cyan-300 dark:bg-cyan-500/20 dark:text-cyan-400 dark:border-cyan-500/40 font-semibold"
                  : "bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white"
              }`}
            >
              {fmt}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="glass-card rounded-2xl overflow-hidden border border-slate-200/90 dark:border-slate-800">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-sans">
            <thead className="bg-slate-100 dark:bg-slate-950/80 text-slate-600 dark:text-slate-400 uppercase tracking-wider font-mono text-[10px] border-b border-slate-200 dark:border-slate-800">
              <tr>
                <th className="py-3 px-4">Artifact / Release Name</th>
                <th className="py-3 px-4">Standard</th>
                <th className="py-3 px-4">Source File</th>
                <th className="py-3 px-4">Components</th>
                <th className="py-3 px-4">Quality Score</th>
                <th className="py-3 px-4">Cataloged Date</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800/60 font-mono">
              {filtered.length > 0 ? (
                filtered.map((s) => (
                  <tr key={s.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/30 transition">
                    <td className="py-3.5 px-4 font-bold text-slate-900 dark:text-white flex items-center gap-2">
                      <FileCheck2 className="w-4 h-4 text-cyan-600 dark:text-cyan-400 shrink-0" />
                      <span>{s.name}</span>
                    </td>
                    <td className="py-3.5 px-4 uppercase text-cyan-600 dark:text-cyan-400 font-semibold">{s.format}</td>
                    <td className="py-3.5 px-4 text-slate-700 dark:text-slate-300">{s.source_file || "n/a"}</td>
                    <td className="py-3.5 px-4 text-slate-800 dark:text-slate-200 font-bold">{s.component_count}</td>
                    <td className="py-3.5 px-4">
                      <span className="px-2 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800 text-[11px] font-bold">
                        {s.quality_score}%
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-slate-500 dark:text-slate-400">
                      {new Date(s.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3.5 px-4 text-right space-x-1 font-sans">
                      <button
                        onClick={() => onNavigateToScan(s.id)}
                        className="px-2.5 py-1 rounded bg-rose-100 hover:bg-rose-200 dark:bg-rose-950 dark:hover:bg-rose-900 text-rose-700 dark:text-rose-300 border border-rose-300 dark:border-rose-800 text-[11px] font-medium transition cursor-pointer"
                        title="Scan For Vulnerabilities"
                      >
                        Scan
                      </button>
                      <button
                        onClick={() => onNavigateToDiff(s.id)}
                        className="px-2.5 py-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border border-slate-300 dark:border-slate-700 text-[11px] font-medium transition cursor-pointer"
                        title="Compare Diff"
                      >
                        Diff
                      </button>
                      <button
                        onClick={() => downloadJson(s.id, s.name)}
                        className="p-1 rounded bg-slate-100 hover:bg-slate-200 dark:bg-slate-900 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-700 transition inline-block align-middle cursor-pointer"
                        title="Download JSON Document"
                      >
                        <Download className="w-3.5 h-3.5" />
                      </button>
                      <button
                        onClick={() => handleDelete(s.id)}
                        disabled={deletingId === s.id}
                        className="p-1 rounded bg-slate-100 hover:bg-rose-100 dark:bg-slate-900 dark:hover:bg-rose-950 text-slate-500 hover:text-rose-600 dark:text-slate-400 dark:hover:text-rose-400 border border-slate-200 dark:border-slate-800 transition inline-block align-middle disabled:opacity-50 cursor-pointer"
                        title="Delete SBOM"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-slate-500 font-sans">
                    No SBOMs found. Use "Generate SBOM" to ingest your first manifest.
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
