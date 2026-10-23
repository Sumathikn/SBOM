import React, { useState } from "react";
import {
  UploadCloud,
  FileCheck2,
  CheckCircle2,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Download,
} from "lucide-react";
import { api } from "../services/api";

interface GenerateViewProps {
  onSuccess: () => void;
  onNavigateToScan: (sbomId: string) => void;
}

export const GenerateView: React.FC<GenerateViewProps> = ({ onSuccess, onNavigateToScan }) => {
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState<"cyclonedx" | "spdx">("cyclonedx");
  const [projectName, setProjectName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<any | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selected = e.target.files[0];
      setFile(selected);
      if (!projectName) {
        setProjectName(selected.name.split(".")[0]);
      }
      setError(null);
    }
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError("Please select a valid dependency manifest file.");
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await api.generateSBOM(file, format, projectName || undefined);
      setResult(res);
      onSuccess();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || "Failed to generate SBOM");
    } finally {
      setLoading(false);
    }
  };

  const downloadSBOM = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result.document || result, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.name || "sbom"}-${result.format}.json`;
    a.click();
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div>
        <h2 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
          <UploadCloud className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
          Automated SBOM Generator
        </h2>
        <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
          Parses source manifests, extracts component metadata, checks licenses, and generates standard CycloneDX or SPDX artifacts.
        </p>
      </div>

      <div className="glass-card rounded-2xl p-6 border border-slate-200/90 dark:border-slate-800 space-y-6">
        <form onSubmit={handleGenerate} className="space-y-6">
          {/* File Upload Zone */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">
              Select or Drop Dependency Manifest:
            </label>
            <div className="border-2 border-dashed border-slate-300 dark:border-slate-700 hover:border-cyan-500 rounded-2xl p-8 text-center transition cursor-pointer bg-slate-50 dark:bg-slate-900/40 relative">
              <input
                type="file"
                onChange={handleFileChange}
                className="absolute inset-0 opacity-0 cursor-pointer"
                accept=".txt,.json,.xml,.mod,.lock"
              />
              <UploadCloud className="w-10 h-10 text-cyan-600 dark:text-cyan-400 mx-auto mb-2" />
              <div className="text-sm font-semibold text-slate-800 dark:text-slate-200">
                {file ? file.name : "Click to browse or drop file here"}
              </div>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
                Supported: <code className="text-cyan-700 dark:text-cyan-300 font-mono">requirements.txt</code>,{" "}
                <code className="text-cyan-700 dark:text-cyan-300 font-mono">package.json</code>,{" "}
                <code className="text-cyan-700 dark:text-cyan-300 font-mono">pom.xml</code>,{" "}
                <code className="text-cyan-700 dark:text-cyan-300 font-mono">go.mod</code>,{" "}
                <code className="text-cyan-700 dark:text-cyan-300 font-mono">Gemfile.lock</code>
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Format Selection */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Output Format Standard:</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setFormat("cyclonedx")}
                  className={`px-4 py-2.5 rounded-xl border text-xs font-semibold transition cursor-pointer ${
                    format === "cyclonedx"
                      ? "bg-cyan-100 text-cyan-800 border-cyan-400 dark:bg-cyan-500/20 dark:text-cyan-300 dark:border-cyan-500"
                      : "bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700"
                  }`}
                >
                  CycloneDX v1.5 (OWASP)
                </button>
                <button
                  type="button"
                  onClick={() => setFormat("spdx")}
                  className={`px-4 py-2.5 rounded-xl border text-xs font-semibold transition cursor-pointer ${
                    format === "spdx"
                      ? "bg-cyan-100 text-cyan-800 border-cyan-400 dark:bg-cyan-500/20 dark:text-cyan-300 dark:border-cyan-500"
                      : "bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-700"
                  }`}
                >
                  SPDX v2.3 (ISO)
                </button>
              </div>
            </div>

            {/* Project / Release Name */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-700 dark:text-slate-300">Project / Artifact Name:</label>
              <input
                type="text"
                placeholder="e.g. backend-api or auth-service"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="w-full bg-white dark:bg-slate-900 text-sm text-slate-900 dark:text-slate-100 rounded-xl px-4 py-2.5 border border-slate-200 dark:border-slate-700 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 text-rose-700 dark:text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-500 dark:text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={loading || !file}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold text-sm hover:from-cyan-400 hover:to-blue-500 transition shadow-lg shadow-cyan-500/20 disabled:opacity-50 cursor-pointer"
            >
              {loading ? "Parsing & Generating..." : "Generate & Store SBOM"}
            </button>
          </div>
        </form>

        {/* Success Preview */}
        {result && (
          <div className="p-6 rounded-2xl bg-white dark:bg-slate-900/90 border border-cyan-400/50 dark:border-cyan-500/40 space-y-4 animate-in fade-in shadow-md dark:shadow-none">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 dark:text-emerald-400" />
                <h3 className="text-sm font-bold text-slate-900 dark:text-white">
                  SBOM Generated Successfully: {result.name}
                </h3>
              </div>
              <span className="text-xs font-bold text-cyan-600 dark:text-cyan-400 uppercase font-mono">
                {result.format}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-500 block text-[10px]">TOTAL COMPONENTS</span>
                <span className="text-base font-bold text-slate-900 dark:text-white">{result.component_count}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-500 block text-[10px]">QUALITY SCORE</span>
                <span className="text-base font-bold text-emerald-600 dark:text-emerald-400">{result.quality_score}%</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-500 block text-[10px]">MANIFEST TYPE</span>
                <span className="text-slate-700 dark:text-slate-300">{result.manifest_type}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <span className="text-slate-500 block text-[10px]">POSTGRES RECORD ID</span>
                <span className="text-slate-600 dark:text-slate-400 truncate block">{result.sbom_id?.slice(0, 8)}...</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={downloadSBOM}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-xs text-slate-700 dark:text-slate-200 border border-slate-200 dark:border-transparent transition cursor-pointer"
              >
                <Download className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                Download JSON
              </button>
              <button
                onClick={() => onNavigateToScan(result.sbom_id)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition shadow-lg shadow-rose-600/20 cursor-pointer"
              >
                <ShieldAlert className="w-4 h-4" />
                Scan For Vulnerabilities
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
