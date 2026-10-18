import React, { useState } from "react";
import {
  UploadCloud,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Download,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { api } from "../services/api";

interface GenerateProps {
  onSuccess: (newSbom: any) => void;
  onNavigateToScan: (sbomId: string) => void;
}

export const GenerateView: React.FC<GenerateProps> = ({ onSuccess, onNavigateToScan }) => {
  const [file, setFile] = useState<File | null>(null);
  const [format, setFormat] = useState<"cyclonedx" | "spdx">("cyclonedx");
  const [projectName, setProjectName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<any | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
      if (!projectName) {
        setProjectName(e.target.files[0].name.replace(/\.[^/.]+$/, ""));
      }
    }
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError("Please select a manifest file to upload.");
      return;
    }

    setLoading(true);
    setError(null);
    try {
      const resp = await api.generateSBOM(file, format, projectName);
      setResult(resp.data);
      onSuccess(resp.data);
    } catch (err: any) {
      setError(err.message || "Failed to generate SBOM.");
    } finally {
      setLoading(false);
    }
  };

  const downloadSBOM = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result.document, null, 2)], {
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
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <UploadCloud className="w-5 h-5 text-cyan-400" />
          Automated SBOM Generator
        </h2>
        <p className="text-xs text-slate-400 mt-1">
          Parses source manifests, extracts component metadata, checks licenses, and generates standard CycloneDX or SPDX artifacts.
        </p>
      </div>

      <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-6">
        <form onSubmit={handleGenerate} className="space-y-6">
          {/* File Upload Zone */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-300">
              Select or Drop Dependency Manifest:
            </label>
            <div className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-2xl p-8 text-center transition cursor-pointer bg-slate-900/40 relative">
              <input
                type="file"
                onChange={handleFileChange}
                className="absolute inset-0 opacity-0 cursor-pointer"
                accept=".txt,.json,.xml,.mod,.lock"
              />
              <UploadCloud className="w-10 h-10 text-cyan-400 mx-auto mb-2" />
              <div className="text-sm font-semibold text-slate-200">
                {file ? file.name : "Click to browse or drop file here"}
              </div>
              <p className="text-xs text-slate-400 mt-1">
                Supported: <code className="text-cyan-300 font-mono">requirements.txt</code>,{" "}
                <code className="text-cyan-300 font-mono">package.json</code>,{" "}
                <code className="text-cyan-300 font-mono">pom.xml</code>,{" "}
                <code className="text-cyan-300 font-mono">go.mod</code>,{" "}
                <code className="text-cyan-300 font-mono">Gemfile.lock</code>
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Format Selection */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Output Format Standard:</label>
              <div className="grid grid-cols-2 gap-2">
                <button
                  type="button"
                  onClick={() => setFormat("cyclonedx")}
                  className={`px-4 py-2.5 rounded-xl border text-xs font-semibold transition ${
                    format === "cyclonedx"
                      ? "bg-cyan-500/20 text-cyan-300 border-cyan-500"
                      : "bg-slate-900 text-slate-400 border-slate-700"
                  }`}
                >
                  CycloneDX v1.5 (OWASP)
                </button>
                <button
                  type="button"
                  onClick={() => setFormat("spdx")}
                  className={`px-4 py-2.5 rounded-xl border text-xs font-semibold transition ${
                    format === "spdx"
                      ? "bg-cyan-500/20 text-cyan-300 border-cyan-500"
                      : "bg-slate-900 text-slate-400 border-slate-700"
                  }`}
                >
                  SPDX v2.3 (ISO)
                </button>
              </div>
            </div>

            {/* Project / Release Name */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold text-slate-300">Project / Artifact Name:</label>
              <input
                type="text"
                placeholder="e.g. backend-api or auth-service"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                className="w-full bg-slate-900 text-sm text-slate-100 rounded-xl px-4 py-2.5 border border-slate-700 focus:outline-none focus:border-cyan-500"
              />
            </div>
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-rose-950/60 border border-rose-800 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={loading || !file}
              className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-semibold text-sm hover:from-cyan-400 hover:to-blue-500 transition shadow-lg shadow-cyan-500/20 disabled:opacity-50"
            >
              {loading ? "Parsing & Generating..." : "Generate & Store SBOM"}
            </button>
          </div>
        </form>

        {/* Success Preview */}
        {result && (
          <div className="p-6 rounded-2xl bg-slate-900/90 border border-cyan-500/40 space-y-4 animate-in fade-in">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-white">
                  SBOM Generated Successfully: {result.name}
                </h3>
              </div>
              <span className="text-xs font-bold text-cyan-400 uppercase font-mono">
                {result.format}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">TOTAL COMPONENTS</span>
                <span className="text-base font-bold text-white">{result.component_count}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">QUALITY SCORE</span>
                <span className="text-base font-bold text-emerald-400">{result.quality_score}%</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">MANIFEST TYPE</span>
                <span className="text-slate-300">{result.manifest_type}</span>
              </div>
              <div className="p-3 rounded-xl bg-slate-950 border border-slate-800">
                <span className="text-slate-500 block text-[10px]">POSTGRES RECORD ID</span>
                <span className="text-slate-400 truncate block">{result.sbom_id?.slice(0, 8)}...</span>
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={downloadSBOM}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-xs text-slate-200 transition"
              >
                <Download className="w-4 h-4 text-cyan-400" />
                Download JSON
              </button>
              <button
                onClick={() => onNavigateToScan(result.sbom_id)}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-semibold text-xs transition shadow-lg shadow-rose-600/20"
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
