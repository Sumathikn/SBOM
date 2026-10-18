import React, { useState, useEffect } from "react";
import {
  Wrench,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  Copy,
  Check,
  GitPullRequest,
  Sparkles,
  ExternalLink,
  Flame,
  CheckCircle2,
} from "lucide-react";
import { RemediationGuidance, ScanResult, PatchResult } from "../types";
import { api } from "../services/api";
import { FixPRModal } from "./FixPRModal";

interface RemediationProps {
  scans: ScanResult[];
}

export const RemediationGuidanceView: React.FC<RemediationProps> = ({ scans }) => {
  const [selectedScanId, setSelectedScanId] = useState<string>(scans[0]?.id || "");
  const [guidanceList, setGuidanceList] = useState<RemediationGuidance[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  // PR Modal state
  const [showPRModal, setShowPRModal] = useState(false);
  const [patchResult, setPatchResult] = useState<PatchResult | null>(null);
  const [manifestText, setManifestText] = useState(
    "# Paste your requirements.txt or package.json here\nflask==2.3.0\nrequests==2.25.1\nwerkzeug==2.2.0"
  );
  const [manifestFilename, setManifestFilename] = useState("requirements.txt");
  const [generatingPatch, setGeneratingPatch] = useState(false);

  useEffect(() => {
    if (selectedScanId) {
      loadPlan(selectedScanId);
    }
  }, [selectedScanId]);

  const loadPlan = async (scanId: string) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getRemediationPlan(scanId);
      setGuidanceList(data);
    } catch (err: any) {
      setError(err.message || "Failed to load remediation guidance.");
    } finally {
      setLoading(false);
    }
  };

  const copyCommand = (cmd: string, index: number) => {
    navigator.clipboard.writeText(cmd);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleGeneratePR = async () => {
    setGeneratingPatch(true);
    try {
      const res = await api.generatePatch(manifestText, manifestFilename, selectedScanId);
      setPatchResult(res);
      setShowPRModal(true);
    } catch (err: any) {
      alert(`Patch generation error: ${err.message}`);
    } finally {
      setGeneratingPatch(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Wrench className="w-5 h-5 text-purple-400" />
            Advanced Remediation &amp; Threat Intelligence Engine
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Intelligent non-vulnerable upgrade paths, SemVer compatibility checks, CISA KEV threat signals, and automated PR patches.
          </p>
        </div>

        {guidanceList.length > 0 && (
          <button
            onClick={() => setShowPRModal(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-gradient-to-r from-purple-600 to-indigo-600 text-white font-semibold text-xs hover:from-purple-500 hover:to-indigo-500 transition shadow-lg shadow-purple-500/20"
          >
            <GitPullRequest className="w-4 h-4" />
            Generate Automated Fix PR
          </button>
        )}
      </div>

      {/* Scan Selector Bar */}
      <div className="glass-card p-4 rounded-2xl border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <label className="text-xs font-semibold text-slate-300">Target Audit Scan:</label>
          <select
            value={selectedScanId}
            onChange={(e) => setSelectedScanId(e.target.value)}
            className="bg-slate-900/90 text-sm text-slate-100 rounded-xl px-3.5 py-2 border border-slate-700 focus:outline-none focus:border-purple-500 font-mono"
          >
            {scans.length > 0 ? (
              scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.sbom_name || "SBOM Audit"} • {s.total_vulnerabilities} vulns • {new Date(s.scanned_at).toLocaleDateString()}
                </option>
              ))
            ) : (
              <option value="">No scans available</option>
            )}
          </select>
        </div>

        <div className="flex items-center gap-4 text-xs font-mono text-slate-400">
          <span>
            Vulnerable Packages Analyzed:{" "}
            <strong className="text-white font-bold">{guidanceList.length}</strong>
          </span>
        </div>
      </div>

      {loading && (
        <div className="text-center py-12 text-slate-400 font-mono text-sm animate-pulse">
          Computing multi-registry safe upgrade paths and compatibility scores...
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/60 border border-rose-800/80 text-rose-300 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Guidance Cards Grid */}
      {!loading && guidanceList.length > 0 && (
        <div className="space-y-4">
          {guidanceList.map((item, idx) => (
            <div
              key={idx}
              className={`glass-card rounded-2xl p-5 border transition-all ${
                item.has_cisa_kev
                  ? "border-rose-800/80 bg-rose-950/10 shadow-lg shadow-rose-950/30"
                  : "border-slate-800 hover:border-purple-500/30"
              }`}
            >
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-3 border-b border-slate-800/80">
                {/* Title & Signals */}
                <div className="space-y-1">
                  <div className="flex items-center gap-2.5 flex-wrap">
                    <span className="text-base font-bold text-white font-mono">{item.component_name}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                      {item.ecosystem}
                    </span>
                    {item.has_cisa_kev && (
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-rose-950 text-rose-400 border border-rose-800 flex items-center gap-1 animate-pulse">
                        <Flame className="w-3 h-3 text-rose-500" />
                        CISA KEV EXPLOITED
                      </span>
                    )}
                    {item.max_epss_score >= 0.25 && (
                      <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800/60">
                        EPSS: {(item.max_epss_score * 100).toFixed(1)}% Likelihood
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400">
                    Remediates {item.vulnerabilities_count} vulnerability(ies):{" "}
                    <span className="text-slate-300 font-mono">{item.cve_ids_fixed.join(", ")}</span>
                  </p>
                </div>

                {/* Confidence & Breaking Risk Badges */}
                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                      Confidence Score
                    </span>
                    <span className="text-sm font-bold text-emerald-400 font-mono">
                      {item.confidence_score}%
                    </span>
                  </div>

                  <div className="text-right">
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                      Breaking Risk
                    </span>
                    <span
                      className={`text-xs font-bold uppercase px-2 py-0.5 rounded ${
                        item.breaking_change_risk === "high"
                          ? "bg-rose-950 text-rose-400 border border-rose-800"
                          : item.breaking_change_risk === "medium"
                          ? "bg-amber-950 text-amber-400 border border-amber-800"
                          : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                      }`}
                    >
                      {item.breaking_change_risk}
                    </span>
                  </div>
                </div>
              </div>

              {/* Version Pathway & Commands */}
              <div className="pt-4 grid grid-cols-1 md:grid-cols-12 gap-4 items-center">
                {/* Version Jump Indicator */}
                <div className="md:col-span-5 flex items-center gap-3 font-mono text-xs">
                  <div className="p-2 rounded-xl bg-slate-900 border border-slate-800 text-slate-300">
                    <span className="text-[10px] text-slate-500 block">CURRENT</span>
                    v{item.current_version}
                  </div>

                  <ArrowRight className="w-4 h-4 text-purple-400 shrink-0" />

                  <div className="p-2 rounded-xl bg-purple-950/40 border border-purple-800/60 text-purple-300">
                    <span className="text-[10px] text-purple-400 block">MINIMUM SAFE</span>
                    v{item.minimum_safe_version}
                  </div>

                  <ArrowRight className="w-4 h-4 text-emerald-400 shrink-0" />

                  <div className="p-2 rounded-xl bg-emerald-950/40 border border-emerald-800/60 text-emerald-300">
                    <span className="text-[10px] text-emerald-400 block">RECOMMENDED</span>
                    v{item.recommended_version}
                  </div>
                </div>

                {/* Copyable CLI Command */}
                <div className="md:col-span-7 flex items-center justify-between p-2.5 rounded-xl bg-slate-950 border border-slate-800 font-mono text-xs">
                  <code className="text-slate-300 overflow-x-auto whitespace-nowrap pr-2">
                    {item.upgrade_command}
                  </code>
                  <button
                    onClick={() => copyCommand(item.upgrade_command, idx)}
                    className="p-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 transition shrink-0"
                    title="Copy upgrade command"
                  >
                    {copiedIndex === idx ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4 text-slate-400" />
                    )}
                  </button>
                </div>
              </div>

              {/* Explanatory notes */}
              {item.remediation_notes.length > 0 && (
                <div className="mt-3 pt-2 text-[11px] text-slate-400 space-y-0.5">
                  {item.remediation_notes.map((note, nIdx) => (
                    <div key={nIdx}>{note}</div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {!loading && guidanceList.length === 0 && (
        <div className="glass-card rounded-2xl p-12 text-center border border-slate-800 space-y-3">
          <CheckCircle2 className="w-10 h-10 text-emerald-400 mx-auto" />
          <h3 className="text-base font-bold text-white">Zero Vulnerable Components Identified</h3>
          <p className="text-xs text-slate-400 max-w-md mx-auto">
            All components in the selected scan meet security policy standards. No remediation patches are currently required.
          </p>
        </div>
      )}

      {/* Automated PR Patch Generation Drawer / Panel */}
      <div className="glass-card rounded-2xl p-6 border border-slate-800 space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-purple-400" />
          Manifest Patch Workbench
        </h3>
        <p className="text-xs text-slate-400">
          Provide your manifest content to preview the exact automated Git diff before applying.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 items-center">
          <div className="md:col-span-1 space-y-1">
            <label className="text-xs text-slate-400">Target Manifest File</label>
            <input
              type="text"
              value={manifestFilename}
              onChange={(e) => setManifestFilename(e.target.value)}
              className="w-full bg-slate-900 text-xs font-mono text-white px-3 py-2 rounded-xl border border-slate-700"
            />
          </div>
          <div className="md:col-span-3 flex justify-end items-end pt-5">
            <button
              onClick={handleGeneratePR}
              disabled={generatingPatch}
              className="px-5 py-2 rounded-xl bg-purple-600 hover:bg-purple-500 text-white font-semibold text-xs transition flex items-center gap-2 shadow-lg shadow-purple-500/20 disabled:opacity-50"
            >
              <GitPullRequest className="w-4 h-4" />
              {generatingPatch ? "Generating Unified Diff..." : "Generate Pull Request Patch"}
            </button>
          </div>
        </div>

        <textarea
          rows={5}
          value={manifestText}
          onChange={(e) => setManifestText(e.target.value)}
          className="w-full bg-slate-950 font-mono text-xs text-slate-200 p-4 rounded-xl border border-slate-800 focus:outline-none focus:border-purple-500"
          placeholder="Paste requirements.txt or package.json..."
        />
      </div>

      {/* Fix PR Modal */}
      {showPRModal && (
        <FixPRModal patchResult={patchResult} onClose={() => setShowPRModal(false)} />
      )}
    </div>
  );
};
