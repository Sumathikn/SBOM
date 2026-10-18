import React, { useState } from "react";
import { X, GitPullRequest, Copy, Check, Terminal, FileCode, CheckCircle2 } from "lucide-react";
import { PatchResult } from "../types";

interface FixPRModalProps {
  patchResult: PatchResult | null;
  onClose: () => void;
}

export const FixPRModal: React.FC<FixPRModalProps> = ({ patchResult, onClose }) => {
  const [copiedDiff, setCopiedDiff] = useState(false);
  const [copiedBody, setCopiedBody] = useState(false);

  if (!patchResult) return null;

  const copyToClipboard = (text: string, setCopied: (v: boolean) => void) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="relative w-full max-w-4xl max-h-[90vh] glass-panel rounded-2xl border border-slate-700/80 shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/80">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-purple-950/80 border border-purple-800/60 flex items-center justify-center text-purple-400">
              <GitPullRequest className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                Automated Security Fix PR Generator
                <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                  {patchResult.modifications_count} Patches
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Ready-to-merge unified diff targeting <code className="text-cyan-400 font-mono">{patchResult.target_file}</code>
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 overflow-y-auto flex-1 font-sans">
          {/* PR Title & Description Preview */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300">Pull Request Details</span>
              <button
                onClick={() => copyToClipboard(patchResult.pr_body, setCopiedBody)}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
              >
                {copiedBody ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedBody ? "Copied PR Body" : "Copy PR Description"}
              </button>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-2">
              <div className="text-xs font-bold text-white font-mono">{patchResult.pr_title}</div>
              <div className="text-xs text-slate-400 font-mono whitespace-pre-wrap leading-relaxed max-h-36 overflow-y-auto">
                {patchResult.pr_body}
              </div>
            </div>
          </div>

          {/* Unified Diff View */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-slate-300 flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                Unified Git Patch (<code className="text-cyan-300 font-mono">{patchResult.target_file}</code>)
              </span>
              <button
                onClick={() => copyToClipboard(patchResult.unified_diff, setCopiedDiff)}
                className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 font-mono"
              >
                {copiedDiff ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedDiff ? "Copied Patch!" : "Copy Git Patch"}
              </button>
            </div>

            <div className="p-4 rounded-xl bg-slate-950 font-mono text-xs border border-slate-800 max-h-64 overflow-y-auto">
              {patchResult.unified_diff ? (
                <pre className="text-slate-300 whitespace-pre">
                  {patchResult.unified_diff.split("\n").map((line, idx) => {
                    let color = "text-slate-400";
                    if (line.startsWith("+")) color = "text-emerald-400 font-bold bg-emerald-950/30 px-1 rounded";
                    if (line.startsWith("-")) color = "text-rose-400 font-bold bg-rose-950/30 px-1 rounded";
                    if (line.startsWith("@")) color = "text-cyan-400";
                    return (
                      <div key={idx} className={color}>
                        {line}
                      </div>
                    );
                  })}
                </pre>
              ) : (
                <span className="text-slate-500 italic">No diff detected in target file.</span>
              )}
            </div>
          </div>

          {/* Instructions to apply */}
          <div className="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800/80 text-xs text-slate-400 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-slate-400" />
              <span>Apply locally via CLI:</span>
              <code className="text-cyan-300 bg-slate-950 px-2 py-0.5 rounded font-mono">
                git apply patch.diff
              </code>
            </div>
            <button
              onClick={onClose}
              className="px-4 py-1.5 rounded-lg bg-cyan-500 text-black font-semibold hover:bg-cyan-400 transition"
            >
              Done
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
