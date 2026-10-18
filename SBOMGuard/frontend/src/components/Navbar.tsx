import React from "react";
import { Shield, Search, Moon, Sun, Database, Terminal, RefreshCw } from "lucide-react";

interface NavbarProps {
  darkMode: boolean;
  setDarkMode: (val: boolean) => void;
  activeView: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  darkMode,
  setDarkMode,
  activeView,
  onRefresh,
  isRefreshing,
}) => {
  return (
    <header className="sticky top-0 z-40 w-full glass-panel border-b border-slate-800/80 px-6 py-3.5 flex items-center justify-between">
      {/* Brand & Workspace Title */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-cyan-600 to-blue-500 p-0.5 shadow-lg shadow-cyan-500/20 flex items-center justify-center">
          <div className="w-full h-full bg-[#0B0F19] rounded-[10px] flex items-center justify-center">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-lg tracking-tight text-white">SBOMGuard</span>
            <span className="text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-800/50">
              v2.0 Enterprise
            </span>
          </div>
          <p className="text-xs text-slate-400 hidden sm:block">
            Automated Supply Chain Security & Remediation
          </p>
        </div>
      </div>

      {/* Center Search Capsule */}
      <div className="hidden md:flex items-center flex-1 max-w-md mx-8">
        <div className="relative w-full">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search dependencies, CVEs, PURLs, or ecosystems..."
            className="w-full bg-slate-900/80 text-sm text-slate-200 pl-10 pr-4 py-2 rounded-xl border border-slate-700/60 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all placeholder:text-slate-500"
          />
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center gap-3">
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-slate-700 transition"
            title="Refresh Data"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? "animate-spin text-cyan-400" : ""}`} />
          </button>
        )}

        <div className="hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs text-slate-300">
          <Database className="w-3.5 h-3.5 text-cyan-400" />
          <span>PostgreSQL 16: <strong className="text-emerald-400 font-medium">Connected</strong></span>
        </div>

        <button
          onClick={() => setDarkMode(!darkMode)}
          className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-cyan-400 hover:border-slate-700 transition"
          title="Toggle Dark/Light Mode"
        >
          {darkMode ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4 text-cyan-400" />}
        </button>

        <div className="flex items-center gap-2.5 pl-2 border-l border-slate-800">
          <div className="w-8 h-8 rounded-full bg-gradient-to-r from-cyan-500 to-indigo-500 flex items-center justify-center font-bold text-xs text-white">
            SG
          </div>
          <div className="hidden xl:block text-left">
            <div className="text-xs font-medium text-slate-200">Security Lead</div>
            <div className="text-[10px] text-slate-400">Chanakya University</div>
          </div>
        </div>
      </div>
    </header>
  );
};
