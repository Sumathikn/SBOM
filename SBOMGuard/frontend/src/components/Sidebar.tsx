import React from "react";
import {
  LayoutDashboard,
  FilePlus2,
  Boxes,
  ShieldAlert,
  GitCompare,
  Wrench,
} from "lucide-react";

interface SidebarProps {
  activeView: string;
  setActiveView: (view: string) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ activeView, setActiveView }) => {
  const navItems = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "generate", label: "Generate SBOM", icon: FilePlus2 },
    { id: "sboms", label: "Repository", icon: Boxes },
    { id: "scan", label: "Vulnerability Scan", icon: ShieldAlert },
    { id: "diff", label: "Diff & Version Drift", icon: GitCompare, badge: "New" },
    { id: "remediation", label: "Remediation Center", icon: Wrench, badge: "AI" },
  ];

  return (
    <aside className="w-64 glass-panel border-r border-slate-200/80 dark:border-slate-800/80 p-4 flex flex-col justify-between h-[calc(100vh-65px)] sticky top-[65px] transition-colors duration-200">
      <div className="space-y-6">
        <div>
          <span className="text-[11px] font-semibold tracking-wider uppercase text-slate-500 dark:text-slate-500 px-3">
            Platform Modules
          </span>
          <nav className="mt-2 space-y-1">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveView(item.id)}
                  className={`w-full flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                    isActive
                      ? "bg-gradient-to-r from-cyan-600/15 to-blue-600/10 text-cyan-700 dark:text-cyan-400 border border-cyan-500/40 shadow-sm font-semibold"
                      : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800/50"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <Icon className={`w-4 h-4 ${isActive ? "text-cyan-600 dark:text-cyan-400" : "text-slate-500 dark:text-slate-400"}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge && (
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        item.badge === "AI"
                          ? "bg-purple-100 text-purple-700 border border-purple-200 dark:bg-purple-950 dark:text-purple-400 dark:border-purple-800/60"
                          : "bg-cyan-100 text-cyan-700 border border-cyan-200 dark:bg-cyan-950 dark:text-cyan-400 dark:border-cyan-800/60"
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
      </div>

      {/* DevSecOps Status Card */}
      <div className="p-3.5 rounded-xl bg-slate-100/90 dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800/80 text-xs">
        <div className="flex items-center justify-between mb-2">
          <span className="text-slate-600 dark:text-slate-400 font-medium">Policy Gatekeeper</span>
          <span className="inline-block w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
        </div>
        <p className="text-[11px] text-slate-500 dark:text-slate-400 leading-relaxed">
          PR Gatekeeping active with threshold: <strong className="text-slate-800 dark:text-slate-200">FAIL_ON_HIGH</strong>
        </p>
      </div>
    </aside>
  );
};
