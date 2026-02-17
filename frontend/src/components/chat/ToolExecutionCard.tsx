"use client";

import React, { useMemo, useState } from "react";
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Loader2,
  Terminal,
  XCircle,
} from "lucide-react";

import { cn } from "@/lib/utils";
import type { ToolRun } from "./types";

function statusMeta(run: ToolRun) {
  if (!run.completed) {
    return {
      icon: <Loader2 className="w-4 h-4 text-cyan-300 animate-spin" />,
      label: "running",
      badge: "bg-cyan-500/10 text-cyan-200 border-cyan-500/20",
    };
  }
  if (run.success) {
    return {
      icon: <CheckCircle2 className="w-4 h-4 text-emerald-300" />,
      label: "success",
      badge: "bg-emerald-500/10 text-emerald-200 border-emerald-500/20",
    };
  }
  return {
    icon: <XCircle className="w-4 h-4 text-rose-300" />,
    label: "failed",
    badge: "bg-rose-500/10 text-rose-200 border-rose-500/20",
  };
}

export function ToolExecutionCard({ run }: { run: ToolRun }) {
  const [open, setOpen] = useState(false);

  const meta = useMemo(() => statusMeta(run), [run]);

  const headerBg = !run.completed
    ? "from-cyan-950/40 to-slate-950/30"
    : run.success
      ? "from-emerald-950/40 to-slate-950/30"
      : "from-rose-950/40 to-slate-950/30";

  const outputPreview = useMemo(() => {
    const lines = run.output || [];
    if (lines.length === 0) return "";
    const last = lines.slice(-3).join("\n");
    return last.slice(0, 600);
  }, [run.output]);

  return (
    <div
      className={cn(
        "rounded-xl border border-[var(--border)] overflow-hidden",
        "bg-gradient-to-r",
        headerBg
      )}
    >
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-white/5 transition"
      >
        <div className="shrink-0">{meta.icon}</div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <Terminal className="w-4 h-4 text-indigo-300" />
            <span className="font-mono text-xs font-bold tracking-wide text-slate-100">
              {run.tool_name}
            </span>
            <span
              className={cn(
                "text-[10px] px-2 py-0.5 rounded-full border font-mono",
                meta.badge
              )}
            >
              {meta.label}
            </span>
          </div>
          <div className="mt-1 text-[11px] font-mono text-[var(--text-dim)] truncate">
            {run.command || "(no command)"}
          </div>
        </div>
        <div className="shrink-0 text-slate-400">
          {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-3">
          <div className="rounded-lg bg-black/40 border border-white/5 p-3">
            <div className="text-[10px] font-mono text-slate-400 mb-2">command</div>
            <pre className="text-[11px] text-slate-200 whitespace-pre-wrap break-all font-mono max-w-full overflow-x-hidden">
              {run.command || ""}
            </pre>
          </div>

          {!!run.output_summary && (
            <div className="rounded-lg bg-[var(--surface2)] border border-[var(--border)] p-3">
              <div className="text-[10px] font-mono text-slate-400 mb-2">summary</div>
              <div className="text-xs text-slate-200 whitespace-pre-wrap break-words">
                {run.output_summary}
              </div>
            </div>
          )}

          {(run.output?.length || 0) > 0 && (
            <div className="rounded-lg bg-black/40 border border-white/5 p-3">
              <div className="text-[10px] font-mono text-slate-400 mb-2">output</div>
              <pre className="text-[11px] text-green-300 whitespace-pre-wrap break-all font-mono max-h-48 overflow-y-auto max-w-full overflow-x-hidden">
                {open ? run.output.join("\n") : outputPreview}
              </pre>
            </div>
          )}

          {(run.findings?.length || 0) > 0 && (
            <div className="rounded-lg bg-amber-500/5 border border-amber-500/20 p-3">
              <div className="text-[10px] font-mono text-amber-300 mb-2">findings</div>
              <ul className="list-disc pl-5 text-xs text-amber-100 space-y-1">
                {run.findings?.slice(0, 12).map((f, idx) => (
                  <li key={idx} className="break-words">
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {(run.next_steps?.length || 0) > 0 && (
            <div className="rounded-lg bg-indigo-500/5 border border-indigo-500/20 p-3">
              <div className="text-[10px] font-mono text-indigo-300 mb-2">next steps</div>
              <ul className="list-disc pl-5 text-xs text-indigo-100 space-y-1">
                {run.next_steps?.slice(0, 12).map((s, idx) => (
                  <li key={idx} className="break-words">
                    {s}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
