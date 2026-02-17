"use client";

import React, { useMemo } from "react";

import { cn } from "@/lib/utils";

const PHASES = [
  "RECON",
  "VULN_DISCOVERY",
  "EXPLOITATION",
  "C2_DEPLOY",
  "POST_EXPLOIT",
  "COMPLETE",
];

export function PhaseProgressBar({
  phase,
  iteration,
}: {
  phase: string | null;
  iteration: number | null;
}) {
  const { currentPhase, idx } = useMemo(() => {
    const p = String(phase || "").toUpperCase().trim();
    const i = PHASES.indexOf(p);
    return {
      currentPhase: p || null,
      idx: i,
    };
  }, [phase]);

  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="text-xs font-mono text-[var(--text-dim)]">PHASE</div>
        <div className="text-[10px] font-mono text-[var(--text-dim)]">
          {iteration != null ? `iter ${iteration}` : ""}
        </div>
      </div>

      <div className="mt-2 flex items-center justify-between gap-3">
        <div className="font-mono text-sm font-bold text-slate-100">
          {currentPhase || "—"}
        </div>
        {idx === -1 && currentPhase && (
          <div className="text-[10px] text-amber-300 font-mono">unmapped phase</div>
        )}
      </div>

      <div className="mt-3 flex gap-1">
        {PHASES.map((p, i) => {
          const done = idx >= 0 && i < idx;
          const active = idx >= 0 && i === idx;
          return (
            <div
              key={p}
              className={cn(
                "h-2 flex-1 rounded-full border",
                done
                  ? "bg-indigo-500/50 border-indigo-500/30"
                  : active
                    ? "bg-indigo-400 border-indigo-400/60"
                    : "bg-white/5 border-white/10"
              )}
              title={p}
            />
          );
        })}
      </div>

      <div className="mt-2 flex flex-wrap gap-2">
        {PHASES.map((p) => (
          <span
            key={p}
            className={cn(
              "text-[10px] font-mono px-2 py-0.5 rounded-full border",
              String(currentPhase || "") === p
                ? "bg-indigo-500/15 text-indigo-200 border-indigo-500/30"
                : "bg-black/20 text-slate-400 border-white/10"
            )}
          >
            {p}
          </span>
        ))}
      </div>
    </div>
  );
}
