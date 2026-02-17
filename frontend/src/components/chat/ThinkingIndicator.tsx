"use client";

import React from "react";
import { Brain, Sparkles } from "lucide-react";

import { cn } from "@/lib/utils";
import type { ThinkingPayload } from "./types";

export function ThinkingIndicator({
  thinking,
}: {
  thinking: ThinkingPayload | null;
}) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4 text-indigo-300" />
          <div className="font-mono text-xs font-bold tracking-wider">THINKING</div>
        </div>
        {thinking ? (
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-amber-300 animate-pulse" />
            <div className="text-[10px] text-[var(--text-dim)] font-mono">
              iter {thinking.iteration} · {thinking.phase}
            </div>
          </div>
        ) : (
          <div className="text-[10px] text-[var(--text-dim)] font-mono">waiting…</div>
        )}
      </div>

      {thinking ? (
        <>
          <div className="mt-3 rounded-lg bg-[var(--surface2)] border border-[var(--border)] p-3">
            <div className="text-[10px] font-mono text-[var(--text-dim)] mb-1">thought</div>
            <div className="text-sm text-slate-100 whitespace-pre-wrap break-words">
              {thinking.thought || ""}
            </div>
          </div>
          {!!thinking.reasoning && (
            <div className="mt-2 rounded-lg bg-black/30 border border-white/5 p-3">
              <div className="text-[10px] font-mono text-[var(--text-dim)] mb-1">reasoning</div>
              <div className="text-xs text-slate-200 whitespace-pre-wrap break-words">
                {thinking.reasoning}
              </div>
            </div>
          )}
        </>
      ) : (
        <div className="mt-3 text-xs text-[var(--text-dim)]">
          No structured thinking yet. The agent will publish a <code className={cn("px-1 rounded bg-black/30")}>thinking</code>{" "}
          event once it enters the main loop.
        </div>
      )}
    </div>
  );
}
