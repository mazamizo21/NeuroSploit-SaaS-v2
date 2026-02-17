"use client";

import React, { useMemo, useState } from "react";
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Circle,
  Flame,
  Target,
} from "lucide-react";

import { cn } from "@/lib/utils";
import type { TodoItem } from "./types";

function sevClass(sev: string) {
  const s = String(sev || "").toLowerCase();
  if (s === "critical") return "bg-red-600/20 text-red-200 border-red-500/30";
  if (s === "high") return "bg-orange-600/20 text-orange-200 border-orange-500/30";
  if (s === "medium") return "bg-yellow-600/20 text-yellow-200 border-yellow-500/30";
  if (s === "low") return "bg-blue-600/20 text-blue-200 border-blue-500/30";
  return "bg-slate-600/20 text-slate-200 border-slate-500/30";
}

export function TodoSidebar({ items }: { items: TodoItem[] }) {
  const [open, setOpen] = useState(true);

  const { unexploited, exploited, skipped } = useMemo(() => {
    const list = Array.isArray(items) ? items : [];
    const un: TodoItem[] = [];
    const ex: TodoItem[] = [];
    const sk: TodoItem[] = [];

    for (const it of list) {
      const reason = String(it.not_exploitable_reason || "").trim();
      if (reason) {
        sk.push(it);
      } else if (it.exploited) {
        ex.push(it);
      } else {
        un.push(it);
      }
    }

    const sortKey = (it: TodoItem) => `${String(it.severity || "")}::${String(it.id || "")}`;
    un.sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
    ex.sort((a, b) => sortKey(a).localeCompare(sortKey(b)));
    sk.sort((a, b) => sortKey(a).localeCompare(sortKey(b)));

    return { unexploited: un, exploited: ex, skipped: sk };
  }, [items]);

  return (
    <aside className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-4">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center justify-between gap-3"
      >
        <div className="flex items-center gap-2">
          <Target className="w-4 h-4 text-indigo-300" />
          <div className="font-mono text-xs font-bold tracking-wider">TODO</div>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-mono text-[var(--text-dim)]">
          <span className="inline-flex items-center gap-1">
            <Flame className="w-3 h-3 text-amber-300" /> {unexploited.length}
          </span>
          <span className="inline-flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-300" /> {exploited.length}
          </span>
          {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>

      {open && (
        <div className="mt-4 space-y-4">
          {items.length === 0 && (
            <div className="text-xs text-[var(--text-dim)]">No tracked findings yet.</div>
          )}

          {unexploited.length > 0 && (
            <div>
              <div className="text-[10px] font-mono text-amber-200 mb-2">UNRESOLVED</div>
              <div className="space-y-2">
                {unexploited.slice(0, 25).map((it) => (
                  <div
                    key={it.id}
                    className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-100 truncate">
                          {it.type || "vulnerability"} · {it.id}
                        </div>
                        <div className="text-[10px] text-[var(--text-dim)] truncate">
                          {it.target || "unknown target"}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-mono", sevClass(it.severity || ""))}>
                          {String(it.severity || "info")}
                        </span>
                        <span className="text-[10px] font-mono text-amber-200">
                          tries {it.exploit_attempts ?? 0}
                        </span>
                        <Circle className="w-3.5 h-3.5 text-amber-300" />
                      </div>
                    </div>
                    {!!it.details && (
                      <div className="mt-2 text-[11px] text-slate-200 whitespace-pre-wrap break-all">
                        {it.details}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {exploited.length > 0 && (
            <div>
              <div className="text-[10px] font-mono text-emerald-200 mb-2">PROVEN</div>
              <div className="space-y-2">
                {exploited.slice(0, 25).map((it) => (
                  <div
                    key={it.id}
                    className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-100 truncate">
                          {it.type || "vulnerability"} · {it.id}
                        </div>
                        <div className="text-[10px] text-[var(--text-dim)] truncate">
                          {it.target || "unknown target"}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-mono", sevClass(it.severity || ""))}>
                          {String(it.severity || "info")}
                        </span>
                        <CheckCircle2 className="w-4 h-4 text-emerald-300" />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {skipped.length > 0 && (
            <div>
              <div className="text-[10px] font-mono text-slate-300 mb-2">SKIPPED</div>
              <div className="space-y-2">
                {skipped.slice(0, 25).map((it) => (
                  <div
                    key={it.id}
                    className="rounded-lg border border-white/10 bg-black/20 p-3"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="text-xs font-semibold text-slate-100 truncate">
                          {it.type || "vulnerability"} · {it.id}
                        </div>
                        <div className="text-[10px] text-[var(--text-dim)] truncate">
                          {it.target || "unknown target"}
                        </div>
                      </div>
                      <span className={cn("text-[10px] px-2 py-0.5 rounded-full border font-mono", sevClass(it.severity || ""))}>
                        {String(it.severity || "info")}
                      </span>
                    </div>
                    {!!it.not_exploitable_reason && (
                      <div className="mt-2 text-[11px] text-slate-300 whitespace-pre-wrap break-all">
                        {it.not_exploitable_reason}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </aside>
  );
}
