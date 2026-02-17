"use client";

import React, { useEffect, useMemo, useState } from "react";
import { CheckCircle2, Edit3, ShieldAlert, XCircle } from "lucide-react";

import { cn } from "@/lib/utils";
import type { ApprovalRequestPayload } from "./types";

export function ApprovalModal({
  request,
  onDecision,
}: {
  request: ApprovalRequestPayload | null;
  onDecision: (decision: "approve" | "modify" | "abort", modification?: string) => void;
}) {
  const [modification, setModification] = useState("");

  useEffect(() => {
    setModification("");
  }, [request?.from_phase, request?.to_phase, request?.reason]);

  const hasRequest = !!request;
  const planned = useMemo(() => request?.planned_actions || [], [request]);
  const risks = useMemo(() => request?.risks || [], [request]);

  if (!hasRequest || !request) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-2xl rounded-2xl border border-[var(--border)] bg-[var(--surface)] shadow-2xl overflow-hidden">
        <div className="p-5 border-b border-[var(--border)]">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-amber-300" />
              <div>
                <div className="font-mono text-xs font-bold tracking-wider">APPROVAL_REQUIRED</div>
                <div className="text-sm text-slate-200">
                  {request.from_phase} -&gt; {request.to_phase}
                </div>
              </div>
            </div>
            <button
              onClick={() => onDecision("abort")}
              className="text-slate-400 hover:text-slate-200"
              title="Abort"
            >
              <XCircle className="w-5 h-5" />
            </button>
          </div>

          <div className="mt-3 rounded-lg bg-black/30 border border-white/10 p-3">
            <div className="text-[10px] font-mono text-[var(--text-dim)] mb-1">reason</div>
            <div className="text-sm text-slate-100 whitespace-pre-wrap break-words">
              {request.reason}
            </div>
          </div>
        </div>

        <div className="p-5 space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="rounded-xl border border-indigo-500/20 bg-indigo-500/5 p-4">
              <div className="text-[10px] font-mono text-indigo-200 mb-2">planned actions</div>
              {planned.length ? (
                <ul className="list-disc pl-5 text-xs text-slate-200 space-y-1">
                  {planned.slice(0, 10).map((a, idx) => (
                    <li key={idx} className="break-words">
                      {a}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-xs text-[var(--text-dim)]">(none provided)</div>
              )}
            </div>

            <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4">
              <div className="text-[10px] font-mono text-rose-200 mb-2">risks</div>
              {risks.length ? (
                <ul className="list-disc pl-5 text-xs text-slate-200 space-y-1">
                  {risks.slice(0, 10).map((r, idx) => (
                    <li key={idx} className="break-words">
                      {r}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-xs text-[var(--text-dim)]">(none provided)</div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface2)] p-4">
            <div className="text-[10px] font-mono text-[var(--text-dim)] mb-2">
              optional modification (if approving with constraints)
            </div>
            <textarea
              value={modification}
              onChange={(e) => setModification(e.target.value)}
              rows={3}
              placeholder="e.g. Do NOT use Metasploit. Exploit only via curl + manual payloads."
              className={cn(
                "w-full bg-black/25 border border-white/10 rounded-lg px-3 py-2",
                "text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
              )}
            />
          </div>

          <div className="flex flex-col sm:flex-row gap-2 sm:justify-end">
            <button
              onClick={() => onDecision("abort")}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-rose-500/30 bg-rose-500/10 text-rose-200 hover:bg-rose-500/15"
            >
              <XCircle className="w-4 h-4" /> Abort
            </button>

            <button
              onClick={() => onDecision("modify", modification.trim() || "")}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-100 hover:bg-amber-500/15"
              title="Approve, but inject your constraints into the agent"
            >
              <Edit3 className="w-4 h-4" /> Modify
            </button>

            <button
              onClick={() => onDecision("approve")}
              className="inline-flex items-center justify-center gap-2 px-4 py-2 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-100 hover:bg-emerald-500/15"
            >
              <CheckCircle2 className="w-4 h-4" /> Approve
            </button>
          </div>

          <div className="text-[10px] text-[var(--text-dim)]">
            Tip: use <span className="font-mono">Modify</span> to add constraints, tool preferences, or explicit guardrails.
          </div>
        </div>
      </div>
    </div>
  );
}
