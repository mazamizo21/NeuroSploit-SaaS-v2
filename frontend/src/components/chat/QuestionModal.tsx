"use client";

import React, { useEffect, useMemo, useState } from "react";
import { HelpCircle, Send, X } from "lucide-react";

import { cn } from "@/lib/utils";
import type { QuestionRequestPayload } from "./types";

export function QuestionModal({
  request,
  onAnswer,
}: {
  request: QuestionRequestPayload | null;
  onAnswer: (answer: string, questionId?: string) => void;
}) {
  const [answer, setAnswer] = useState("");

  useEffect(() => {
    setAnswer("");
  }, [request?.question_id]);

  const options = useMemo(() => request?.options || [], [request]);

  if (!request) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="w-full max-w-xl rounded-2xl border border-[var(--border)] bg-[var(--surface)] shadow-2xl overflow-hidden">
        <div className="p-5 border-b border-[var(--border)]">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <HelpCircle className="w-5 h-5 text-indigo-300" />
              <div>
                <div className="font-mono text-xs font-bold tracking-wider">AGENT_QUESTION</div>
                <div className="text-[11px] text-[var(--text-dim)] font-mono">{request.question_id}</div>
              </div>
            </div>
            <button
              onClick={() => onAnswer("", request.question_id)}
              className="text-slate-400 hover:text-slate-200"
              title="Dismiss (send empty answer)"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="mt-3 rounded-lg bg-black/30 border border-white/10 p-3">
            <div className="text-[10px] font-mono text-[var(--text-dim)] mb-1">question</div>
            <div className="text-sm text-slate-100 whitespace-pre-wrap break-words">
              {request.question}
            </div>
          </div>

          {!!request.context && (
            <div className="mt-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] p-3">
              <div className="text-[10px] font-mono text-[var(--text-dim)] mb-1">context</div>
              <div className="text-xs text-slate-200 whitespace-pre-wrap break-words">
                {request.context}
              </div>
            </div>
          )}
        </div>

        <div className="p-5 space-y-3">
          {options.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {options.slice(0, 12).map((opt) => (
                <button
                  key={opt}
                  onClick={() => onAnswer(opt, request.question_id)}
                  className="px-3 py-2 rounded-lg border border-indigo-500/30 bg-indigo-500/10 text-indigo-100 hover:bg-indigo-500/15 text-sm"
                >
                  {opt}
                </button>
              ))}
            </div>
          ) : (
            <>
              <textarea
                value={answer}
                onChange={(e) => setAnswer(e.target.value)}
                rows={3}
                placeholder="Type your answer…"
                className={cn(
                  "w-full bg-black/25 border border-white/10 rounded-lg px-3 py-2",
                  "text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
                )}
              />

              <div className="flex items-center justify-end gap-2">
                <button
                  onClick={() => onAnswer(answer.trim(), request.question_id)}
                  disabled={!answer.trim()}
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg border border-indigo-500/30 bg-indigo-500/10 text-indigo-100 hover:bg-indigo-500/15 disabled:opacity-50"
                >
                  <Send className="w-4 h-4" /> Send
                </button>
              </div>
            </>
          )}

          <div className="text-[10px] text-[var(--text-dim)]">
            Format: <span className="font-mono">{String(request.format || "text")}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
