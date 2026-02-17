"use client";

import { useCallback, useMemo, useState } from "react";
import { Sparkles, Send } from "lucide-react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

type ChatRole = "assistant" | "user";

type ChatLine = {
  role: ChatRole;
  content: string;
  ts: string;
};

function nowTs(): string {
  return new Date().toLocaleTimeString();
}

function summarizeTargets(targets: string[]): string {
  const clean = (targets || []).map((t) => String(t)).filter(Boolean);
  if (clean.length === 0) return "(no targets)";
  if (clean.length <= 4) return clean.join(", ");
  return `${clean.slice(0, 4).join(", ")} (+${clean.length - 4} more)`;
}

export default function ChatJobCreateCard({
  scopeId,
  scopeName,
  scopeTargets,
  className,
  onCreated,
}: {
  scopeId: string;
  scopeName?: string;
  scopeTargets?: string[];
  className?: string;
  onCreated?: (jobId: string) => void;
}) {
  const targets = useMemo(() => (scopeTargets || []).map((t) => String(t)).filter(Boolean), [scopeTargets]);
  const [useScopeTargets, setUseScopeTargets] = useState(true);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState("");

  const [lines, setLines] = useState<ChatLine[]>([
    {
      role: "assistant",
      ts: nowTs(),
      content:
        "Tell me what you want to pentest (goal + any preferred targets). I’ll create a pentest and open the live job chat so you can steer it in real time.",
    },
  ]);

  const [message, setMessage] = useState("");

  const send = useCallback(async () => {
    const msg = message.trim();
    if (!msg || sending) return;
    if (!scopeId) {
      setError("Scope is required before creating a pentest");
      return;
    }

    setError("");
    setSending(true);
    setLines((prev) => [...prev, { role: "user", ts: nowTs(), content: msg }]);
    setMessage("");

    try {
      const payload: Record<string, unknown> = {
        message: msg,
        scope_id: scopeId,
      };
      if (useScopeTargets && targets.length > 0) {
        payload.targets = targets;
      }

      const job = await api.post("/api/v1/jobs/chat", payload);
      const jobId = String(job?.id || "");
      const jobName = String(job?.name || "(unnamed)");
      const jobPhase = String(job?.phase || "FULL");
      const jobTargets: string[] = Array.isArray(job?.targets) ? job.targets.map((t: any) => String(t)) : [];

      setLines((prev) => [
        ...prev,
        {
          role: "assistant",
          ts: nowTs(),
          content: `✅ Created: ${jobName}  |  phase=${jobPhase}  |  targets=${summarizeTargets(jobTargets)}\nOpening live view…`,
        },
      ]);

      if (jobId && onCreated) onCreated(jobId);
    } catch (err: any) {
      const msgOut = err?.message || "Failed to create job";
      setError(msgOut);
      setLines((prev) => [...prev, { role: "assistant", ts: nowTs(), content: `❌ ${msgOut}` }]);
    } finally {
      setSending(false);
    }
  }, [message, onCreated, scopeId, sending, targets, useScopeTargets]);

  const scopeLabel = scopeName ? `${scopeName}` : scopeId;

  return (
    <div className={cn("rounded-lg border border-[var(--border)] bg-[var(--surface2)] p-3", className)}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-indigo-400" />
          <div>
            <p className="text-xs font-semibold text-slate-200">AI Guided Create</p>
            <p className="text-[11px] text-[var(--text-dim)]">
              Describe the pentest in natural language. We&apos;ll create the job and drop you into the live chat.
            </p>
          </div>
        </div>
        <div className="text-[10px] font-mono text-[var(--text-dim)]">scope: {scopeLabel}</div>
      </div>

      <div className="mt-3 bg-black/40 rounded-lg border border-white/5 p-3 h-28 overflow-y-auto font-mono text-[11px] space-y-1">
        {lines.map((l, idx) => (
          <div
            key={idx}
            className={cn(
              "whitespace-pre-wrap break-words",
              l.role === "user" ? "text-indigo-200" : "text-green-300"
            )}
          >
            <span className="opacity-60">[{l.ts}]</span> {l.role === "user" ? "you" : "ai"}: {l.content}
          </div>
        ))}
      </div>

      <div className="mt-3 flex items-center gap-2">
        <input
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !e.shiftKey) {
              e.preventDefault();
              send();
            }
          }}
          placeholder="e.g. Run a full lab pentest and generate a report"
          className="flex-1 bg-[var(--surface2)] border border-[var(--border)] rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
        />
        <button
          type="button"
          onClick={send}
          disabled={!message.trim() || sending}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/30 border border-indigo-500/30 disabled:opacity-50"
        >
          <Send className="w-4 h-4" />
          <span className="text-sm">Start</span>
        </button>
      </div>

      <label className="mt-2 flex items-start gap-2 text-xs text-[var(--text-dim)]">
        <input
          type="checkbox"
          checked={useScopeTargets}
          onChange={(e) => setUseScopeTargets(e.target.checked)}
          className="mt-1"
        />
        <span>
          Use all targets in this scope ({summarizeTargets(targets)})
          <span className="block text-[11px] opacity-70">
            Recommended for lab scopes. Disable to let the classifier extract targets from your message.
          </span>
        </span>
      </label>

      {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
    </div>
  );
}
