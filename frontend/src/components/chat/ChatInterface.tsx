"use client";

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Terminal, Wifi, WifiOff, Send } from "lucide-react";

import { api, wsUrl } from "@/lib/api";
import { cn } from "@/lib/utils";

import type {
  ApprovalRequestPayload,
  ChatEnvelope,
  ErrorPayload,
  GuidanceAckPayload,
  OutputPayload,
  PhaseUpdatePayload,
  QuestionRequestPayload,
  ResponsePayload,
  ThinkingPayload,
  TodoItem,
  TodoUpdatePayload,
  ToolCompletePayload,
  ToolOutputChunkPayload,
  ToolRun,
  ToolStartPayload,
} from "./types";

import { ToolExecutionCard } from "./ToolExecutionCard";
import { ThinkingIndicator } from "./ThinkingIndicator";
import { PhaseProgressBar } from "./PhaseProgressBar";
import { ApprovalModal } from "./ApprovalModal";
import { QuestionModal } from "./QuestionModal";
import { StopResumeButton } from "./StopResumeButton";
import { TodoSidebar } from "./TodoSidebar";

function redactSecrets(text: string): string {
  if (!text) return text;
  return (
    text
      // OpenAI/Anthropic-style keys
      .replace(/\bsk-[A-Za-z0-9_-]{10,}\b/g, "sk-***REDACTED***")
      // Bearer tokens
      .replace(/\bBearer\s+[A-Za-z0-9._-]{10,}\b/gi, "Bearer ***REDACTED***")
      // JWTs (base64url.base64url.base64url) even when printed without "Bearer"
      .replace(/\b[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\b/g, "***REDACTED_JWT***")
      // Zhipu/GLM key pattern: <32hex>.<token>
      .replace(/\b[a-f0-9]{32}\.[A-Za-z0-9_-]{10,}\b/gi, "***REDACTED_ZHIPU_KEY***")
      // Header-ish prints
      .replace(/(x-api-key\s*[:=]\s*)[^\s]+/gi, "$1***REDACTED***")
  );
}

function isNoisyLine(line: string): boolean {
  const noisy = [
    "httpcore.connection",
    "httpcore.http11",
    "httpx - ",
    "anthropic._base_client - DEBUG",
    "send_request_headers",
    "send_request_body",
    "receive_response_headers",
    "receive_response_body",
    "response_closed",
    "connect_tcp",
    "start_tls",
    "close.started",
    "close.complete",
    "Sending HTTP Request:",
    "HTTP Response:",
    "request_id: req_",
    "Request options:",
    "idempotency_key",
  ];
  return noisy.some((n) => line.includes(n));
}

function safeJsonParse(raw: string): any | null {
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

function nowIso() {
  return new Date().toISOString();
}

const MAX_CHAT_MSG_CHARS = 8000;

type ChatRole = "user" | "assistant" | "system";
type ChatMessage = {
  id: string;
  role: ChatRole;
  timestamp: string;
  text: string;
};

const CHAT_STORAGE_VERSION = 1;
const CHAT_STORAGE_PREFIX = `tazosploit:job_chat:v${CHAT_STORAGE_VERSION}`;

function chatStorageKey(jobId: string) {
  return `${CHAT_STORAGE_PREFIX}:job:${jobId}`;
}

function loadChatHistory(jobId: string): ChatMessage[] {
  try {
    if (typeof window === "undefined") return [];
    const raw = window.localStorage.getItem(chatStorageKey(jobId));
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const out: ChatMessage[] = [];
    for (const row of parsed) {
      if (!row || typeof row !== "object") continue;
      const role = String((row as any).role || "");
      const text = String((row as any).text || "");
      const timestamp = String((row as any).timestamp || "");
      if ((role !== "user" && role !== "assistant" && role !== "system") || !text) continue;
      out.push({
        id: String((row as any).id || msgId(role)),
        role: role as ChatRole,
        timestamp: timestamp || nowIso(),
        text: redactSecrets(text).slice(0, 8000),
      });
    }
    return out.slice(-200);
  } catch {
    return [];
  }
}

function saveChatHistory(jobId: string, messages: ChatMessage[]) {
  try {
    if (typeof window === "undefined") return;
    // Hard bounds to avoid unbounded localStorage growth.
    const payload = (Array.isArray(messages) ? messages : []).slice(-200);
    window.localStorage.setItem(chatStorageKey(jobId), JSON.stringify(payload));
  } catch {
    // ignore storage failures (private mode, quota, etc.)
  }
}

function clearChatHistory(jobId: string) {
  try {
    if (typeof window === "undefined") return;
    window.localStorage.removeItem(chatStorageKey(jobId));
  } catch {
    // ignore
  }
}

function msgId(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export default function ChatInterface({
  jobId,
  jobStatus,
  className,
}: {
  jobId: string;
  jobStatus?: string | null;
  className?: string;
}) {
  const wsRef = useRef<WebSocket | null>(null);
  const [connected, setConnected] = useState<boolean | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string>("");

  const [phase, setPhase] = useState<PhaseUpdatePayload | null>(null);
  const [thinking, setThinking] = useState<ThinkingPayload | null>(null);

  const chatEndRef = useRef<HTMLDivElement | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [output, setOutput] = useState<string[]>([]);
  const [tools, setTools] = useState<ToolRun[]>([]);
  const [todoItems, setTodoItems] = useState<TodoItem[]>([]);

  const [approvalRequest, setApprovalRequest] = useState<ApprovalRequestPayload | null>(null);
  const [questionRequest, setQuestionRequest] = useState<QuestionRequestPayload | null>(null);

  const [chatMode, setChatMode] = useState<"copilot" | "steer">("copilot");
  const [showTechnical, setShowTechnical] = useState(false);
  const [showAgentResponses, setShowAgentResponses] = useState(false);

  const [guidanceText, setGuidanceText] = useState("");
  const [guidanceSending, setGuidanceSending] = useState(false);

  const sendWs = useCallback((type: string, payload: Record<string, unknown> = {}) => {
    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return false;
    ws.send(JSON.stringify({ type, payload }));
    return true;
  }, []);

  const startNewConversation = useCallback(() => {
    try {
      if (typeof window !== "undefined") {
        const ok = window.confirm("Start a new conversation? This will clear the current chat transcript for this job.");
        if (!ok) return;
      }
    } catch {
      // ignore
    }

    setChatMessages([]);
    setGuidanceText("");
    clearChatHistory(jobId);
  }, [jobId]);

  // Persist chat across refreshes (scoped to this jobId).
  useEffect(() => {
    if (!jobId) return;
    const loaded = loadChatHistory(jobId);
    if (loaded.length) setChatMessages(loaded);
  }, [jobId]);

  useEffect(() => {
    if (!jobId) return;
    saveChatHistory(jobId, chatMessages);
  }, [jobId, chatMessages]);

  const appendOutputLine = useCallback((line: string) => {
    const clean = redactSecrets(String(line || ""));
    if (!clean || isNoisyLine(clean)) return;
    setOutput((prev) => [...prev.slice(-500), clean]);
  }, []);

  const appendChatMessage = useCallback((role: ChatRole, text: string, timestamp?: string) => {
    const clean = redactSecrets(String(text || "")).trim();
    if (!clean) return;

    // Avoid hard-truncating answers (causes the UI to stop mid-sentence).
    // Chunk into multiple chat messages instead.
    const ts = timestamp || nowIso();
    const chunks: string[] = [];
    let rest = clean;
    while (rest.length > MAX_CHAT_MSG_CHARS) {
      // Prefer splitting on a paragraph boundary near the limit.
      const window = rest.slice(0, MAX_CHAT_MSG_CHARS);
      const cut = Math.max(window.lastIndexOf("\n\n"), window.lastIndexOf("\n"));
      const idx = cut > 200 ? cut : MAX_CHAT_MSG_CHARS;
      chunks.push(rest.slice(0, idx).trimEnd());
      rest = rest.slice(idx).trimStart();
    }
    if (rest) chunks.push(rest);

    const chunkMsgs = chunks.map((c, i) => ({
      id: msgId(`${role}-${i}`),
      role,
      timestamp: ts,
      text: c,
    }));

    setChatMessages((prev) => {
      const next = [...prev.slice(-200), ...chunkMsgs];
      return next.slice(-200);
    });
  }, []);

  const handleEnvelope = useCallback(
    (env: ChatEnvelope<any>) => {
      const t = String(env.type || "").toLowerCase();
      setLastUpdated(new Date().toLocaleTimeString());

      if (t === "connected") {
        setConnected(true);
        return;
      }

      if (t === "output") {
        const payload = (env.payload || {}) as OutputPayload;
        const ts = payload.timestamp ? new Date(payload.timestamp).toLocaleTimeString() : "";
        const prefix = ts ? `[${ts}] ` : "";
        appendOutputLine(`${prefix}${payload.line || ""}`);
        return;
      }

      if (t === "guidance_ack") {
        const payload = (env.payload || {}) as GuidanceAckPayload;
        const pos = payload.queue_position != null ? `#${payload.queue_position}` : "";
        appendChatMessage(
          "system",
          `Guidance queued ${pos}`.trim() + (payload.message ? `: ${payload.message}` : ""),
          env.timestamp
        );
        return;
      }

      if (t === "response") {
        const payload = (env.payload || {}) as ResponsePayload;
        const header = payload.phase ? `[${payload.phase}${payload.iteration != null ? ` ${payload.iteration}` : ""}] ` : "";
        // By default we treat the operator panel as a normal chatbot (Copilot).
        // Raw agent responses often include commands/code and can overwhelm humans.
        // Operators can opt-in via "Show agent responses".
        if (showAgentResponses) {
          appendChatMessage("assistant", `${header}${payload.answer || ""}`, env.timestamp);
        }
        return;
      }

      if (t === "approval_ack") {
        const decision = String((env.payload || {})?.decision || "").trim();
        appendChatMessage("system", `approval recorded${decision ? `: ${decision}` : ""}`, env.timestamp);
        return;
      }

      if (t === "answer_ack") {
        appendChatMessage("system", "answer recorded", env.timestamp);
        return;
      }

      if (t === "phase_update") {
        setPhase((env.payload || {}) as PhaseUpdatePayload);
        return;
      }

      if (t === "thinking") {
        setThinking((env.payload || {}) as ThinkingPayload);
        return;
      }

      if (t === "tool_start") {
        const payload = (env.payload || {}) as ToolStartPayload;
        const run: ToolRun = {
          id: `tool-${payload.tool_name || "unknown"}-${Date.now()}`,
          tool_name: String(payload.tool_name || "unknown"),
          command: String(payload.command || ""),
          args: payload.args || {},
          started_at: env.timestamp || nowIso(),
          output: [],
          completed: false,
        };
        setTools((prev) => [...prev.slice(-30), run]);
        return;
      }

      if (t === "tool_output_chunk") {
        const payload = (env.payload || {}) as ToolOutputChunkPayload;
        const toolName = String(payload.tool_name || "unknown");
        const chunk = String(payload.chunk || "").slice(0, 2000);
        if (!chunk) return;
        setTools((prev) => {
          const next = [...prev];
          for (let i = next.length - 1; i >= 0; i--) {
            if (next[i].tool_name === toolName && !next[i].completed) {
              const out = [...next[i].output, chunk];
              next[i] = { ...next[i], output: out.slice(-200) };
              break;
            }
          }
          return next;
        });
        return;
      }

      if (t === "tool_complete") {
        const payload = (env.payload || {}) as ToolCompletePayload;
        const toolName = String(payload.tool_name || "unknown");
        setTools((prev) => {
          const next = [...prev];
          for (let i = next.length - 1; i >= 0; i--) {
            if (next[i].tool_name === toolName && !next[i].completed) {
              next[i] = {
                ...next[i],
                completed: true,
                success: !!payload.success,
                output_summary: String(payload.output_summary || "").slice(0, 2000),
                findings: payload.findings || [],
                next_steps: payload.next_steps || [],
              };
              break;
            }
          }
          return next;
        });
        return;
      }

      if (t === "todo_update") {
        const payload = (env.payload || {}) as TodoUpdatePayload;
        const items = Array.isArray(payload.items) ? (payload.items as TodoItem[]) : [];
        setTodoItems(items);
        return;
      }

      if (t === "approval_request") {
        setApprovalRequest((env.payload || {}) as ApprovalRequestPayload);
        return;
      }

      if (t === "question") {
        setQuestionRequest((env.payload || {}) as QuestionRequestPayload);
        return;
      }

      if (t === "error") {
        const payload = (env.payload || {}) as ErrorPayload;
        appendOutputLine(`[error] ${payload.message || "unknown error"}`);
        // Keep the main transcript "human clean" (no runtime/tool-policy noise).
        // Errors remain available under Technical details → Execution Logs.
        return;
      }

      if (t === "stopped") {
        appendChatMessage("system", "paused by operator", env.timestamp);
        return;
      }

      if (t === "resumed") {
        appendChatMessage("system", "resume requested", env.timestamp);
        return;
      }

      // Ignore unknown event types.
    },
    [appendChatMessage, appendOutputLine, showAgentResponses]
  );

  useEffect(() => {
    if (!chatEndRef.current) return;
    chatEndRef.current.scrollIntoView({ block: "end", behavior: "smooth" });
  }, [chatMessages.length]);

  // WebSocket connect/reconnect lifecycle
  useEffect(() => {
    if (!jobId) return;

    let ws: WebSocket | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let reconnectAttempts = 0;
    const maxReconnectAttempts = 10;

    function connect() {
      try {
        ws = new WebSocket(wsUrl(`/api/v1/ws/jobs/${jobId}/chat`));
        wsRef.current = ws;

        ws.onopen = () => {
          reconnectAttempts = 0;
          setConnected(true);
        };

        ws.onmessage = (e) => {
          const obj = safeJsonParse(String(e.data || ""));
          if (!obj || typeof obj.type !== "string") return;
          handleEnvelope(obj as ChatEnvelope);
        };

        ws.onerror = () => {
          // Keep silent; onclose handles reconnection
        };

        ws.onclose = () => {
          setConnected(false);
          if (reconnectAttempts < maxReconnectAttempts) {
            reconnectAttempts++;
            reconnectTimer = setTimeout(connect, 1500 * Math.min(reconnectAttempts, 6));
          }
        };
      } catch {
        setConnected(false);
      }
    }

    setConnected(null);
    connect();

    return () => {
      if (ws) ws.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    };
  }, [jobId, handleEnvelope]);

  const onSendMessage = useCallback(async () => {
    const message = guidanceText.trim();
    if (!message) return;

    setGuidanceSending(true);
    try {
      // Always show the user's message in the transcript.
      appendChatMessage("user", message);
      setGuidanceText("");

      if (chatMode === "steer") {
        const ok = sendWs("guidance", { message });
        if (!ok) {
          appendChatMessage("system", "steer failed: chat socket not connected");
        }
        return;
      }

      // Copilot mode: ask the server-side Copilot (does not affect the running agent).
      try {
        const resp = await api.post(`/api/v1/jobs/${jobId}/copilot`, { message });
        const answer = String(resp?.answer || "").trim();
        if (answer) {
          appendChatMessage("assistant", answer);
        } else {
          appendChatMessage("system", "copilot returned an empty answer");
        }
      } catch (e: any) {
        appendChatMessage("system", `copilot error: ${String(e?.message || e || "unknown error")}`);
      }
    } finally {
      setGuidanceSending(false);
    }
  }, [appendChatMessage, chatMode, guidanceText, jobId, sendWs]);

  const onStop = useCallback(() => {
    const ok = sendWs("stop", {});
    if (!ok) appendChatMessage("system", "chat socket not connected");
  }, [appendChatMessage, sendWs]);

  const onResume = useCallback(() => {
    const ok = sendWs("resume", {});
    if (!ok) appendChatMessage("system", "chat socket not connected");
  }, [appendChatMessage, sendWs]);

  const onApprovalDecision = useCallback(
    (decision: "approve" | "modify" | "abort", modification?: string) => {
      sendWs("approval", {
        decision,
        modification: modification || undefined,
      });
      setApprovalRequest(null);
    },
    [sendWs]
  );

  const onAnswer = useCallback(
    (answer: string, questionId?: string) => {
      sendWs("answer", {
        answer,
        question_id: questionId,
      });
      setQuestionRequest(null);
    },
    [sendWs]
  );

  const connectionLabel = connected === null ? "CONNECTING" : connected ? "ONLINE" : "OFFLINE";

  const toolRuns = useMemo(() => {
    // Preserve original ordering but group identical tool names nicely in UI.
    // We keep the full list for debugging/traceability.
    return tools.slice().reverse();
  }, [tools]);

  return (
    <div className={cn("space-y-3 max-w-full min-w-0 overflow-x-hidden", className)}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-indigo-400" />
          <span className="font-mono text-xs font-bold tracking-wider">JOB_CHAT</span>
          <span
            className={cn(
              "inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border",
              connected ? "border-emerald-500/30 text-emerald-300" : "border-slate-500/30 text-slate-300"
            )}
          >
            {connected ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
            {connectionLabel}
          </span>
          <span className="text-[10px] text-[var(--text-dim)] font-mono">UPDATED: {lastUpdated || "—"}</span>
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowTechnical((v) => !v)}
            className="text-[10px] px-2 py-1 rounded border border-[var(--border)] bg-[var(--surface2)] text-[var(--text-dim)] hover:text-slate-200"
            title="Toggle technical details (tools/logs)"
          >
            {showTechnical ? "Hide details" : "Show details"}
          </button>
          <StopResumeButton
            jobStatus={jobStatus || null}
            connected={!!connected}
            onStop={onStop}
            onResume={onResume}
          />
        </div>
      </div>

      <PhaseProgressBar phase={phase?.phase || thinking?.phase || null} iteration={phase?.iteration ?? thinking?.iteration ?? null} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left column */}
        <div className="lg:col-span-2 space-y-4">
          <div>
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs font-mono text-[var(--text-dim)]">AI CHAT</div>
              <button
                onClick={startNewConversation}
                className="text-[10px] text-slate-400 hover:text-slate-200"
                title="Start a new conversation"
              >
                new conversation
              </button>
            </div>
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface2)] flex flex-col h-72 min-w-0 overflow-hidden">
              <div className="px-3 pt-2 pb-1 flex items-center justify-between gap-2 border-b border-[var(--border)]">
                <div className="flex items-center gap-1">
                  <button
                    type="button"
                    onClick={() => setChatMode("copilot")}
                    className={cn(
                      "text-[10px] px-2 py-1 rounded border font-mono",
                      chatMode === "copilot"
                        ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                        : "border-[var(--border)] bg-[var(--surface)] text-[var(--text-dim)]"
                    )}
                    title="Ask Copilot (summaries/reports/questions)"
                  >
                    Copilot
                  </button>
                  <button
                    type="button"
                    onClick={() => setChatMode("steer")}
                    className={cn(
                      "text-[10px] px-2 py-1 rounded border font-mono",
                      chatMode === "steer"
                        ? "border-indigo-500/30 bg-indigo-500/10 text-indigo-200"
                        : "border-[var(--border)] bg-[var(--surface)] text-[var(--text-dim)]"
                    )}
                    title="Steer the running agent (guidance via WebSocket)"
                  >
                    Steer agent
                  </button>
                </div>

                <label className="flex items-center gap-2 text-[10px] font-mono text-[var(--text-dim)] select-none">
                  <input
                    type="checkbox"
                    checked={showAgentResponses}
                    onChange={(e) => setShowAgentResponses(e.target.checked)}
                    className="accent-indigo-500"
                  />
                  show agent responses
                </label>
              </div>

              <div className="flex-1 p-3 overflow-y-auto text-[12px] space-y-2 min-w-0">
                {chatMessages.length > 0 ? (
                  chatMessages.map((m) => {
                    const ts = m.timestamp ? new Date(m.timestamp).toLocaleTimeString() : "";
                    const label = m.role === "user" ? "you" : m.role === "assistant" ? "ai" : "system";
                    const color =
                      m.role === "user"
                        ? "text-indigo-200"
                        : m.role === "assistant"
                        ? "text-emerald-200"
                        : "text-slate-300";
                    return (
                      <div key={m.id} className={cn("whitespace-pre-wrap break-all", color)}>
                        <span className="opacity-60 font-mono">[{ts || "—"}]</span> <span className="font-semibold">{label}:</span> {m.text}
                      </div>
                    );
                  })
                ) : (
                  <div className="text-[var(--text-dim)]">No chat yet. Type a message below.</div>
                )}
                <div ref={chatEndRef} />
              </div>

              {/* Composer attached to the transcript */}
              <div className="border-t border-[var(--border)] p-2 bg-[var(--surface2)]">
                <div className="flex items-center gap-2 min-w-0">
                  <textarea
                    value={guidanceText}
                    onChange={(e) => setGuidanceText(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        onSendMessage();
                      }
                    }}
                    rows={2}
                    placeholder={
                      chatMode === "copilot"
                        ? "Ask Copilot… (report, summary, what happened, what next)"
                        : connected
                        ? "Steer the agent… (change direction, prioritize, stop a technique)"
                        : "Steer mode: disconnected…"
                    }
                    className="flex-1 min-w-0 max-w-full resize-none bg-black/20 border border-white/10 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/40"
                  />
                  <button
                    onClick={onSendMessage}
                    disabled={!guidanceText.trim() || guidanceSending || (chatMode === "steer" && !connected)}
                    className="inline-flex items-center gap-2 px-3 py-2 rounded-lg bg-indigo-600/20 text-indigo-300 hover:bg-indigo-600/30 border border-indigo-500/30 disabled:opacity-50"
                    title={chatMode === "copilot" ? "Send to Copilot" : connected ? "Send guidance" : "Disconnected"}
                  >
                    <Send className="w-4 h-4" />
                    <span className="text-sm">Send</span>
                  </button>
                </div>
              </div>
            </div>
          </div>

          {showTechnical && (
            <details className="rounded-xl border border-[var(--border)] bg-[var(--surface)] p-3">
              <summary className="cursor-pointer select-none text-xs font-mono text-[var(--text-dim)]">
                Technical details (thinking / tools / logs)
              </summary>
              <div className="mt-3 space-y-4">
                <ThinkingIndicator thinking={thinking} />

                {toolRuns.length > 0 && (
                  <div className="space-y-3">
                    <div className="text-xs font-mono text-[var(--text-dim)]">TOOLS</div>
                    {toolRuns.slice(0, 8).map((run) => (
                      <ToolExecutionCard key={run.id} run={run} />
                    ))}
                  </div>
                )}

                <div>
                  <div className="flex items-center justify-between mb-2">
                    <div className="text-xs font-mono text-[var(--text-dim)]">EXECUTION LOGS</div>
                    <button
                      onClick={() => setOutput([])}
                      className="text-[10px] text-slate-400 hover:text-slate-200"
                      title="Clear logs"
                    >
                      clear
                    </button>
                  </div>
                  <div className="bg-black rounded-lg p-3 h-52 overflow-y-auto font-mono text-[11px] space-y-1 border border-white/5">
                    {output.length > 0 ? (
                      output.map((line, idx) => (
                        <div key={idx} className="text-green-400 break-all">
                          {line}
                        </div>
                      ))
                    ) : (
                      <div className="text-[var(--text-dim)]">No logs yet.</div>
                    )}
                  </div>
                </div>
              </div>
            </details>
          )}

        </div>

        {/* Right column */}
        <TodoSidebar items={todoItems} />
      </div>

      <ApprovalModal request={approvalRequest} onDecision={onApprovalDecision} />
      <QuestionModal request={questionRequest} onAnswer={onAnswer} />
    </div>
  );
}
