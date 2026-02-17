"use client";

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw, Save, SlidersHorizontal, Trash2 } from "lucide-react";

import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { Card } from "@/components/Card";

type JobSettings = {
  USE_STRUCTURED_OUTPUT?: boolean;
  TOOL_USAGE_TRACKER_ENABLED?: boolean;
  EXPLOITATION_INJECTOR_ENABLED?: boolean;
  TOOL_PHASE_GATE_ENABLED?: boolean;
  REQUIRE_APPROVAL_FOR_EXPLOITATION?: boolean;
  REQUIRE_APPROVAL_FOR_POST_EXPLOITATION?: boolean;
  KNOWLEDGE_GRAPH_ENABLED?: boolean;
  KG_INJECT_EVERY?: number;
  KG_SUMMARY_MAX_CHARS?: number;
  AUTO_COMPLETE_IDLE_ITERATIONS?: number;
  AUTO_COMPLETE_MIN_ITERATIONS?: number;
  LLM_THINKING_ENABLED?: boolean;
};

type BoolTri = "inherit" | "true" | "false";

function boolToTri(val: boolean | undefined): BoolTri {
  if (val === undefined) return "inherit";
  return val ? "true" : "false";
}

function triToBool(val: BoolTri): boolean | undefined {
  if (val === "inherit") return undefined;
  return val === "true";
}

function normalizeSettings(raw: any): JobSettings {
  if (!raw || typeof raw !== "object") return {};
  const out: JobSettings = {};
  for (const [k, v] of Object.entries(raw)) {
    (out as any)[String(k).toUpperCase()] = v;
  }
  return out;
}

export default function JobSettingsOverridesCard({
  jobId,
  jobStatus,
  className,
}: {
  jobId: string;
  jobStatus?: string | null;
  className?: string;
}) {
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string>("");
  const [lastSaved, setLastSaved] = useState<string>("");
  const [settings, setSettings] = useState<JobSettings>({});

  const overrideCount = useMemo(() => Object.keys(settings || {}).length, [settings]);

  const load = useCallback(async () => {
    if (!jobId) return;
    setLoading(true);
    setError("");
    try {
      const res = await api.get(`/api/v1/jobs/${jobId}/settings`);
      setSettings(normalizeSettings(res?.settings));
    } catch (e: any) {
      setError(String(e?.message || e || "Failed to load job settings"));
      setSettings({});
    } finally {
      setLoading(false);
    }
  }, [jobId]);

  const save = useCallback(
    async (next: JobSettings) => {
      if (!jobId) return;
      setSaving(true);
      setError("");
      try {
        const res = await api.put(`/api/v1/jobs/${jobId}/settings`, {
          settings: next || {},
        });
        setSettings(normalizeSettings(res?.settings));
        setLastSaved(new Date().toLocaleTimeString());
      } catch (e: any) {
        setError(String(e?.message || e || "Failed to save job settings"));
      } finally {
        setSaving(false);
      }
    },
    [jobId]
  );

  useEffect(() => {
    load();
  }, [load]);

  const setBool = useCallback((key: keyof JobSettings, tri: BoolTri) => {
    const boolVal = triToBool(tri);
    setSettings((prev) => {
      const next = { ...(prev || {}) } as JobSettings;
      if (boolVal === undefined) {
        delete (next as any)[key];
      } else {
        (next as any)[key] = boolVal;
      }
      return next;
    });
  }, []);

  const setInt = useCallback((key: keyof JobSettings, raw: string) => {
    setSettings((prev) => {
      const next = { ...(prev || {}) } as JobSettings;
      const token = String(raw || "").trim();
      if (!token) {
        delete (next as any)[key];
        return next;
      }
      const num = Number(token);
      if (!Number.isFinite(num)) {
        return next;
      }
      (next as any)[key] = Math.trunc(num);
      return next;
    });
  }, []);

  const fields = useMemo(
    () =>
      [
        {
          key: "LLM_THINKING_ENABLED" as const,
          label: "LLM thinking mode",
          help: "Enable provider native thinking/reasoning (slower + higher cost; useful for complex chains).",
          type: "bool" as const,
        },
        {
          key: "AUTO_COMPLETE_IDLE_ITERATIONS" as const,
          label: "Auto-complete idle iterations",
          help: "When all vulns are resolved, stop after N idle iterations (0 disables).",
          type: "int" as const,
        },
        {
          key: "AUTO_COMPLETE_MIN_ITERATIONS" as const,
          label: "Auto-complete min iterations",
          help: "Minimum iterations before auto-complete is allowed (0 disables the minimum).",
          type: "int" as const,
        },
        {
          key: "REQUIRE_APPROVAL_FOR_EXPLOITATION" as const,
          label: "Approval before exploitation",
          help: "Pauses the agent before entering exploitation phase (uses WebSocket approval flow).",
          type: "bool" as const,
        },
        {
          key: "REQUIRE_APPROVAL_FOR_POST_EXPLOITATION" as const,
          label: "Approval before post-exploit",
          help: "Pauses the agent before entering post-exploitation phase.",
          type: "bool" as const,
        },
        {
          key: "KNOWLEDGE_GRAPH_ENABLED" as const,
          label: "Knowledge Graph (Neo4j)",
          help: "Enable/disable KG writes and periodic KG context injection.",
          type: "bool" as const,
        },
        {
          key: "KG_INJECT_EVERY" as const,
          label: "KG inject interval",
          help: "Inject KG summary every N iterations (bounded 1–50).",
          type: "int" as const,
        },
        {
          key: "KG_SUMMARY_MAX_CHARS" as const,
          label: "KG summary max chars",
          help: "Upper bound for injected KG summary (bounded 200–20000).",
          type: "int" as const,
        },
        {
          key: "TOOL_PHASE_GATE_ENABLED" as const,
          label: "Tool phase gate",
          help: "Enable/disable tool-phase restrictions (skill/tool mapping).",
          type: "bool" as const,
        },
        {
          key: "TOOL_USAGE_TRACKER_ENABLED" as const,
          label: "Tool usage tracker",
          help: "Tracks tool usage patterns and publishes structured events.",
          type: "bool" as const,
        },
        {
          key: "EXPLOITATION_INJECTOR_ENABLED" as const,
          label: "Exploitation injector",
          help: "Enables proactive exploitation nudges when recon stalls.",
          type: "bool" as const,
        },
        {
          key: "USE_STRUCTURED_OUTPUT" as const,
          label: "Structured output",
          help: "Enable structured agent events (recommended ON for UI + live telemetry).",
          type: "bool" as const,
        },
      ] as const,
    []
  );

  return (
    <Card className={cn("space-y-4", className)}>
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <SlidersHorizontal className="w-4 h-4 text-indigo-300" />
            <h3 className="text-sm font-medium">Job Settings Overrides</h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[var(--surface2)] border border-[var(--border)] text-[var(--text-dim)]">
              {overrideCount} overrides
            </span>
          </div>
          <p className="text-xs text-[var(--text-dim)] mt-1">
            Stored in Redis at <code className="px-1 rounded bg-black/20">job:{jobId}:settings</code>. Applied when the agent starts/resumes.
            {jobStatus === "running" ? " (Job is running; changes apply on resume.)" : ""}
          </p>
          {!!lastSaved && (
            <p className="text-[10px] text-[var(--text-dim)] mt-1 font-mono">last_saved: {lastSaved}</p>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={load}
            disabled={loading}
            className="px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] text-xs hover:bg-white/5 disabled:opacity-50 transition inline-flex items-center gap-1"
            title="Reload"
          >
            <RefreshCw className={cn("w-3 h-3", loading ? "animate-spin" : "")} />
            Reload
          </button>
          <button
            type="button"
            onClick={() => save(settings)}
            disabled={saving || loading}
            className="px-3 py-2 rounded-lg bg-emerald-600 text-white text-xs hover:bg-emerald-500 disabled:opacity-50 transition inline-flex items-center gap-1"
            title="Save overrides"
          >
            <Save className={cn("w-3 h-3", saving ? "animate-pulse" : "")} />
            Save
          </button>
          <button
            type="button"
            onClick={() => save({})}
            disabled={saving || loading}
            className="px-3 py-2 rounded-lg bg-rose-600/20 text-rose-200 border border-rose-500/30 text-xs hover:bg-rose-600/25 disabled:opacity-50 transition inline-flex items-center gap-1"
            title="Clear overrides"
          >
            <Trash2 className="w-3 h-3" />
            Clear
          </button>
        </div>
      </div>

      {!!error && (
        <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {fields.map((f) => {
          const rawVal = (settings as any)[f.key];
          return (
            <div
              key={f.key}
              className="rounded-xl border border-[var(--border)] bg-[var(--surface2)] p-4"
            >
              <div className="flex items-start justify-between gap-3">
                <div>
                  <div className="text-xs font-medium">{f.label}</div>
                  <div className="text-[10px] text-[var(--text-dim)] mt-1">{f.help}</div>
                </div>
                <div className="shrink-0">
                  {f.type === "bool" ? (
                    <select
                      value={boolToTri(rawVal as boolean | undefined)}
                      onChange={(e) => setBool(f.key, e.target.value as BoolTri)}
                      className="px-2 py-1 rounded bg-black/20 border border-[var(--border)] text-[11px] font-mono"
                    >
                      <option value="inherit">inherit</option>
                      <option value="true">on</option>
                      <option value="false">off</option>
                    </select>
                  ) : (
                    <input
                      type="number"
                      value={rawVal === undefined ? "" : String(rawVal)}
                      onChange={(e) => setInt(f.key, e.target.value)}
                      placeholder="inherit"
                      className="w-28 px-2 py-1 rounded bg-black/20 border border-[var(--border)] text-[11px] font-mono"
                    />
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <p className="text-[10px] text-[var(--text-dim)]">
        Tip: to revert a single field back to defaults, set it to <span className="font-mono">inherit</span> (or clear its number).
      </p>
    </Card>
  );
}
