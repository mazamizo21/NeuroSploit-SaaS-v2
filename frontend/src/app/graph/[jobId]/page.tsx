"use client";

import { useParams } from "next/navigation";
import { useEffect, useState } from "react";
import AppShell from "@/app/AppShell";
import { api } from "@/lib/api";
import AttackGraph from "@/components/AttackGraph";
import { ArrowLeft, Network } from "lucide-react";
import Link from "next/link";

export default function GraphPage() {
  return (
    <AppShell>
      <GraphPageInner />
    </AppShell>
  );
}

function GraphPageInner() {
  const { jobId } = useParams();
  const [job, setJob] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!jobId) return;
    api
      .get(`/api/v1/jobs/${jobId}`)
      .then(setJob)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [jobId]);

  // Poll job status for running indicator
  useEffect(() => {
    if (!jobId) return;
    const interval = setInterval(() => {
      api.get(`/api/v1/jobs/${jobId}`).then(setJob).catch(() => {});
    }, 10000);
    return () => clearInterval(interval);
  }, [jobId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <div className="text-4xl mb-3 animate-spin-slow">🌐</div>
          <p className="text-sm text-[var(--text-dim)] animate-pulse">Loading...</p>
        </div>
      </div>
    );
  }

  const isRunning = job?.status === "running";

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Link
          href={`/pentests/${jobId}`}
          className="p-2 rounded-lg hover:bg-white/5 transition"
          title="Back to pentest"
        >
          <ArrowLeft className="w-5 h-5" />
        </Link>
        <div className="flex items-center gap-3 flex-1">
          <Network className="w-5 h-5 text-indigo-400" />
          <div>
            <h1 className="text-xl font-bold">Attack Graph</h1>
            <p className="text-xs text-[var(--text-dim)]">
              {job?.name || "Pentest"} &middot; {(job?.targets || []).join(", ")}
              {isRunning && (
                <span className="text-cyan-400 ml-2 animate-pulse">● LIVE</span>
              )}
            </p>
          </div>
        </div>
        <Link
          href={`/pentests/${jobId}`}
          className="px-3 py-2 rounded-lg bg-[var(--surface2)] border border-[var(--border)] hover:bg-white/5 transition text-sm text-[var(--text-dim)]"
        >
          Back to Pentest
        </Link>
      </div>

      {/* Graph */}
      <AttackGraph
        jobId={String(jobId)}
        isRunning={isRunning}
        pollIntervalMs={isRunning ? 8000 : 0}
      />
    </div>
  );
}
