"use client";

import React from "react";
import { PauseCircle, PlayCircle } from "lucide-react";

import { cn } from "@/lib/utils";

export function StopResumeButton({
  jobStatus,
  connected,
  onStop,
  onResume,
}: {
  jobStatus: string | null;
  connected: boolean;
  onStop: () => void;
  onResume: () => void;
}) {
  const status = String(jobStatus || "").toLowerCase();

  if (status === "running") {
    return (
      <button
        onClick={onStop}
        disabled={!connected}
        className={cn(
          "inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm border",
          "border-rose-500/30 bg-rose-500/10 text-rose-200 hover:bg-rose-500/15",
          !connected && "opacity-50 cursor-not-allowed"
        )}
        title={connected ? "Pause job" : "Chat socket offline"}
      >
        <PauseCircle className="w-4 h-4" /> Pause
      </button>
    );
  }

  if (status === "paused") {
    return (
      <button
        onClick={onResume}
        disabled={!connected}
        className={cn(
          "inline-flex items-center gap-2 px-3 py-2 rounded-lg text-sm border",
          "border-emerald-500/30 bg-emerald-500/10 text-emerald-100 hover:bg-emerald-500/15",
          !connected && "opacity-50 cursor-not-allowed"
        )}
        title={connected ? "Resume job" : "Chat socket offline"}
      >
        <PlayCircle className="w-4 h-4" /> Resume
      </button>
    );
  }

  return null;
}
