"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";

interface HeatmapCell {
  technique_id: string;
  technique_name: string;
  tactic: string;
  count: number;
  jobs: string[];
}

interface Tactic {
  id: string;
  name: string;
  shortName: string;
}

function intensityColor(count: number): string {
  if (count === 0) return "bg-white/5";
  if (count === 1) return "bg-blue-900/60";
  if (count <= 3) return "bg-blue-700/70";
  if (count <= 5) return "bg-blue-500/80";
  return "bg-blue-400/90";
}

function intensityTextColor(count: number): string {
  if (count === 0) return "text-[var(--text-dim)]";
  return "text-white";
}

export default function MitreHeatmap() {
  const [data, setData] = useState<{ tactics: Tactic[]; techniques: HeatmapCell[] } | null>(null);
  const [hoveredCell, setHoveredCell] = useState<HeatmapCell | null>(null);

  useEffect(() => {
    api.get("/api/v1/dashboard/mitre-heatmap").then(setData).catch(() => {});
  }, []);

  if (!data) {
    return (
      <div className="text-sm text-[var(--text-dim)] p-4">Loading MITRE heatmap...</div>
    );
  }

  // Group techniques by tactic
  const byTactic: Record<string, HeatmapCell[]> = {};
  for (const t of data.tactics) {
    byTactic[t.id] = [];
  }
  for (const cell of data.techniques) {
    if (byTactic[cell.tactic]) {
      byTactic[cell.tactic].push(cell);
    }
  }

  return (
    <div className="relative">
      {/* Hover tooltip */}
      {hoveredCell && (
        <div className="absolute -top-12 left-1/2 -translate-x-1/2 z-10 bg-[var(--surface)] border border-[var(--border)] rounded-lg px-3 py-2 text-xs shadow-lg pointer-events-none whitespace-nowrap">
          <span className="font-bold">{hoveredCell.technique_id}</span> — {hoveredCell.technique_name}
          <br />
          <span className="text-[var(--text-dim)]">
            Used {hoveredCell.count}× in jobs: {hoveredCell.jobs.join(", ")}
          </span>
        </div>
      )}

      <div className="overflow-x-auto">
        <div className="flex gap-1 min-w-[700px]">
          {data.tactics.map((tactic) => {
            const cells = byTactic[tactic.id] || [];
            if (cells.length === 0) return null;
            return (
              <div key={tactic.id} className="flex flex-col items-center flex-1 min-w-[60px]">
                <div className="text-[9px] text-[var(--text-dim)] font-medium mb-1 text-center leading-tight h-8 flex items-end">
                  {tactic.shortName}
                </div>
                <div className="flex flex-col gap-0.5 w-full">
                  {cells.map((cell) => (
                    <div
                      key={cell.technique_id}
                      className={`rounded px-1 py-0.5 text-center cursor-pointer transition-all hover:scale-105 ${intensityColor(cell.count)} ${intensityTextColor(cell.count)}`}
                      onMouseEnter={() => setHoveredCell(cell)}
                      onMouseLeave={() => setHoveredCell(null)}
                    >
                      <div className="text-[8px] font-mono leading-none">{cell.technique_id}</div>
                      <div className="text-[7px] leading-none opacity-80">{cell.count}×</div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 mt-3 text-[9px] text-[var(--text-dim)]">
        <span>Intensity:</span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-white/5 border border-white/10" /> 0
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-blue-900/60" /> 1×
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-blue-700/70" /> 2-3×
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-blue-500/80" /> 4-5×
        </span>
        <span className="flex items-center gap-1">
          <span className="w-3 h-3 rounded bg-blue-400/90" /> 5+
        </span>
      </div>
    </div>
  );
}
