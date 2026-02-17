"use client";

import { NODE_COLORS, NODE_LABELS, GraphNodeType } from "@/lib/graphTypes";

const ALL_TYPES: GraphNodeType[] = [
  "Target",
  "Service",
  "Port",
  "Vulnerability",
  "CVE",
  "Exploit",
  "Credential",
  "Endpoint",
  "Technology",
  "MitreTechnique",
];

interface GraphLegendProps {
  activeTypes?: Set<GraphNodeType>;
  onToggleType?: (type: GraphNodeType) => void;
}

export default function GraphLegend({ activeTypes, onToggleType }: GraphLegendProps) {
  return (
    <div className="flex items-center gap-3 flex-wrap px-4 py-2">
      {ALL_TYPES.map((type) => {
        const color = NODE_COLORS[type];
        const label = NODE_LABELS[type];
        const isActive = !activeTypes || activeTypes.has(type);

        return (
          <button
            key={type}
            onClick={() => onToggleType?.(type)}
            className={`flex items-center gap-1.5 text-[10px] transition-all ${
              isActive ? "opacity-100" : "opacity-30"
            } hover:opacity-100`}
            title={`${isActive ? "Hide" : "Show"} ${label} nodes`}
          >
            <span
              className="w-2.5 h-2.5 rounded-full shrink-0"
              style={{
                backgroundColor: color,
                boxShadow: isActive ? `0 0 6px ${color}60` : "none",
              }}
            />
            <span className="text-[var(--text-dim)] whitespace-nowrap">{label}</span>
          </button>
        );
      })}
    </div>
  );
}
