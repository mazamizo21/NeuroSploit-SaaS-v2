"use client";

import { GraphNode, NODE_COLORS, NODE_LABELS } from "@/lib/graphTypes";
import { X } from "lucide-react";

interface NodeDetailPanelProps {
  node: GraphNode | null;
  onClose: () => void;
}

function PropertyRow({ label, value }: { label: string; value: string | number | boolean | undefined }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <div className="flex justify-between items-start gap-2 py-1.5 border-b border-white/5 last:border-0">
      <span className="text-[11px] text-[var(--text-dim)] shrink-0 uppercase tracking-wide">{label}</span>
      <span className="text-[11px] text-slate-200 text-right break-all font-mono">
        {typeof value === "boolean" ? (value ? "Yes" : "No") : String(value)}
      </span>
    </div>
  );
}

export default function NodeDetailPanel({ node, onClose }: NodeDetailPanelProps) {
  if (!node) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-center px-4">
        <div className="text-4xl mb-3 opacity-30">🎯</div>
        <p className="text-sm text-[var(--text-dim)]">Select a node</p>
        <p className="text-xs text-[var(--text-dim)] mt-1 opacity-60">
          Click any node in the graph to view its details
        </p>
      </div>
    );
  }

  const typeColor = NODE_COLORS[node.type] || "#888";
  const typeLabel = NODE_LABELS[node.type] || node.type;

  // Gather all displayable properties
  const metadata = node.metadata || {};

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="px-4 py-3 border-b border-[var(--border)] flex items-center justify-between shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <div
            className="w-3 h-3 rounded-full shrink-0"
            style={{ backgroundColor: typeColor, boxShadow: `0 0 8px ${typeColor}60` }}
          />
          <span className="text-xs font-bold text-slate-200 truncate">{node.label}</span>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded hover:bg-white/10 transition shrink-0"
          title="Close panel"
        >
          <X className="w-3.5 h-3.5 text-[var(--text-dim)]" />
        </button>
      </div>

      {/* Type badge */}
      <div className="px-4 py-2 shrink-0">
        <span
          className="inline-flex items-center gap-1.5 text-[10px] font-bold uppercase px-2 py-0.5 rounded-full border"
          style={{
            color: typeColor,
            borderColor: `${typeColor}40`,
            backgroundColor: `${typeColor}15`,
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ backgroundColor: typeColor }}
          />
          {typeLabel}
        </span>
      </div>

      {/* Properties */}
      <div className="flex-1 overflow-y-auto px-4 pb-4 custom-scrollbar">
        <div className="space-y-0">
          <PropertyRow label="ID" value={node.id} />
          <PropertyRow label="Name" value={node.label} />
          <PropertyRow label="Type" value={typeLabel} />
          <PropertyRow label="Description" value={node.description} />
          <PropertyRow label="Risk Score" value={node.risk_score} />
          <PropertyRow label="Severity" value={node.severity} />
          <PropertyRow label="CVE" value={node.cve_id} />
          <PropertyRow label="CWE" value={node.cwe_id} />
          <PropertyRow label="Confidence" value={node.confidence} />
          <PropertyRow label="Detected By" value={node.detected_by} />
          <PropertyRow label="Version" value={node.version} />
          <PropertyRow label="Port" value={node.port} />
          <PropertyRow label="Protocol" value={node.protocol} />
          <PropertyRow label="Username" value={node.username} />
          <PropertyRow label="Service" value={node.service} />
          <PropertyRow label="Source" value={node.source} />
          <PropertyRow label="Created" value={node.created_at} />
          <PropertyRow label="Updated" value={node.updated_at} />

          {/* MITRE Techniques */}
          {node.mitre_techniques && node.mitre_techniques.length > 0 && (
            <div className="py-2 border-b border-white/5">
              <span className="text-[10px] text-[var(--text-dim)] uppercase tracking-wide block mb-1">
                MITRE Techniques
              </span>
              <div className="flex flex-wrap gap-1">
                {node.mitre_techniques.map((t) => (
                  <span
                    key={t}
                    className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-300 border border-cyan-500/25"
                  >
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Extra metadata */}
          {Object.keys(metadata).length > 0 && (
            <div className="py-2">
              <span className="text-[10px] text-[var(--text-dim)] uppercase tracking-wide block mb-1">
                Metadata
              </span>
              <div className="space-y-0">
                {Object.entries(metadata)
                  .filter(([, v]) => v !== null && v !== undefined && v !== "")
                  .map(([key, value]) => (
                    <PropertyRow
                      key={key}
                      label={key.replace(/_/g, " ")}
                      value={
                        typeof value === "object"
                          ? JSON.stringify(value).slice(0, 200)
                          : String(value)
                      }
                    />
                  ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
