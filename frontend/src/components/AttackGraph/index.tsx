"use client";

import {
  useState,
  useEffect,
  useRef,
  useCallback,
  useMemo,
} from "react";
import dynamic from "next/dynamic";
import { GraphData, GraphNode, GraphNodeType } from "@/lib/graphTypes";
import { fetchAttackGraph, mergeGraphData, GraphApiResponse } from "@/lib/graphApi";
import NodeDetailPanel from "./NodeDetailPanel";
import GraphLegend from "./GraphLegend";
import GraphControls, { ViewMode } from "./GraphControls";
import { RefreshCw, AlertTriangle, Wifi } from "lucide-react";
import type { ForceGraphHandle } from "./ForceGraph";

// Dynamic import of ForceGraph (it uses WebGL/Canvas, must be client-only)
const ForceGraphView = dynamic(() => import("./ForceGraph"), {
  ssr: false,
  loading: () => (
    <div className="w-full h-full flex items-center justify-center bg-[#0a0a0a]">
      <div className="text-center">
        <div className="text-4xl mb-3 animate-spin-slow">🌐</div>
        <p className="text-sm text-[var(--text-dim)] animate-pulse">Loading 3D engine...</p>
      </div>
    </div>
  ),
});

// ─── Props ─────────────────────────────────────────────────────────────────
interface AttackGraphProps {
  jobId: string;
  isRunning?: boolean;
  pollIntervalMs?: number;
}

// ─── Component ─────────────────────────────────────────────────────────────
export default function AttackGraph({
  jobId,
  isRunning = false,
  pollIntervalMs = 10000,
}: AttackGraphProps) {
  // ─── State ─────────────────────────────────────────────────────────────
  const [graphData, setGraphData] = useState<GraphData>({ nodes: [], links: [] });
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>("3d");
  const [labelsOn, setLabelsOn] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [source, setSource] = useState<string>("unknown");
  const [lastUpdate, setLastUpdate] = useState<string>("");
  const [newNodeIds, setNewNodeIds] = useState<Set<string>>(new Set());
  const [isPolling, setIsPolling] = useState(false);
  const [activeTypes, setActiveTypes] = useState<Set<GraphNodeType>>(
    () => new Set<GraphNodeType>([
      "Target", "Service", "Port", "Vulnerability", "CVE",
      "Exploit", "Credential", "Endpoint", "Technology", "MitreTechnique",
    ])
  );

  // Refs
  const containerRef = useRef<HTMLDivElement>(null);
  const graphRef = useRef<ForceGraphHandle>(null);
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  // ─── Resize observer ──────────────────────────────────────────────────
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        const { width, height } = entry.contentRect;
        setDimensions({ width: Math.floor(width), height: Math.floor(height) });
      }
    });

    observer.observe(container);
    // Set initial size
    setDimensions({
      width: Math.floor(container.clientWidth),
      height: Math.floor(container.clientHeight),
    });

    return () => observer.disconnect();
  }, []);

  // ─── Fetch graph data ────────────────────────────────────────────────
  const loadGraph = useCallback(
    async (isInitial = false) => {
      try {
        if (isInitial) setLoading(true);
        else setIsPolling(true);

        const resp: GraphApiResponse = await fetchAttackGraph(jobId);

        if (isInitial || graphData.nodes.length === 0) {
          setGraphData({ nodes: resp.nodes, links: resp.links });
          setNewNodeIds(new Set());
        } else {
          // Merge with existing data
          const merged = mergeGraphData(graphData, {
            nodes: resp.nodes,
            links: resp.links,
          });

          if (merged) {
            setGraphData(merged.data);
            // Track new nodes for animation
            if (merged.newNodeIds.length > 0) {
              setNewNodeIds(new Set(merged.newNodeIds));
              // Clear new node highlighting after animation
              setTimeout(() => setNewNodeIds(new Set()), 3000);
            }
          }
        }

        setSource(resp.source);
        setLastUpdate(new Date().toLocaleTimeString());
        setError(null);
      } catch (err) {
        if (isInitial) {
          setError(err instanceof Error ? err.message : "Failed to load graph");
        }
      } finally {
        setLoading(false);
        setIsPolling(false);
      }
    },
    [jobId, graphData]
  );

  // Initial load
  useEffect(() => {
    loadGraph(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId]);

  // Polling for real-time updates
  useEffect(() => {
    if (!isRunning || !pollIntervalMs) return;
    const interval = setInterval(() => loadGraph(false), pollIntervalMs);
    return () => clearInterval(interval);
  }, [isRunning, pollIntervalMs, loadGraph]);

  // ─── Filter data by active types ─────────────────────────────────────
  const filteredData = useMemo(() => {
    const visibleNodes = graphData.nodes.filter((n) => activeTypes.has(n.type));
    const visibleNodeIds = new Set(visibleNodes.map((n) => n.id));
    const visibleLinks = graphData.links.filter((l) => {
      const src = typeof l.source === "string" ? l.source : l.source.id;
      const tgt = typeof l.target === "string" ? l.target : l.target.id;
      return visibleNodeIds.has(src) && visibleNodeIds.has(tgt);
    });
    return { nodes: visibleNodes, links: visibleLinks };
  }, [graphData, activeTypes]);

  // ─── Handlers ────────────────────────────────────────────────────────
  const handleNodeClick = useCallback((node: GraphNode) => {
    setSelectedNode(node);
  }, []);

  const handleBackgroundClick = useCallback(() => {
    setSelectedNode(null);
  }, []);

  const handleToggleType = useCallback((type: GraphNodeType) => {
    setActiveTypes((prev) => {
      const next = new Set(prev);
      if (next.has(type)) {
        next.delete(type);
      } else {
        next.add(type);
      }
      return next;
    });
  }, []);

  // ─── Render ──────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="w-full h-[600px] rounded-xl border border-[var(--border)] bg-[#0a0a0a] flex items-center justify-center">
        <div className="text-center">
          <div className="text-5xl mb-4 animate-spin-slow">🌐</div>
          <p className="text-sm text-[var(--text-dim)] animate-pulse">
            Building attack graph...
          </p>
          <p className="text-xs text-[var(--text-dim)] mt-1 opacity-50">
            Querying knowledge graph for job data
          </p>
        </div>
      </div>
    );
  }

  if (error && graphData.nodes.length === 0) {
    return (
      <div className="w-full h-[600px] rounded-xl border border-red-500/30 bg-[#0a0a0a] flex items-center justify-center">
        <div className="text-center max-w-md">
          <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
          <p className="text-sm text-red-300 mb-2">Failed to load attack graph</p>
          <p className="text-xs text-[var(--text-dim)] mb-4">{error}</p>
          <button
            onClick={() => loadGraph(true)}
            className="px-4 py-2 rounded-lg bg-red-600/20 text-red-300 hover:bg-red-600/30 transition text-sm"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  if (graphData.nodes.length === 0) {
    return (
      <div className="w-full h-[600px] rounded-xl border border-[var(--border)] bg-[#0a0a0a] flex items-center justify-center">
        <div className="text-center">
          <div className="text-5xl mb-4 opacity-30">🕸️</div>
          <p className="text-sm text-[var(--text-dim)]">No graph data yet</p>
          <p className="text-xs text-[var(--text-dim)] mt-1 opacity-60">
            {isRunning
              ? "Data will appear as the pentest discovers hosts and services..."
              : "Run a pentest to generate the attack graph"}
          </p>
          {isRunning && (
            <div className="mt-3 flex items-center justify-center gap-2 text-xs text-cyan-400 animate-pulse">
              <Wifi className="w-3.5 h-3.5" />
              Listening for updates...
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="w-full rounded-xl border border-[var(--border)] bg-[#0a0a0a] overflow-hidden flex flex-col">
      {/* ─── Main layout: sidebar + graph ─────────────────────────────── */}
      <div className="flex flex-1" style={{ height: "600px" }}>
        {/* Left sidebar — node details */}
        <div className="w-[250px] shrink-0 border-r border-[var(--border)] bg-[var(--surface)] overflow-hidden">
          <NodeDetailPanel
            node={selectedNode}
            onClose={() => setSelectedNode(null)}
          />
        </div>

        {/* Center — force graph */}
        <div className="flex-1 relative" ref={containerRef}>
          <GraphControls
            viewMode={viewMode}
            labelsOn={labelsOn}
            onToggleView={() => setViewMode((m) => (m === "3d" ? "2d" : "3d"))}
            onToggleLabels={() => setLabelsOn((v) => !v)}
            onResetCamera={() => graphRef.current?.resetCamera()}
            onZoomIn={() => graphRef.current?.zoomIn()}
            onZoomOut={() => graphRef.current?.zoomOut()}
            onFitToView={() => graphRef.current?.fitToView()}
          />

          <ForceGraphView
            ref={graphRef}
            data={filteredData}
            viewMode={viewMode}
            labelsOn={labelsOn}
            selectedNodeId={selectedNode?.id || null}
            newNodeIds={newNodeIds}
            onNodeClick={handleNodeClick}
            onBackgroundClick={handleBackgroundClick}
            width={dimensions.width}
            height={dimensions.height}
          />
        </div>
      </div>

      {/* ─── Bottom bar: legend + stats ───────────────────────────────── */}
      <div className="border-t border-[var(--border)] bg-[var(--surface)]">
        <GraphLegend activeTypes={activeTypes} onToggleType={handleToggleType} />

        <div className="flex items-center justify-between px-4 py-1.5 border-t border-[var(--border)] text-[10px] text-[var(--text-dim)]">
          <div className="flex items-center gap-4">
            <span>
              Nodes: <span className="text-slate-300 font-medium">{filteredData.nodes.length}</span>
              {filteredData.nodes.length !== graphData.nodes.length && (
                <span className="opacity-50"> / {graphData.nodes.length}</span>
              )}
            </span>
            <span>
              Links: <span className="text-slate-300 font-medium">{filteredData.links.length}</span>
            </span>
            <span>
              View: <span className="text-slate-300 font-medium uppercase">{viewMode}</span>
            </span>
            <span>
              Labels: <span className="text-slate-300 font-medium">{labelsOn ? "On" : "Off"}</span>
            </span>
          </div>

          <div className="flex items-center gap-3">
            {/* Data source */}
            <span className="flex items-center gap-1">
              Source: <span className="text-slate-300">{source}</span>
            </span>

            {/* Polling indicator */}
            {isRunning && (
              <span className="flex items-center gap-1 text-cyan-400">
                {isPolling ? (
                  <RefreshCw className="w-3 h-3 animate-spin" />
                ) : (
                  <Wifi className="w-3 h-3" />
                )}
                Live
              </span>
            )}

            {/* Last update */}
            {lastUpdate && (
              <span className="opacity-60">Updated: {lastUpdate}</span>
            )}

            {/* Manual refresh */}
            <button
              onClick={() => loadGraph(false)}
              className="p-1 rounded hover:bg-white/10 transition"
              title="Refresh graph"
            >
              <RefreshCw className={`w-3 h-3 ${isPolling ? "animate-spin" : ""}`} />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
