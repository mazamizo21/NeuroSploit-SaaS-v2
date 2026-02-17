"use client";

import {
  useRef,
  useEffect,
  useCallback,
  useMemo,
  useState,
  forwardRef,
  useImperativeHandle,
} from "react";
import { GraphNode, GraphLink, GraphData } from "@/lib/graphTypes";
import { ViewMode } from "./GraphControls";

// Direct imports for the force-graph libraries (this component is always loaded client-side via dynamic())
import ForceGraph3D from "react-force-graph-3d";
import ForceGraph2D from "react-force-graph-2d";
import SpriteText from "three-spritetext";
import * as THREE from "three";

// ─── Types ─────────────────────────────────────────────────────────────────
export interface ForceGraphHandle {
  zoomIn: () => void;
  zoomOut: () => void;
  fitToView: () => void;
  resetCamera: () => void;
}

interface ForceGraphProps {
  data: GraphData;
  viewMode: ViewMode;
  labelsOn: boolean;
  selectedNodeId: string | null;
  newNodeIds: Set<string>;
  onNodeClick: (node: GraphNode) => void;
  onBackgroundClick: () => void;
  width: number;
  height: number;
}

// ─── Component ─────────────────────────────────────────────────────────────
const ForceGraphView = forwardRef<ForceGraphHandle, ForceGraphProps>(
  function ForceGraphView(
    {
      data,
      viewMode,
      labelsOn,
      selectedNodeId,
      newNodeIds,
      onNodeClick,
      onBackgroundClick,
      width,
      height,
    },
    ref
  ) {
    const fgRef = useRef<any>(null);
    const [hoveredNodeId, setHoveredNodeId] = useState<string | null>(null);

    // Connected node IDs (for edge highlighting)
    const connectedIds = useMemo(() => {
      const ids = new Set<string>();
      if (!selectedNodeId) return ids;
      ids.add(selectedNodeId);
      for (const link of data.links) {
        const src = typeof link.source === "string" ? link.source : link.source.id;
        const tgt = typeof link.target === "string" ? link.target : link.target.id;
        if (src === selectedNodeId) ids.add(tgt);
        if (tgt === selectedNodeId) ids.add(src);
      }
      return ids;
    }, [selectedNodeId, data.links]);

    // Expose imperative methods
    useImperativeHandle(ref, () => ({
      zoomIn: () => {
        const fg = fgRef.current;
        if (!fg) return;
        if (viewMode === "3d") {
          const dist = fg.cameraPosition().z || 500;
          fg.cameraPosition({ z: dist * 0.7 }, undefined, 300);
        } else {
          const currentZoom = fg.zoom?.() || 1;
          fg.zoom?.(currentZoom * 1.3, 300);
        }
      },
      zoomOut: () => {
        const fg = fgRef.current;
        if (!fg) return;
        if (viewMode === "3d") {
          const dist = fg.cameraPosition().z || 500;
          fg.cameraPosition({ z: dist * 1.4 }, undefined, 300);
        } else {
          const currentZoom = fg.zoom?.() || 1;
          fg.zoom?.(currentZoom * 0.7, 300);
        }
      },
      fitToView: () => {
        fgRef.current?.zoomToFit?.(400, 50);
      },
      resetCamera: () => {
        const fg = fgRef.current;
        if (!fg) return;
        if (viewMode === "3d") {
          fg.cameraPosition({ x: 0, y: 0, z: 500 }, { x: 0, y: 0, z: 0 }, 600);
        } else {
          fg.centerAt?.(0, 0, 400);
          fg.zoom?.(1, 400);
        }
      },
    }));

    // Auto-fit on data change
    useEffect(() => {
      const timer = setTimeout(() => {
        fgRef.current?.zoomToFit?.(400, 50);
      }, 500);
      return () => clearTimeout(timer);
    }, [data.nodes.length]);

    // ─── Node rendering (3D) ─────────────────────────────────────────────
    const nodeThreeObject = useCallback(
      (node: GraphNode) => {

        const isSelected = node.id === selectedNodeId;
        const isConnected = connectedIds.has(node.id);
        const isHovered = node.id === hoveredNodeId;
        const isNew = newNodeIds.has(node.id);

        // Create sphere
        const radius = node.size * (isSelected ? 1.5 : isHovered ? 1.2 : 1);
        const geometry = new THREE.SphereGeometry(radius, 16, 16);
        const material = new THREE.MeshLambertMaterial({
          color: node.color,
          transparent: true,
          opacity: isSelected || isConnected || !selectedNodeId ? 0.9 : 0.3,
          emissive: isHovered || isSelected ? node.color : "#000000",
          emissiveIntensity: isHovered ? 0.5 : isSelected ? 0.3 : 0,
        });

        const mesh = new THREE.Mesh(geometry, material);

        // Glow effect for selected/hovered
        if (isSelected || isHovered) {
          const glowGeometry = new THREE.SphereGeometry(radius * 1.6, 16, 16);
          const glowMaterial = new THREE.MeshBasicMaterial({
            color: node.color,
            transparent: true,
            opacity: 0.15,
          });
          const glow = new THREE.Mesh(glowGeometry, glowMaterial);
          mesh.add(glow);
        }

        // Scale-up animation for new nodes
        if (isNew) {
          mesh.scale.set(0.01, 0.01, 0.01);
          const animate = () => {
            if (mesh.scale.x < 1) {
              mesh.scale.multiplyScalar(1.08);
              requestAnimationFrame(animate);
            } else {
              mesh.scale.set(1, 1, 1);
            }
          };
          requestAnimationFrame(animate);
        }

        // Add label sprite if labels are on
        if (labelsOn) {
          const sprite = new SpriteText(node.label);
          sprite.color = "#e2e8f0";
          sprite.textHeight = 3.5;
          sprite.backgroundColor = "rgba(0,0,0,0.6)";
          sprite.padding = 1;
          sprite.borderRadius = 2;
          sprite.position.set(0, radius + 5, 0);
          mesh.add(sprite);
        }

        return mesh;
      },
      [selectedNodeId, connectedIds, hoveredNodeId, newNodeIds, labelsOn]
    );

    // ─── Link styling ────────────────────────────────────────────────────
    const linkColor = useCallback(
      (link: GraphLink) => {
        if (!selectedNodeId) return "rgba(136, 136, 136, 0.3)";
        const src = typeof link.source === "string" ? link.source : link.source.id;
        const tgt = typeof link.target === "string" ? link.target : link.target.id;
        if (connectedIds.has(src) && connectedIds.has(tgt)) {
          return "rgba(136, 136, 255, 0.8)";
        }
        return "rgba(136, 136, 136, 0.08)";
      },
      [selectedNodeId, connectedIds]
    );

    const linkWidth = useCallback(
      (link: GraphLink) => {
        if (!selectedNodeId) return 1;
        const src = typeof link.source === "string" ? link.source : link.source.id;
        const tgt = typeof link.target === "string" ? link.target : link.target.id;
        return connectedIds.has(src) && connectedIds.has(tgt) ? 2.5 : 0.5;
      },
      [selectedNodeId, connectedIds]
    );

    // ─── Link label for 3D (optional) ────────────────────────────────────
    const linkThreeObject = useCallback(
      (link: GraphLink) => {
        if (!labelsOn) return undefined;
        const sprite = new SpriteText(link.label || link.type || "");
        sprite.color = "rgba(148, 163, 184, 0.5)";
        sprite.textHeight = 2;
        return sprite;
      },
      [labelsOn]
    );

    const linkPositionUpdate = useCallback(
      (sprite: any, { start, end }: { start: any; end: any }) => {
        if (!sprite || !start || !end) return;
        const mid = {
          x: (start.x + end.x) / 2,
          y: (start.y + end.y) / 2,
          z: (start.z + end.z) / 2,
        };
        Object.assign(sprite.position, mid);
      },
      []
    );

    // ─── 2D Node rendering ──────────────────────────────────────────────
    const nodeCanvasObject2D = useCallback(
      (node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
        const isSelected = node.id === selectedNodeId;
        const isConnected = connectedIds.has(node.id);
        const isHovered = node.id === hoveredNodeId;
        const r = node.size * (isSelected ? 1.5 : isHovered ? 1.2 : 1);
        const x = node.x || 0;
        const y = node.y || 0;

        // Glow
        if (isSelected || isHovered) {
          ctx.beginPath();
          ctx.arc(x, y, r * 2, 0, 2 * Math.PI);
          ctx.fillStyle = `${node.color}20`;
          ctx.fill();
        }

        // Node circle
        ctx.beginPath();
        ctx.arc(x, y, r, 0, 2 * Math.PI);
        ctx.fillStyle = isSelected || isConnected || !selectedNodeId
          ? node.color
          : `${node.color}40`;
        ctx.fill();

        // Border
        if (isSelected) {
          ctx.strokeStyle = "#ffffff";
          ctx.lineWidth = 1.5;
          ctx.stroke();
        }

        // Label
        if (labelsOn && globalScale > 0.5) {
          const fontSize = Math.max(3, 12 / globalScale);
          ctx.font = `${fontSize}px Inter, sans-serif`;
          ctx.textAlign = "center";
          ctx.textBaseline = "top";
          ctx.fillStyle = "rgba(226, 232, 240, 0.85)";
          ctx.fillText(node.label, x, y + r + 2);
        }
      },
      [selectedNodeId, connectedIds, hoveredNodeId, labelsOn]
    );

    // ─── Event handlers ─────────────────────────────────────────────────
    const handleNodeClick = useCallback(
      (node: any) => {
        onNodeClick(node as GraphNode);

        // Focus camera on node
        const fg = fgRef.current;
        if (fg && viewMode === "3d") {
          const distance = 200;
          const distRatio = 1 + distance / Math.hypot(node.x || 0, node.y || 0, node.z || 0);
          fg.cameraPosition(
            {
              x: (node.x || 0) * distRatio,
              y: (node.y || 0) * distRatio,
              z: (node.z || 0) * distRatio,
            },
            { x: node.x, y: node.y, z: node.z },
            600
          );
        }
      },
      [onNodeClick, viewMode]
    );

    const handleNodeHover = useCallback(
      (node: any) => setHoveredNodeId(node ? node.id : null),
      []
    );

    // ─── Common props ────────────────────────────────────────────────────
    const commonProps = {
      ref: fgRef,
      graphData: data,
      width,
      height,
      backgroundColor: "#0a0a0a",
      nodeId: "id",
      nodeLabel: (node: any) => `${(node as GraphNode).label} (${(node as GraphNode).type})`,
      onNodeClick: handleNodeClick,
      onNodeHover: handleNodeHover,
      onBackgroundClick: onBackgroundClick,
      linkColor: linkColor as any,
      linkWidth: linkWidth as any,
      linkDirectionalParticles: 2,
      linkDirectionalParticleWidth: 1.5,
      linkDirectionalParticleSpeed: 0.005,
      cooldownTicks: 100,
      warmupTicks: 50,
      d3AlphaDecay: 0.02,
      d3VelocityDecay: 0.3,
    };

    // ─── Render ──────────────────────────────────────────────────────────
    if (viewMode === "3d") {
      return (
        <ForceGraph3D
          {...(commonProps as any)}
          nodeThreeObject={nodeThreeObject}
          nodeThreeObjectExtend={false}
          linkThreeObject={labelsOn ? (linkThreeObject as any) : undefined}
          linkThreeObjectExtend={false}
          linkPositionUpdate={labelsOn ? (linkPositionUpdate as any) : undefined}
          linkOpacity={0.3}
          enableNodeDrag={true}
          enableNavigationControls={true}
          showNavInfo={false}
        />
      );
    }

    return (
      <ForceGraph2D
        {...(commonProps as any)}
        nodeCanvasObject={nodeCanvasObject2D}
        nodePointerAreaPaint={(node: any, color: string, ctx: CanvasRenderingContext2D) => {
          const r = (node as GraphNode).size * 1.5;
          ctx.beginPath();
          ctx.arc(node.x || 0, node.y || 0, r, 0, 2 * Math.PI);
          ctx.fillStyle = color;
          ctx.fill();
        }}
        linkLineDash={[2, 2]}
        enableZoomInteraction={true}
        enablePanInteraction={true}
        enableNodeDrag={true}
      />
    );
  }
);

export default ForceGraphView;
