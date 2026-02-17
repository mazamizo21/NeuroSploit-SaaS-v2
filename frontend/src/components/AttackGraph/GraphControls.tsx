"use client";

import { Box, Layers, Tag, Tags, Maximize2, RotateCcw, ZoomIn, ZoomOut } from "lucide-react";

export type ViewMode = "3d" | "2d";

interface GraphControlsProps {
  viewMode: ViewMode;
  labelsOn: boolean;
  onToggleView: () => void;
  onToggleLabels: () => void;
  onResetCamera: () => void;
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitToView: () => void;
}

function ControlButton({
  onClick,
  title,
  active,
  children,
}: {
  onClick: () => void;
  title: string;
  active?: boolean;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      title={title}
      className={`p-1.5 rounded-lg border transition-all ${
        active
          ? "bg-indigo-500/20 border-indigo-500/40 text-indigo-300"
          : "bg-[var(--surface2)] border-[var(--border)] text-[var(--text-dim)] hover:text-white hover:bg-white/5"
      }`}
    >
      {children}
    </button>
  );
}

export default function GraphControls({
  viewMode,
  labelsOn,
  onToggleView,
  onToggleLabels,
  onResetCamera,
  onZoomIn,
  onZoomOut,
  onFitToView,
}: GraphControlsProps) {
  return (
    <div className="absolute top-3 right-3 z-10 flex flex-col gap-1.5">
      <ControlButton
        onClick={onToggleView}
        title={viewMode === "3d" ? "Switch to 2D view" : "Switch to 3D view"}
        active={viewMode === "3d"}
      >
        {viewMode === "3d" ? (
          <Box className="w-4 h-4" />
        ) : (
          <Layers className="w-4 h-4" />
        )}
      </ControlButton>

      <ControlButton
        onClick={onToggleLabels}
        title={labelsOn ? "Hide labels" : "Show labels"}
        active={labelsOn}
      >
        {labelsOn ? <Tag className="w-4 h-4" /> : <Tags className="w-4 h-4 opacity-50" />}
      </ControlButton>

      <div className="h-px bg-[var(--border)] my-0.5" />

      <ControlButton onClick={onZoomIn} title="Zoom in">
        <ZoomIn className="w-4 h-4" />
      </ControlButton>

      <ControlButton onClick={onZoomOut} title="Zoom out">
        <ZoomOut className="w-4 h-4" />
      </ControlButton>

      <ControlButton onClick={onFitToView} title="Fit to view">
        <Maximize2 className="w-4 h-4" />
      </ControlButton>

      <ControlButton onClick={onResetCamera} title="Reset camera">
        <RotateCcw className="w-4 h-4" />
      </ControlButton>
    </div>
  );
}
