"use client";
import { useMemo } from "react";

interface ProgressRingProps {
  current: number;
  max: number;
  size?: number;
  isRunning?: boolean;
}

/**
 * Real-time animated progress ring with:
 * - SVG-based circular progress
 * - Smooth stroke-dashoffset animation
 * - Glowing effect that intensifies with progress
 * - Color transitions: blue (0-25%) → green (25-50%) → yellow (50-75%) → red (75-100%)
 * - Pulsing animation when actively running
 */
export function ProgressRing({ current, max, size = 120, isRunning = false }: ProgressRingProps) {
  const strokeWidth = size * 0.08;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const center = size / 2;
  
  const progress = useMemo(() => {
    if (max <= 0) return 0;
    return Math.min(Math.max((current / max) * 100, 0), 100);
  }, [current, max]);
  
  const strokeDashoffset = circumference - (progress / 100) * circumference;
  
  // Color transitions based on progress percentage
  const { color, glowColor, bgColor } = useMemo(() => {
    if (progress <= 25) {
      // Blue phase
      return {
        color: "#3b82f6",      // blue-500
        glowColor: "#60a5fa",  // blue-400
        bgColor: "rgba(59, 130, 246, 0.1)",
      };
    } else if (progress <= 50) {
      // Green phase
      return {
        color: "#22c55e",      // green-500
        glowColor: "#4ade80",  // green-400
        bgColor: "rgba(34, 197, 94, 0.1)",
      };
    } else if (progress <= 75) {
      // Yellow phase
      return {
        color: "#eab308",      // yellow-500
        glowColor: "#facc15",  // yellow-400
        bgColor: "rgba(234, 179, 8, 0.1)",
      };
    } else {
      // Red phase - approaching max
      return {
        color: "#ef4444",      // red-500
        glowColor: "#f87171",  // red-400
        bgColor: "rgba(239, 68, 68, 0.1)",
      };
    }
  }, [progress]);
  
  // Glow intensity increases with progress
  const glowIntensity = useMemo(() => {
    const base = 2;
    const extra = (progress / 100) * 15;
    return base + extra;
  }, [progress]);
  
  // Filter ID unique per instance to avoid conflicts
  const filterId = useMemo(() => `glow-${Math.random().toString(36).substr(2, 9)}`, []);
  
  return (
    <div className="relative inline-flex items-center justify-center">
      {/* Pulsing background when running */}
      {isRunning && (
        <div 
          className="absolute inset-0 rounded-full animate-ping opacity-20"
          style={{ 
            backgroundColor: glowColor,
            animationDuration: "2s",
          }}
        />
      )}
      
      <svg 
        width={size} 
        height={size} 
        className={`transform -rotate-90 ${isRunning ? "animate-pulse" : ""}`}
        style={{ animationDuration: "3s" }}
      >
        <defs>
          {/* Glow filter */}
          <filter id={filterId} x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation={glowIntensity} result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          
          {/* Gradient for more visual depth */}
          <linearGradient id={`gradient-${filterId}`} x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={glowColor} />
            <stop offset="100%" stopColor={color} />
          </linearGradient>
        </defs>
        
        {/* Background ring */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke="rgba(255, 255, 255, 0.1)"
          strokeWidth={strokeWidth}
        />
        
        {/* Subtle background glow ring */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={bgColor}
          strokeWidth={strokeWidth * 2}
          style={{ opacity: 0.5 }}
        />
        
        {/* Progress ring with glow */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          fill="none"
          stroke={`url(#gradient-${filterId})`}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          filter={`url(#${filterId})`}
          className="transition-all duration-500 ease-out"
        />
        
        {/* Bright tip at the progress end for extra pop */}
        {progress > 0 && (
          <circle
            cx={center}
            cy={center}
            r={radius}
            fill="none"
            stroke={glowColor}
            strokeWidth={strokeWidth * 0.5}
            strokeLinecap="round"
            strokeDasharray={`${strokeWidth * 0.5} ${circumference}`}
            strokeDashoffset={strokeDashoffset}
            filter={`url(#${filterId})`}
            className="transition-all duration-500 ease-out"
            style={{ opacity: 0.8 }}
          />
        )}
      </svg>
      
      {/* Center content */}
      <div 
        className="absolute inset-0 flex flex-col items-center justify-center"
        style={{ transform: "rotate(0deg)" }}
      >
        <div className="text-center">
          <span 
            className="font-bold tabular-nums transition-colors duration-300"
            style={{ 
              fontSize: size * 0.22, 
              color: color,
              textShadow: `0 0 ${glowIntensity}px ${glowColor}`,
            }}
          >
            {current.toLocaleString()}
          </span>
          <div 
            className="text-[var(--text-dim)] transition-colors duration-300"
            style={{ fontSize: size * 0.11 }}
          >
            / {max.toLocaleString()}
          </div>
        </div>
        
        {/* Progress percentage */}
        <div 
          className="mt-1 font-medium tabular-nums transition-colors duration-300"
          style={{ 
            fontSize: size * 0.09, 
            color: glowColor,
            opacity: 0.8,
          }}
        >
          {progress.toFixed(1)}%
        </div>
      </div>
      
      {/* Running indicator dots */}
      {isRunning && (
        <div className="absolute -bottom-1 flex gap-1">
          {[0, 1, 2].map((i) => (
            <div
              key={i}
              className="rounded-full animate-bounce"
              style={{
                width: size * 0.04,
                height: size * 0.04,
                backgroundColor: glowColor,
                animationDelay: `${i * 0.15}s`,
                animationDuration: "0.8s",
              }}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default ProgressRing;
