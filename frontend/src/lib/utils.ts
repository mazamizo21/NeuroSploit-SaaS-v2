import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(d: string | Date) {
  return new Date(d).toLocaleString();
}

export function severityColor(s: string) {
  const map: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-blue-500 text-white",
    info: "bg-gray-500 text-white",
  };
  return map[s] || "bg-gray-400 text-white";
}

export function statusColor(s: string) {
  const map: Record<string, string> = {
    pending: "text-yellow-400",
    queued: "text-blue-400",
    running: "text-green-400 animate-pulse",
    paused: "text-amber-300",
    completed: "text-green-500",
    failed: "text-red-500",
    cancelled: "text-gray-400",
    timeout: "text-red-400",
  };
  return map[s] || "text-gray-400";
}
