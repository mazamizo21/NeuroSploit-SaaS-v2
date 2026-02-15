"use client";

import React, { useEffect, useState, useRef } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Terminal, Shield, AlertTriangle, CheckCircle } from "lucide-react";
import { useDopamine } from "@/context/DopamineContext";
import { api } from "@/lib/api";

interface LogEntry {
    timestamp: string;
    source: string;
    message: string;
    type: 'info' | 'success' | 'warning' | 'error' | 'critical';
    details?: string;
}

interface ActivityItem {
    id: string;
    type: string; // finding | job_completed | job_failed
    title: string;
    detail: string;
    severity?: string | null;
    timestamp: string;
}

export const LiveLogViewer: React.FC = () => {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const scrollRef = useRef<HTMLDivElement>(null);
    const { triggerCriticalFinding, triggerSuccess, triggerWarning } = useDopamine();
    const processedRef = useRef<Set<string>>(new Set());
    const initialLoadedRef = useRef(false);
    const [connected, setConnected] = useState<boolean | null>(null);
    const [lastUpdated, setLastUpdated] = useState<string>("");

    useEffect(() => {
        let cancelled = false;
        setLogs([
            {
                timestamp: new Date().toISOString(),
                source: "System",
                message: "Connecting to control plane activity stream...",
                type: "info",
            },
        ]);

        function mapItemToLog(item: ActivityItem): LogEntry {
            const sev = String(item.severity || "").toLowerCase();
            let type: LogEntry["type"] = "info";
            if (item.type === "finding") {
                if (sev === "critical") type = "critical";
                else if (sev === "high") type = "error";
                else if (sev === "medium") type = "warning";
                else type = "info";
            } else if (item.type === "job_completed") type = "success";
            else if (item.type === "job_failed") type = "error";

            const source =
                item.type === "finding"
                    ? `FINDING/${String(item.severity || "info").toUpperCase()}`
                    : String(item.type).replaceAll("_", " ").toUpperCase();
            const message = item.detail ? `${item.title} · ${item.detail}` : item.title;

            return {
                timestamp: item.timestamp || new Date().toISOString(),
                source,
                message,
                type,
            };
        }

        async function load() {
            try {
                const res = await api.get("/api/v1/dashboard/activity?limit=20");
                const items: ActivityItem[] = Array.isArray(res) ? res : [];
                if (cancelled) return;

                setConnected(true);
                setLastUpdated(new Date().toLocaleTimeString());

                // Trigger dopamine effects only for NEW items after the first successful load.
                for (const item of items) {
                    const key = `${item.type}:${item.id}`;
                    if (processedRef.current.has(key)) continue;
                    processedRef.current.add(key);
                    if (!initialLoadedRef.current) continue;

                    const sev = String(item.severity || "").toLowerCase();
                    if (item.type === "finding" && sev === "critical") triggerCriticalFinding();
                    else if (item.type === "job_completed") triggerSuccess();
                    else triggerWarning();
                }
                if (!initialLoadedRef.current) {
                    // Seed the processed set on first success so we don't celebrate historical items.
                    for (const item of items) processedRef.current.add(`${item.type}:${item.id}`);
                    initialLoadedRef.current = true;
                }

                // Activity endpoint returns newest-first; render oldest-first.
                const mapped = items.slice().reverse().map(mapItemToLog);
                setLogs(mapped.slice(-50));
            } catch {
                if (cancelled) return;
                setConnected(false);
            }
        }

        load();
        const interval = window.setInterval(load, 7000);
        return () => {
            cancelled = true;
            clearInterval(interval);
        };
    }, [triggerCriticalFinding, triggerSuccess, triggerWarning]);

    // Auto-scroll to bottom
    useEffect(() => {
        if (scrollRef.current) {
            scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
        }
    }, [logs]);

    const getTypeColor = (type: string) => {
        switch (type) {
            case 'critical': return 'text-red-500 bg-red-500/10 border-red-500/20';
            case 'error': return 'text-red-400 bg-red-400/10 border-red-400/20';
            case 'warning': return 'text-orange-400 bg-orange-400/10 border-orange-400/20';
            case 'success': return 'text-neon-green bg-neon-green/10 border-neon-green/20';
            default: return 'text-blue-400 bg-blue-400/10 border-blue-400/20';
        }
    };

    const getTypeIcon = (type: string) => {
        switch (type) {
            case 'critical': return <Shield className="w-4 h-4 text-red-500 animate-pulse" />;
            case 'warning': return <AlertTriangle className="w-4 h-4 text-orange-400" />;
            case 'success': return <CheckCircle className="w-4 h-4 text-neon-green" />;
            default: return <Terminal className="w-4 h-4 text-blue-400" />;
        }
    };

    return (
        <div className="flex flex-col h-full bg-[#0a0a0c] border border-white/10 rounded-lg overflow-hidden shadow-2xl relative">
            {/* Header */}
            <div className="flex items-center justify-between px-4 py-3 bg-[#12121a] border-b border-white/5">
                <div className="flex items-center gap-2">
                    <Terminal className="w-5 h-5 text-neon-purple" />
                    <h3 className="font-mono text-sm font-bold text-gray-200 tracking-wider">HACKER_CONSOLE</h3>
                </div>
                <div className="flex items-center gap-2">
                    <div className="flex gap-1">
                        <div className="w-3 h-3 rounded-full bg-red-500/50"></div>
                        <div className="w-3 h-3 rounded-full bg-yellow-500/50"></div>
                        <div className="w-3 h-3 rounded-full bg-green-500/50"></div>
                    </div>
                </div>
            </div>

            {/* Log Stream */}
            <div
                ref={scrollRef}
                className="flex-1 overflow-y-auto p-4 font-mono text-xs space-y-2 scroll-smooth custom-scrollbar"
            >
                <AnimatePresence initial={false}>
                    {logs.map((log, index) => (
                        <motion.div
                            key={`${log.timestamp}-${index}`}
                            initial={{ opacity: 0, x: -20 }}
                            animate={{ opacity: 1, x: 0 }}
                            className={`flex items-start gap-3 p-2 rounded border ${getTypeColor(log.type)} backdrop-blur-sm`}
                        >
                            <span className="text-gray-500 shrink-0 select-none">{new Date(log.timestamp).toLocaleTimeString()}</span>
                            <div className="mt-0.5 shrink-0">{getTypeIcon(log.type)}</div>
                            <div className="break-all">
                                <span className="font-bold opacity-75 mr-2">[{log.source}]</span>
                                <span className={log.type === 'critical' ? 'font-bold underline decoration-wavy' : ''}>
                                    {log.message}
                                </span>
                            </div>
                        </motion.div>
                    ))}
                </AnimatePresence>

                {/* Typing indicator */}
                <div className="flex items-center gap-2 text-gray-600 animate-pulse px-2">
                    <span className="text-neon-purple">❯</span>
                    <span className="w-2 h-4 bg-neon-purple/50 block"></span>
                </div>
            </div>

            {/* Status Bar */}
            <div className="px-4 py-2 bg-[#12121a] border-t border-white/5 flex items-center justify-between text-[10px] text-gray-500 font-mono">
                <span>
                    STATUS:{" "}
                    {connected === null ? "CONNECTING" : connected ? "ONLINE" : "OFFLINE"}
                </span>
                <span>UPDATED: {lastUpdated || "—"}</span>
            </div>
        </div>
    );
};
