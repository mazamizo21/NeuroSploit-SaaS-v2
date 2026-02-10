"use client";

import React, { useEffect, useState, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, Shield, AlertTriangle, CheckCircle, Smartphone } from 'lucide-react';
import { useDopamine } from '@/context/DopamineContext';

interface LogEntry {
    timestamp: string;
    source: string;
    message: string;
    type: 'info' | 'success' | 'warning' | 'error' | 'critical';
    details?: string;
}

export const LiveLogViewer: React.FC = () => {
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const scrollRef = useRef<HTMLDivElement>(null);
    const { triggerCriticalFinding, triggerSuccess, triggerWarning } = useDopamine();
    const processedRef = useRef<Set<string>>(new Set());

    // Simulate reading from the logs file via an API (mocked for now as we don't have the API route yet)
    // In a real implementation, we would poll an API endpoint that reads `logs/llm_interactions.jsonl`
    useEffect(() => {
        const mockLogs: LogEntry[] = [
            { timestamp: new Date().toISOString(), source: 'System', message: 'TazoSploit v2.0 initialized', type: 'info' },
            { timestamp: new Date().toISOString(), source: 'Orchestrator', message: 'Connected to control plane', type: 'success' },
        ];
        setLogs(mockLogs);

        const interval = setInterval(() => {
            // Simulate incoming logs - in production this would fetch from /api/logs
            const events = [
                { msg: "Scanning port 443...", type: 'info' },
                { msg: "Directories enumerated: /admin, /login, /config", type: 'info' },
                { msg: "VULNERABILITY DETECTED: SQL Injection in login form", type: 'critical' },
                { msg: "Payload successfully executed", type: 'success' },
                { msg: "Connection timed out retrying...", type: 'warning' },
                { msg: "Analyzing response headers...", type: 'info' },
            ];

            const randomEvent = events[Math.floor(Math.random() * events.length)];
            const newLog: LogEntry = {
                timestamp: new Date().toISOString(),
                source: 'Agent-01',
                message: randomEvent.msg,
                type: randomEvent.type as any
            };

            setLogs(prev => [...prev.slice(-49), newLog]); // Keep last 50

            // Trigger Dopamine effects based on log type
            if (randomEvent.type === 'critical') triggerCriticalFinding();
            if (randomEvent.type === 'success') triggerSuccess();
            if (randomEvent.type === 'warning') triggerWarning();

        }, 3000);

        return () => clearInterval(interval);
    }, []);

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
                <span>STATUS: ACTIVE</span>
                <span>CONNECTION: ENCRYPTED (AES-256)</span>
            </div>
        </div>
    );
};
