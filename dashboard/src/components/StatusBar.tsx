"use client";

import { ConnectionStatus } from "../lib/ws";

interface StatusBarProps {
    status: ConnectionStatus;
    entryCount: number;
    apiUrl: string;
}

const STATUS_CONFIG: Record<ConnectionStatus, { label: string; color: string; dot: string }> = {
    connecting: { label: "Connecting...", color: "text-yellow-400", dot: "bg-yellow-400 animate-pulse" },
    connected: { label: "Connected", color: "text-green-400", dot: "bg-green-400" },
    disconnected: { label: "Disconnected", color: "text-gray-400", dot: "bg-gray-400" },
    error: { label: "Error", color: "text-red-400", dot: "bg-red-400" },
    auth_failed: { label: "Auth Failed", color: "text-red-500", dot: "bg-red-500" },
};

export default function StatusBar({ status, entryCount, apiUrl }: StatusBarProps) {
    const cfg = STATUS_CONFIG[status];
    return (
        <div className="flex items-center justify-between px-6 py-3 border-b"
            style={{ borderColor: "var(--border)", background: "var(--surface)" }}>
            <div className="flex items-center gap-3">
                <div className="flex items-center gap-2">
                    <div className={`w-2 h-2 rounded-full ${cfg.dot}`} />
                    <span className={`text-sm font-medium ${cfg.color}`}>{cfg.label}</span>
                </div>
                <span className="text-xs" style={{ color: "var(--muted)" }}>
                    {apiUrl}
                </span>
            </div>
            <div className="flex items-center gap-4">
                <span className="text-xs" style={{ color: "var(--muted)" }}>
                    {entryCount} audit entries
                </span>
                <span className="text-xs font-bold tracking-widest" style={{ color: "var(--info)" }}>
                    AGENTMESH v0.1.0
                </span>
            </div>
        </div>
    );
}