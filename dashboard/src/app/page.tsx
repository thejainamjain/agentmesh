"use client";

import { useEffect, useRef, useState } from "react";
import { AuditWSClient, AuditEntry, ConnectionStatus, WSMessage } from "../lib/ws";
import StatusBar from "../components/StatusBar";
import AgentActivity from "../components/AgentActivity";
import PolicyViolations from "../components/PolicyViolations";
import AuditLog from "../components/AuditLog";

// Environment variables — never hardcode secrets
const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://127.0.0.1:8000";
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8000";
// NOTE: AGENTMESH_WS_SECRET is intentionally NOT prefixed with NEXT_PUBLIC_
// It must be passed via a server action or API route in production.
// For local development, we read it from the window object set by a server component.
// For now we fall back to a prompt — production deployments use the API route.
const WS_SECRET = process.env.NEXT_PUBLIC_WS_SECRET ?? "";

const AUDIT_PATH = process.env.NEXT_PUBLIC_AUDIT_PATH ?? "agentmesh-audit.jsonl";

// ---------------------------------------------------------------------------
// Stats helpers
// ---------------------------------------------------------------------------

function computeStats(entries: AuditEntry[]) {
    const total = entries.length;
    const allowed = entries.filter(e => e.policy_decision === "allow").length;
    const denied = entries.filter(e => e.policy_decision === "deny").length;
    const flagged = entries.filter(e => e.monitor_flags.length > 0).length;
    const agents = new Set(entries.map(e => e.agent_id)).size;
    return { total, allowed, denied, flagged, agents };
}

// ---------------------------------------------------------------------------
// Main dashboard page
// ---------------------------------------------------------------------------

export default function DashboardPage() {
    const [entries, setEntries] = useState<AuditEntry[]>([]);
    const [status, setStatus] = useState<ConnectionStatus>("connecting");
    const [secret, setSecret] = useState(WS_SECRET);
    const [showSecretInput, setShowSecretInput] = useState(!WS_SECRET);
    const clientRef = useRef<AuditWSClient | null>(null);

    function startConnection(s: string) {
        clientRef.current?.destroy();
        const client = new AuditWSClient({
            wsUrl: WS_URL,
            secret: s,
            auditPath: AUDIT_PATH,
            onMessage: (msg: WSMessage) => {
                if (msg.type === "entry") {
                    setEntries(prev => [...prev, msg.data]);
                }
            },
            onStatusChange: setStatus,
        });
        clientRef.current = client;
        client.connect();
    }

    useEffect(() => {
        if (secret) startConnection(secret);
        return () => clientRef.current?.destroy();
    }, []);

    const stats = computeStats(entries);

    return (
        <div className="min-h-screen flex flex-col" style={{ background: "var(--bg)" }}>
            {/* Header */}
            <header className="px-6 py-4 flex items-center gap-3"
                style={{ borderBottom: "1px solid var(--border)", background: "var(--surface)" }}>
                <div className="flex items-center gap-3">
                    <span className="text-xl">🛡️</span>
                    <div>
                        <h1 className="text-base font-bold tracking-tight" style={{ color: "var(--text)" }}>
                            AgentMesh
                        </h1>
                        <p className="text-xs" style={{ color: "var(--muted)" }}>
                            Runtime Trust &amp; Security Layer
                        </p>
                    </div>
                </div>
            </header>

            <StatusBar status={status} entryCount={stats.total} apiUrl={API_URL} />

            {/* Secret input — shown when no secret configured */}
            {showSecretInput && (
                <div className="mx-6 mt-4 p-4 rounded-lg"
                    style={{ background: "#1e1b2e", border: "1px solid #4c1d95" }}>
                    <p className="text-sm mb-3" style={{ color: "#c4b5fd" }}>
                        🔐 Enter your <code className="px-1 rounded" style={{ background: "#2d1b69" }}>
                            AGENTMESH_WS_SECRET
                        </code> to connect
                    </p>
                    <div className="flex gap-2">
                        <input
                            type="password"
                            className="flex-1 px-3 py-2 rounded text-sm font-mono"
                            style={{
                                background: "var(--bg)", border: "1px solid var(--border)",
                                color: "var(--text)", outline: "none"
                            }}
                            placeholder="Paste your AGENTMESH_WS_SECRET here"
                            value={secret}
                            onChange={e => setSecret(e.target.value)}
                            onKeyDown={e => {
                                if (e.key === "Enter" && secret) {
                                    setShowSecretInput(false);
                                    startConnection(secret);
                                }
                            }}
                        />
                        <button
                            className="px-4 py-2 rounded text-sm font-medium transition-colors"
                            style={{ background: "#4c1d95", color: "#e9d5ff" }}
                            onClick={() => { setShowSecretInput(false); startConnection(secret); }}
                            disabled={!secret}>
                            Connect
                        </button>
                    </div>
                </div>
            )}

            {/* Stats row */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3 px-6 py-4">
                {[
                    { label: "Total Calls", value: stats.total, color: "var(--text)" },
                    { label: "Allowed", value: stats.allowed, color: "var(--allow)" },
                    { label: "Denied", value: stats.denied, color: "var(--deny)" },
                    { label: "Flagged", value: stats.flagged, color: "var(--warn)" },
                    { label: "Active Agents", value: stats.agents, color: "var(--info)" },
                ].map(stat => (
                    <div key={stat.label} className="rounded-lg px-4 py-3"
                        style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                        <div className="text-2xl font-bold font-mono" style={{ color: stat.color }}>
                            {stat.value}
                        </div>
                        <div className="text-xs mt-1" style={{ color: "var(--muted)" }}>
                            {stat.label}
                        </div>
                    </div>
                ))}
            </div>

            {/* Main grid */}
            <div className="flex-1 grid grid-cols-1 lg:grid-cols-3 gap-4 px-6 pb-6">
                <div className="lg:col-span-2 flex flex-col gap-4">
                    <AgentActivity entries={entries} />
                    <PolicyViolations entries={entries} />
                </div>
                <div className="lg:col-span-1">
                    <AuditLog entries={entries} />
                </div>
            </div>
        </div>
    );
}