"use client";

import { AuditEntry } from "../lib/ws";
import { useState } from "react";

interface AuditLogProps {
    entries: AuditEntry[];
}

function truncateHash(hash: string | null): string {
    if (!hash) return "—";
    return hash.slice(0, 8) + "...";
}

function formatTime(iso: string): string {
    try { return new Date(iso).toLocaleString("en-US", { hour12: false }); }
    catch { return iso; }
}

export default function AuditLog({ entries }: AuditLogProps) {
    const [expanded, setExpanded] = useState<string | null>(null);
    const recent = [...entries].reverse().slice(0, 200);

    return (
        <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border)" }}>
            <div className="px-4 py-3 flex items-center justify-between"
                style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                <h2 className="text-sm font-semibold tracking-wide" style={{ color: "var(--text)" }}>
                    🔒 Immutable Audit Chain
                </h2>
                <div className="flex items-center gap-3">
                    <span className="text-xs px-2 py-0.5 rounded"
                        style={{ background: "#14532d", color: "#86efac" }}>
                        SHA-256 Chained · Ed25519 Signed
                    </span>
                    <span className="text-xs" style={{ color: "var(--muted)" }}>
                        {entries.length} entries
                    </span>
                </div>
            </div>

            <div className="overflow-y-auto font-mono text-xs"
                style={{ maxHeight: "400px", background: "var(--bg)" }}>
                {recent.length === 0 ? (
                    <div className="flex items-center justify-center py-12">
                        <p style={{ color: "var(--muted)" }}>No audit entries yet</p>
                    </div>
                ) : (
                    recent.map((entry, i) => (
                        <div key={entry.entry_id}>
                            {/* Chain link visualisation */}
                            {i > 0 && (
                                <div className="flex justify-start pl-8">
                                    <div className="w-px h-3" style={{ background: "var(--border)" }} />
                                </div>
                            )}
                            <div
                                className="px-4 py-2 cursor-pointer hover:bg-white/5 transition-colors"
                                onClick={() => setExpanded(expanded === entry.entry_id ? null : entry.entry_id)}>
                                <div className="flex items-center gap-3">
                                    <span className="text-lg">{i === 0 ? "🔷" : "🔗"}</span>
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 flex-wrap">
                                            <span style={{ color: "var(--muted)" }}>{formatTime(entry.timestamp)}</span>
                                            <span style={{ color: "var(--info)" }}>{entry.agent_id}</span>
                                            <span style={{ color: "var(--text)" }}>{entry.action_type}</span>
                                            {entry.tool_name && (
                                                <span style={{ color: "#a78bfa" }}>{entry.tool_name}</span>
                                            )}
                                            <span className={`px-1.5 py-0.5 rounded text-xs ${entry.policy_decision === "allow"
                                                    ? "text-green-300"
                                                    : "text-red-300"
                                                }`}>
                                                {entry.policy_decision}
                                            </span>
                                        </div>
                                        <div className="flex items-center gap-2 mt-0.5" style={{ color: "var(--muted)" }}>
                                            <span>id:{truncateHash(entry.entry_id)}</span>
                                            <span>prev:{truncateHash(entry.prev_hash)}</span>
                                            <span>sig:{truncateHash(entry.signature)}</span>
                                        </div>
                                    </div>
                                </div>

                                {/* Expanded detail */}
                                {expanded === entry.entry_id && (
                                    <div className="mt-3 ml-10 p-3 rounded text-xs overflow-x-auto"
                                        style={{ background: "var(--surface)", border: "1px solid var(--border)" }}>
                                        <pre style={{ color: "var(--text)", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                                            {JSON.stringify({
                                                entry_id: entry.entry_id,
                                                timestamp: entry.timestamp,
                                                agent_id: entry.agent_id,
                                                action_type: entry.action_type,
                                                tool_name: entry.tool_name,
                                                arguments_hash: entry.arguments_hash,
                                                result_hash: entry.result_hash,
                                                policy_decision: entry.policy_decision,
                                                monitor_flags: entry.monitor_flags,
                                                prev_hash: entry.prev_hash,
                                                signature: entry.signature,
                                            }, null, 2)}
                                        </pre>
                                    </div>
                                )}
                            </div>
                        </div>
                    ))
                )}
            </div>
        </div>
    );
}