"use client";

import { AuditEntry } from "../lib/ws";

interface AgentActivityProps {
    entries: AuditEntry[];
}

function DecisionBadge({ decision }: { decision: string }) {
    const styles: Record<string, string> = {
        allow: "bg-green-900 text-green-300 border border-green-700",
        deny: "bg-red-900 text-red-300 border border-red-700",
        rate_limited: "bg-yellow-900 text-yellow-300 border border-yellow-700",
        pending: "bg-gray-800 text-gray-400 border border-gray-600",
    };
    return (
        <span className={`text-xs px-2 py-0.5 rounded font-mono ${styles[decision] ?? styles.pending}`}>
            {decision.toUpperCase()}
        </span>
    );
}

function formatTime(iso: string): string {
    try {
        return new Date(iso).toLocaleTimeString("en-US", {
            hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit"
        });
    } catch { return iso; }
}

export default function AgentActivity({ entries }: AgentActivityProps) {
    const recent = [...entries].reverse().slice(0, 100);

    return (
        <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border)" }}>
            <div className="px-4 py-3 flex items-center justify-between"
                style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                <h2 className="text-sm font-semibold tracking-wide" style={{ color: "var(--text)" }}>
                    ⚡ Live Agent Activity
                </h2>
                <span className="text-xs" style={{ color: "var(--muted)" }}>
                    {entries.length} total calls
                </span>
            </div>

            <div className="overflow-y-auto" style={{ maxHeight: "420px", background: "var(--bg)" }}>
                {recent.length === 0 ? (
                    <div className="flex items-center justify-center py-12">
                        <p className="text-sm" style={{ color: "var(--muted)" }}>
                            Waiting for agent activity...
                        </p>
                    </div>
                ) : (
                    <table className="w-full text-xs font-mono">
                        <thead style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                            <tr>
                                {["Time", "Agent", "Tool", "Decision", "Flags"].map(h => (
                                    <th key={h} className="px-4 py-2 text-left font-medium"
                                        style={{ color: "var(--muted)" }}>{h}</th>
                                ))}
                            </tr>
                        </thead>
                        <tbody>
                            {recent.map((entry, i) => (
                                <tr key={entry.entry_id}
                                    className="border-b transition-colors hover:bg-white/5"
                                    style={{ borderColor: "var(--border)", animationDelay: `${i * 20}ms` }}>
                                    <td className="px-4 py-2 whitespace-nowrap" style={{ color: "var(--muted)" }}>
                                        {formatTime(entry.timestamp)}
                                    </td>
                                    <td className="px-4 py-2 whitespace-nowrap" style={{ color: "var(--info)" }}>
                                        {entry.agent_id}
                                    </td>
                                    <td className="px-4 py-2 whitespace-nowrap" style={{ color: "var(--text)" }}>
                                        {entry.tool_name ?? "—"}
                                    </td>
                                    <td className="px-4 py-2">
                                        <DecisionBadge decision={entry.policy_decision} />
                                    </td>
                                    <td className="px-4 py-2">
                                        {entry.monitor_flags.length > 0 ? (
                                            <span className="text-xs px-1.5 py-0.5 rounded"
                                                style={{ background: "#7c2d12", color: "#fca5a5" }}>
                                                {entry.monitor_flags[0]}
                                            </span>
                                        ) : (
                                            <span style={{ color: "var(--muted)" }}>—</span>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                )}
            </div>
        </div>
    );
}