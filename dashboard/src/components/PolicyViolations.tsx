"use client";

import { AuditEntry } from "../lib/ws";

interface PolicyViolationsProps {
    entries: AuditEntry[];
}

function formatTime(iso: string): string {
    try {
        return new Date(iso).toLocaleString("en-US", { hour12: false });
    } catch { return iso; }
}

export default function PolicyViolations({ entries }: PolicyViolationsProps) {
    const violations = entries
        .filter(e => e.policy_decision === "deny" || e.policy_decision === "rate_limited")
        .reverse()
        .slice(0, 50);

    return (
        <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border)" }}>
            <div className="px-4 py-3 flex items-center justify-between"
                style={{ background: "var(--surface)", borderBottom: "1px solid var(--border)" }}>
                <h2 className="text-sm font-semibold tracking-wide" style={{ color: "var(--text)" }}>
                    🚫 Policy Violations
                </h2>
                <span className="text-xs px-2 py-0.5 rounded"
                    style={{
                        background: violations.length > 0 ? "#7f1d1d" : "#1e3a2f",
                        color: violations.length > 0 ? "#fca5a5" : "#86efac"
                    }}>
                    {violations.length} violations
                </span>
            </div>

            <div className="overflow-y-auto" style={{ maxHeight: "300px", background: "var(--bg)" }}>
                {violations.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-10 gap-2">
                        <span className="text-2xl">✅</span>
                        <p className="text-sm" style={{ color: "var(--muted)" }}>No policy violations</p>
                    </div>
                ) : (
                    <div className="divide-y" style={{ borderColor: "var(--border)" }}>
                        {violations.map(entry => (
                            <div key={entry.entry_id} className="px-4 py-3">
                                <div className="flex items-start justify-between gap-3">
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2 mb-1">
                                            <span className="font-mono text-xs font-bold" style={{ color: "#f87171" }}>
                                                {entry.policy_decision.toUpperCase()}
                                            </span>
                                            <span className="font-mono text-xs" style={{ color: "var(--info)" }}>
                                                {entry.agent_id}
                                            </span>
                                            {entry.tool_name && (
                                                <>
                                                    <span style={{ color: "var(--muted)" }}>→</span>
                                                    <span className="font-mono text-xs" style={{ color: "var(--text)" }}>
                                                        {entry.tool_name}
                                                    </span>
                                                </>
                                            )}
                                        </div>
                                        {entry.monitor_flags.length > 0 && (
                                            <div className="flex flex-wrap gap-1 mt-1">
                                                {entry.monitor_flags.map((flag, i) => (
                                                    <span key={i} className="text-xs px-1.5 py-0.5 rounded font-mono"
                                                        style={{ background: "#7c2d12", color: "#fca5a5" }}>
                                                        {flag}
                                                    </span>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                    <span className="text-xs whitespace-nowrap flex-shrink-0"
                                        style={{ color: "var(--muted)" }}>
                                        {formatTime(entry.timestamp)}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}