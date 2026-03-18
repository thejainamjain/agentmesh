from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any


def _hash_data(data: Any) -> str:
    """SHA-256 of canonical JSON — stable regardless of dict insertion order."""
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


class CapturedCall:
    """
    Record of a single intercepted tool call.

    Created by the interceptor before the tool executes.
    Passed to the policy engine (Week 4) and behavior monitor (Week 5).
    Written to the audit trail (Week 6) after execution.

    Fields match the audit entry schema in ARCHITECTURE.md Section 7.
    """

    __slots__ = (
        "agent_id", "mesh_id", "token", "tool_name", "arguments",
        "arguments_hash", "timestamp", "result", "result_hash",
        "allowed", "block_reason", "monitor_flags",
    )

    def __init__(
        self,
        agent_id: str,
        mesh_id: str,
        token: str,
        tool_name: str,
        arguments: dict[str, Any],
        arguments_hash: str | None = None,
        timestamp: datetime | None = None,
    ) -> None:
        self.agent_id: str = agent_id
        self.mesh_id: str = mesh_id
        self.token: str = token
        self.tool_name: str = tool_name
        self.arguments: dict[str, Any] = arguments
        self.arguments_hash: str = arguments_hash if arguments_hash is not None else _hash_data(arguments)
        self.timestamp: datetime = timestamp if timestamp is not None else datetime.now(timezone.utc)
        self.result: Any = None
        self.result_hash: str | None = None
        self.allowed: bool = True
        self.block_reason: str | None = None
        self.monitor_flags: list[str] = []

    @classmethod
    def capture(
        cls,
        agent_id: str,
        mesh_id: str,
        token: str,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> "CapturedCall":
        """Factory — creates a CapturedCall at the moment of interception."""
        return cls(
            agent_id=agent_id,
            mesh_id=mesh_id,
            token=token,
            tool_name=tool_name,
            arguments=arguments,
        )

    def record_result(self, result: Any) -> None:
        """Called by the interceptor after the tool executes successfully."""
        self.result = result
        self.result_hash = _hash_data(result)

    def block(self, reason: str) -> None:
        """Mark this call as blocked before execution."""
        self.allowed = False
        self.block_reason = reason

    def to_dict(self) -> dict[str, Any]:
        """Serialise to plain dict."""
        return self.to_audit_dict()

    def to_audit_dict(self) -> dict[str, Any]:
        """
        Convert to the audit entry format from ARCHITECTURE.md Section 7.
        Used by the audit trail (Week 6) to record the call.
        """
        return {
            "agent_id": self.agent_id,
            "mesh_id": self.mesh_id,
            "action_type": "tool_call",
            "tool_name": self.tool_name,
            "arguments_hash": self.arguments_hash,
            "timestamp": self.timestamp.isoformat(),
            "result_hash": self.result_hash,
            "policy_decision": "allow" if self.allowed else "deny",
            "block_reason": self.block_reason,
            "monitor_flags": self.monitor_flags,
        }

    def __repr__(self) -> str:
        status = "ALLOWED" if self.allowed else f"BLOCKED({self.block_reason})"
        return (
            f"CapturedCall(agent_id={self.agent_id!r}, "
            f"tool_name={self.tool_name!r}, status={status})"
        )