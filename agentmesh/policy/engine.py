from __future__ import annotations

import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import yaml

from agentmesh.policy.exceptions import (
    PolicyDenied,
    PolicyError,
    PolicyLoadError,
    PolicyValidationError,
    RateLimitExceeded,
)
from agentmesh.policy.schema import validate_policy

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy decision types
# ---------------------------------------------------------------------------

class Decision(Enum):
    ALLOW = "allow"
    DENY = "deny"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True)
class PolicyDecision:
    """
    The result of a policy evaluation.

    Immutable — once issued, a decision cannot be modified.
    Written to the audit trail by the interceptor.
    """
    decision: Decision
    reason: str
    agent_id: str
    tool_name: str
    caller_id: str | None = None

    @property
    def allowed(self) -> bool:
        return self.decision == Decision.ALLOW

    def __str__(self) -> str:
        return (
            f"PolicyDecision({self.decision.value}: "
            f"agent={self.agent_id!r} tool={self.tool_name!r} "
            f"caller={self.caller_id!r} reason={self.reason!r})"
        )


# ---------------------------------------------------------------------------
# Rate limit state (in-memory rolling window)
# ---------------------------------------------------------------------------

@dataclass
class _RateLimitState:
    """Rolling window counter for a single agent+tool combination."""
    max_calls: int
    window_seconds: int
    timestamps: list[float] = field(default_factory=list)

    def is_allowed(self) -> bool:
        """Check and record a call. Returns True if within the rate limit."""
        now = time.monotonic()
        # Drop timestamps outside the current window
        cutoff = now - self.window_seconds
        self.timestamps = [t for t in self.timestamps if t > cutoff]
        if len(self.timestamps) >= self.max_calls:
            return False
        self.timestamps.append(now)
        return True

    def calls_in_window(self) -> int:
        """Current call count within the rolling window."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        return len([t for t in self.timestamps if t > cutoff])


def _parse_rate_limit(rate_str: str) -> tuple[int, int]:
    """
    Parse a rate limit string into (max_calls, window_seconds).

    Accepts: '10/minute', '100/hour', '5/second'
    Returns: (10, 60), (100, 3600), (5, 1)

    Raises:
        PolicyLoadError: If the format is invalid.
    """
    match = re.fullmatch(r"(\d+)/(second|minute|hour)", rate_str.strip())
    if not match:
        raise PolicyLoadError(
            f"Invalid rate limit format: {rate_str!r}. "
            f"Expected format: '<count>/<second|minute|hour>' e.g. '10/minute'"
        )
    count = int(match.group(1))
    unit = match.group(2)
    window = {"second": 1, "minute": 60, "hour": 3600}[unit]
    return count, window


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Loads, validates, and evaluates AgentMesh policy rules.

    Security guarantees:
    - Default deny: calls with no matching rule are always blocked.
    - Fail secure: any engine error results in a DENY, never an ALLOW.
    - Immutable after load: the policy cannot be modified at runtime.
    - Schema validated: invalid YAML is rejected before any rule is evaluated.

    Usage:
        engine = PolicyEngine.from_file("agentmesh-policy.yaml")
        decision = engine.evaluate(
            caller_id="orchestrator",
            agent_id="researcher",
            tool_name="web_search",
        )
        if not decision.allowed:
            raise PolicyDenied(decision.reason)
    """

    def __init__(self, policy_dict: dict[str, Any]) -> None:
        """
        Initialise from a validated policy dict.

        Do not call directly — use PolicyEngine.from_file() or
        PolicyEngine.from_dict() which perform validation first.
        """
        self._policy = policy_dict
        self._agents: dict[str, dict] = policy_dict.get("agents", {})
        # Rate limit state: (agent_id, tool_name) → _RateLimitState
        self._rate_limits: dict[tuple[str, str], _RateLimitState] = {}
        self._init_rate_limits()
        logger.info(
            "PolicyEngine loaded: %d agents, %d rate limit rules",
            len(self._agents),
            len(self._rate_limits),
        )

    def _init_rate_limits(self) -> None:
        """Pre-parse all rate limit strings at load time, not at eval time."""
        for agent_id, agent_policy in self._agents.items():
            for tool_name, rate_str in agent_policy.get("rate_limits", {}).items():
                max_calls, window_seconds = _parse_rate_limit(rate_str)
                self._rate_limits[(agent_id, tool_name)] = _RateLimitState(
                    max_calls=max_calls,
                    window_seconds=window_seconds,
                )

    # ── Constructors ─────────────────────────────────────────────────────────

    @classmethod
    def from_file(cls, policy_path: str | Path) -> "PolicyEngine":
        """
        Load and validate a policy YAML file.

        Raises:
            PolicyLoadError: If the file cannot be read or parsed.
            PolicyValidationError: If the YAML fails schema validation.

        Security note: if this raises for any reason, the caller must
        treat it as a DENY-all state. Do not catch and ignore.
        """
        path = Path(policy_path)
        if not path.exists():
            raise PolicyLoadError(
                f"Policy file not found: {path}. "
                f"AgentMesh requires a valid policy file to operate. "
                f"All calls will be denied until a policy is loaded."
            )
        if not path.is_file():
            raise PolicyLoadError(f"Policy path is not a file: {path}")

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as e:
            raise PolicyLoadError(f"Cannot read policy file {path}: {e}") from e

        try:
            policy_dict = yaml.safe_load(raw)
        except yaml.YAMLError as e:
            raise PolicyLoadError(
                f"Policy file {path} contains invalid YAML: {e}"
            ) from e

        if not isinstance(policy_dict, dict):
            raise PolicyLoadError(
                f"Policy file {path} must be a YAML mapping, got {type(policy_dict).__name__}"
            )

        validate_policy(policy_dict)
        logger.info("Policy loaded and validated from %s", path)
        return cls(policy_dict)

    @classmethod
    def from_dict(cls, policy_dict: dict[str, Any]) -> "PolicyEngine":
        """
        Load from a pre-parsed dict (useful for testing).

        Raises:
            PolicyValidationError: If the dict fails schema validation.
        """
        validate_policy(policy_dict)
        return cls(policy_dict)

    # ── Core evaluation ───────────────────────────────────────────────────────

    def evaluate(
        self,
        agent_id: str,
        tool_name: str,
        caller_id: str | None = None,
    ) -> PolicyDecision:
        """
        Evaluate whether an agent is permitted to call a tool.

        Evaluation order (first failure = DENY immediately):
          1. Agent must be registered in the policy
          2. Tool must not be in denied_tools (explicit deny)
          3. Tool must be in allowed_tools
          4. caller_id must be in allowed_callers (if caller provided)
          5. Rate limit must not be exceeded

        Args:
            agent_id:  The agent attempting the tool call.
            tool_name: The tool being called.
            caller_id: The agent that invoked this agent (None = top-level).

        Returns:
            PolicyDecision with decision=ALLOW, DENY, or RATE_LIMITED.

        Security note: this method never raises — all errors return DENY.
        Raising would risk the caller treating an exception as a pass-through.
        """
        try:
            return self._evaluate_inner(agent_id, tool_name, caller_id)
        except (PolicyDenied, RateLimitExceeded):
            raise
        except Exception as e:
            # Fail secure — any unexpected error is a DENY
            logger.error(
                "PolicyEngine internal error for agent=%r tool=%r: %s — failing secure",
                agent_id, tool_name, e,
            )
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"Policy engine internal error — failing secure: {e}",
                agent_id=agent_id,
                tool_name=tool_name,
                caller_id=caller_id,
            )

    def _evaluate_inner(
        self,
        agent_id: str,
        tool_name: str,
        caller_id: str | None,
    ) -> PolicyDecision:
        """Core evaluation logic — called by evaluate() with error wrapping."""

        def deny(reason: str) -> PolicyDecision:
            logger.warning(
                "PolicyEngine DENY: agent=%r tool=%r caller=%r reason=%r",
                agent_id, tool_name, caller_id, reason,
            )
            return PolicyDecision(
                decision=Decision.DENY,
                reason=reason,
                agent_id=agent_id,
                tool_name=tool_name,
                caller_id=caller_id,
            )

        def allow(reason: str = "rule match") -> PolicyDecision:
            logger.debug(
                "PolicyEngine ALLOW: agent=%r tool=%r caller=%r",
                agent_id, tool_name, caller_id,
            )
            return PolicyDecision(
                decision=Decision.ALLOW,
                reason=reason,
                agent_id=agent_id,
                tool_name=tool_name,
                caller_id=caller_id,
            )

        # ── Step 1: Agent must exist in policy ───────────────────────────────
        agent_policy = self._agents.get(agent_id)
        if agent_policy is None:
            return deny(
                f"Agent {agent_id!r} is not registered in the policy. "
                f"Add it to your policy YAML before it can call any tools."
            )

        # ── Step 2: Explicit deny list (belt and suspenders) ─────────────────
        denied_tools = agent_policy.get("denied_tools", [])
        if tool_name in denied_tools:
            return deny(
                f"Tool {tool_name!r} is explicitly denied for agent {agent_id!r}."
            )

        # ── Step 3: Allowed tools ─────────────────────────────────────────────
        allowed_tools = agent_policy.get("allowed_tools", [])
        if tool_name not in allowed_tools:
            return deny(
                f"Tool {tool_name!r} is not in allowed_tools for agent {agent_id!r}. "
                f"Allowed: {allowed_tools}"
            )

        # ── Step 4: Caller verification ───────────────────────────────────────
        allowed_callers = agent_policy.get("allowed_callers", [])
        if caller_id is not None:
            # A caller was specified — it must be in the allowed list
            if caller_id not in allowed_callers:
                return deny(
                    f"Caller {caller_id!r} is not in allowed_callers for agent {agent_id!r}. "
                    f"Allowed callers: {allowed_callers}"
                )
        else:
            # No caller = top-level call. Only permitted if allowed_callers is empty.
            if allowed_callers:
                return deny(
                    f"Agent {agent_id!r} requires a caller from {allowed_callers} "
                    f"but was called directly (no caller_id)."
                )

        # ── Step 5: Rate limit ────────────────────────────────────────────────
        rate_state = self._rate_limits.get((agent_id, tool_name))
        if rate_state is not None:
            if not rate_state.is_allowed():
                logger.warning(
                    "PolicyEngine RATE_LIMITED: agent=%r tool=%r (%d/%ds)",
                    agent_id, tool_name,
                    rate_state.calls_in_window(), rate_state.window_seconds,
                )
                return PolicyDecision(
                    decision=Decision.RATE_LIMITED,
                    reason=(
                        f"Rate limit exceeded for agent {agent_id!r} tool {tool_name!r}: "
                        f"{rate_state.max_calls} calls per "
                        f"{rate_state.window_seconds}s window"
                    ),
                    agent_id=agent_id,
                    tool_name=tool_name,
                    caller_id=caller_id,
                )

        return allow()

    # ── Introspection helpers (used by tests and dashboard) ──────────────────

    def registered_agents(self) -> list[str]:
        """Return all agent IDs registered in the policy."""
        return list(self._agents.keys())

    def allowed_tools_for(self, agent_id: str) -> list[str]:
        """Return the allowed tools for an agent, or [] if unregistered."""
        return self._agents.get(agent_id, {}).get("allowed_tools", [])

    def allowed_callers_for(self, agent_id: str) -> list[str]:
        """Return the allowed callers for an agent, or [] if unregistered."""
        return self._agents.get(agent_id, {}).get("allowed_callers", [])

    def has_rate_limit(self, agent_id: str, tool_name: str) -> bool:
        """Return True if a rate limit is configured for this agent+tool."""
        return (agent_id, tool_name) in self._rate_limits

    def __repr__(self) -> str:
        return f"PolicyEngine(agents={self.registered_agents()})"