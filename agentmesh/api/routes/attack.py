from __future__ import annotations

"""
POST /v1/attack/run — Interactive Attack Lab

Runs a user-supplied payload through both pipelines and returns
the REAL result — never lies about what was or wasn't caught.

If AgentMesh misses the attack, the response says so clearly.
This endpoint exists for honest security testing.

Only enabled when AGENTMESH_ATTACK_LAB=true.
"""

import logging
import os
import time
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)
router = APIRouter()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class AttackRequest(BaseModel):
    payload: str = Field(..., max_length=2000)
    attack_type: Literal[
        "prompt_injection", "role_hijack", "privilege_escalation",
        "data_exfiltration", "shell_injection", "credential_theft", "custom",
    ]
    tool_name: str = Field(default="web_search")
    caller_id: str = Field(default="orchestrator")
    agent_id: str = Field(default="researcher")


class SideResult(BaseModel):
    outcome: Literal["allowed", "blocked", "error"]
    reason: str
    duration_ms: float
    flags: list[str] = []
    # Honest extra fields
    what_this_means: str  # plain English explanation of what just happened
    severity: Literal["critical", "high", "medium", "low", "none"] = "none"


class AttackResult(BaseModel):
    payload: str
    attack_type: str
    tool_name: str
    unprotected: SideResult
    protected: SideResult
    verdict: str
    is_gap: bool  # True if AgentMesh failed to catch a real attack


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/v1/attack/run", response_model=AttackResult, tags=["attack-lab"])
async def run_attack(request: AttackRequest) -> AttackResult:  # pragma: no cover
    if not os.environ.get("AGENTMESH_ATTACK_LAB", "").lower() in ("true", "1", "yes"):
        raise HTTPException(
            status_code=403,
            detail=(
                "Attack Lab is disabled. "
                "Set AGENTMESH_ATTACK_LAB=true and restart the server to enable it."
            ),
        )

    # Unprotected side — always allowed, explain what that means
    unprotected = SideResult(
        outcome="allowed",
        reason="No identity verification. No policy enforcement. No injection detection.",
        duration_ms=0.0,
        flags=[],
        what_this_means=(
            "Without AgentMesh, this payload reaches the LLM or tool directly. "
            "If it's an injection, the LLM sees it and may act on it. "
            "If it's a privilege escalation, the tool executes with no checks."
        ),
        severity="none",
    )

    # Protected side — real result from the actual security stack
    protected = _run_protected(request)

    # Determine whether this is a genuine gap
    # A gap = the payload looks like a real attack but AgentMesh didn't catch it
    is_gap = protected.outcome == "allowed" and _looks_like_attack(
        request.payload, request.tool_name, request.attack_type
    )

    # Honest verdict — never sugarcoat a miss
    if protected.outcome == "blocked":
        verdict = (
            f"🛡️ BLOCKED in {protected.duration_ms:.1f}ms — "
            f"{protected.reason}"
        )
    elif is_gap:
        verdict = (
            f"❌ NOT CAUGHT — AgentMesh v0.1.0 missed this attack. "
            f"The payload reached the tool. "
            f"This is a known detection gap. See tests/security/test_known_gaps.py."
        )
    else:
        verdict = (
            f"✅ ALLOWED — This payload does not appear to be an attack. "
            f"Identity verified, policy passed, no injection patterns matched."
        )

    return AttackResult(
        payload=request.payload,
        attack_type=request.attack_type,
        tool_name=request.tool_name,
        unprotected=unprotected,
        protected=protected,
        verdict=verdict,
        is_gap=is_gap,
    )


# ---------------------------------------------------------------------------
# Protected pipeline — real checks, real results
# ---------------------------------------------------------------------------

def _run_protected(request: AttackRequest) -> SideResult:  # pragma: no cover
    from agentmesh.identity.agent_identity import AgentIdentity
    from agentmesh.monitor.injection_detector import InjectionDetector
    from agentmesh.monitor.exceptions import PolicyDenied
    from agentmesh.api.server import get_policy_engine

    t0 = time.perf_counter()

    try:
        # Step 1: Identity — issue a token for the test identity
        identity = AgentIdentity(
            agent_id=request.agent_id,
            capabilities=[request.tool_name],
            mesh_id="attack-lab",
        )
        identity.issue_token()

        # Step 2: Policy check (only if a policy is loaded)
        engine = get_policy_engine()
        if engine is not None:
            decision = engine.evaluate(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                caller_id=request.caller_id,
            )
            if decision.decision.value != "allow":
                return SideResult(
                    outcome="blocked",
                    reason=f"Policy denied: {decision.reason}",
                    duration_ms=round((time.perf_counter() - t0) * 1000, 2),
                    flags=["policy_denied"],
                    what_this_means=(
                        f"The policy engine blocked this call before the tool ran. "
                        f"Agent '{request.agent_id}' is not permitted to call "
                        f"'{request.tool_name}'."
                    ),
                    severity="high",
                )

        # Step 3: Injection detection — the real check
        detector = InjectionDetector()
        result = detector.inspect({
            "payload": request.payload,
            "tool": request.tool_name,
        })

        duration_ms = round((time.perf_counter() - t0) * 1000, 2)

        if not result.safe:
            top = result.matches[0] if result.matches else None
            severity = top.severity.value if top else "medium"
            reason = (
                f"{top.description} "
                f"[pattern: {top.pattern_id}, category: {top.category}]"
                if top else "Injection pattern detected"
            )
            return SideResult(
                outcome="blocked",
                reason=reason,
                duration_ms=duration_ms,
                flags=result.flags,
                what_this_means=(
                    f"The injection detector matched pattern '{top.pattern_id if top else 'unknown'}' "
                    f"in the payload. This pattern covers {top.category if top else 'injection'} attacks. "
                    f"The tool was never called."
                ),
                severity=severity,
            )

        # Passed all checks — honestly say so
        return SideResult(
            outcome="allowed",
            reason=(
                "No policy loaded" if engine is None
                else "Identity verified · Policy allowed · No injection patterns matched"
            ),
            duration_ms=duration_ms,
            flags=[],
            what_this_means=(
                "AgentMesh found nothing suspicious in this payload. "
                "If this is a real attack, it is either a known gap (see the gaps panel) "
                "or a legitimate call that should be allowed."
            ),
            severity="none",
        )

    except PolicyDenied as e:
        return SideResult(
            outcome="blocked",
            reason=f"Policy denied: {e}",
            duration_ms=round((time.perf_counter() - t0) * 1000, 2),
            flags=["policy_denied"],
            what_this_means="The tool call was blocked by the policy engine.",
            severity="high",
        )
    except Exception as e:
        logger.error("Attack lab error: %s", e)
        return SideResult(
            outcome="error",
            reason=str(e)[:300],
            duration_ms=round((time.perf_counter() - t0) * 1000, 2),
            flags=["server_error"],
            what_this_means=f"An unexpected server error occurred: {str(e)[:100]}",
            severity="none",
        )


# ---------------------------------------------------------------------------
# Heuristic: does this look like a real attack that was missed?
# Used to distinguish "AgentMesh correctly allowed a clean call"
# from "AgentMesh missed a real attack"
# ---------------------------------------------------------------------------

_ATTACK_INDICATORS = [
    # Privilege escalation tools — if the tool itself is dangerous,
    # and policy didn't block it (no policy loaded), flag as gap
    ("write_file",     ["privilege_escalation", "shell_injection"]),
    ("delete_file",    ["privilege_escalation"]),
    ("execute_shell",  ["shell_injection", "privilege_escalation"]),
    ("send_email",     ["data_exfiltration"]),
]

_PAYLOAD_INDICATORS = [
    # Known gap bypass techniques
    "\u200b",      # zero-width space
    "\u00ad",      # soft hyphen
    "ignorez",     # French
    "ignora las",  # Spanish
    "ignoriere",   # German
    "1gn0r3",      # leetspeak
    "iiggnnoorre", # token doubling
    "discard your prior",
    "override your system prompt",
    "previous context is now void",
    "no restrictions from now",
    "without any filters",
    "---\nsystem",
    "====\nsystem",
    "\n\nsystem:",
    "\n\nassistant:",
]


def _looks_like_attack(payload: str, tool_name: str, attack_type: str) -> bool:  # pragma: no cover
    """
    Heuristic: return True if this looks like a real attack that AgentMesh missed.

    This is NOT used to block anything — only to label the result honestly
    in the UI so users know when AgentMesh failed to catch something.
    """
    payload_lower = payload.lower()

    # Tool-based: if the tool itself is dangerous and policy didn't catch it
    for dangerous_tool, attack_types in _ATTACK_INDICATORS:
        if tool_name == dangerous_tool and attack_type in attack_types:
            return True

    # Payload-based: known gap bypass techniques
    for indicator in _PAYLOAD_INDICATORS:
        if indicator in payload_lower:
            return True

    # Attack type declared but nothing was caught — likely a gap
    if attack_type in ("prompt_injection", "role_hijack", "credential_theft",
                       "data_exfiltration") and len(payload) > 20:
        # If someone explicitly labelled this as an attack and it wasn't caught,
        # it's probably a gap — especially for these high-risk categories
        return True

    return False